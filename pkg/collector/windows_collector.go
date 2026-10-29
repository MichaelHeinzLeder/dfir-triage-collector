//go:build windows

package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64   = modkernel32.NewProc("GetTickCount64")
)

// WindowsCollector implements ArtifactCollector for Windows hosts using native Win32 APIs,
// golang.org/x/sys/windows/registry, and built-in telemetry interfaces with CGO_ENABLED=0.
type WindowsCollector struct {
	logger *slog.Logger
}

// NewPlatformCollector returns a WindowsCollector when compiled with GOOS=windows.
func NewPlatformCollector(logger *slog.Logger) ArtifactCollector {
	return &WindowsCollector{logger: logger}
}

// IsElevated checks if the current process token is elevated (Administrator / SYSTEM).
func (c *WindowsCollector) IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// CollectHostInfo gathers Windows system metadata via Registry, Win32 APIs, and process token inspection.
func (c *WindowsCollector) CollectHostInfo(ctx context.Context) (models.HostInfo, error) {
	info := models.HostInfo{
		OS:           "windows",
		Architecture: runtime.GOARCH,
	}

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	if u, err := user.Current(); err == nil {
		info.CurrentUser = u.Username
	} else {
		info.CurrentUser = os.Getenv("USERNAME")
	}

	if c.IsElevated() {
		info.PrivilegeLevel = "Administrator (Elevated)"
	} else {
		info.PrivilegeLevel = "Standard User (Unprivileged)"
	}

	// Query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion for product name and build number.
	productName, buildNumber := readWindowsVersionRegistry()
	info.OSVersion = productName
	info.KernelVersion = buildNumber

	// Query system uptime via GetTickCount64 (milliseconds since system boot).
	ret, _, _ := procGetTickCount64.Call()
	if ret > 0 {
		uptimeMs := uint64(ret)
		info.UptimeSeconds = uptimeMs / 1000
		bootUTC := time.Now().UTC().Add(-time.Duration(uptimeMs) * time.Millisecond)
		info.BootTimeUTC = models.FormatUTC(bootUTC)
	}

	return info, nil
}

func readWindowsVersionRegistry() (productName string, buildVersion string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows", ""
	}
	defer k.Close()

	prod, _, _ := k.GetStringValue("ProductName")
	displayVer, _, _ := k.GetStringValue("DisplayVersion")
	currentBuild, _, _ := k.GetStringValue("CurrentBuildNumber")
	if currentBuild == "" {
		currentBuild, _, _ = k.GetStringValue("CurrentBuild")
	}

	if prod == "" {
		prod = "Windows"
	}
	if displayVer != "" {
		productName = fmt.Sprintf("%s (%s)", prod, displayVer)
	} else {
		productName = prod
	}
	return productName, currentBuild
}

// CollectProcesses enumerates active Windows processes via CreateToolhelp32Snapshot,
// enriches them with full image paths, creation timestamps, token owners, command lines, and SHA-256 hashes.
func (c *WindowsCollector) CollectProcesses(ctx context.Context) ([]models.ProcessArtifact, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	// Optional enrichment map for full command-line arguments from CIM/WMI if available.
	cmdLineMap := queryProcessCommandLines(ctx)
	hashCache := make(map[string]string)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snapshot, &pe); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	var procs []models.ProcessArtifact
	for {
		select {
		case <-ctx.Done():
			return procs, ctx.Err()
		default:
		}

		pid := int(pe.ProcessID)
		ppid := int(pe.ParentProcessID)
		exeName := windows.UTF16ToString(pe.ExeFile[:])

		exePath, username, startUTC := inspectWindowsProcessHandle(uint32(pid))
		cmdLine := cmdLineMap[pid]
		if cmdLine == "" {
			if exePath != "" {
				cmdLine = exePath
			} else {
				cmdLine = exeName
			}
		}

		var sha256Hex string
		if exePath != "" {
			if cached, ok := hashCache[exePath]; ok {
				sha256Hex = cached
			} else if h, err := HashFileSHA256(exePath); err == nil {
				sha256Hex = h
				hashCache[exePath] = h
			}
		}

		procs = append(procs, models.ProcessArtifact{
			PID:            pid,
			PPID:           ppid,
			Name:           exeName,
			ExecutablePath: exePath,
			CommandLine:    cmdLine,
			Username:       username,
			SHA256:         sha256Hex,
			StartTimeUTC:   startUTC,
		})

		pe.Size = uint32(unsafe.Sizeof(pe))
		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return procs, nil
}

// inspectWindowsProcessHandle opens a process with PROCESS_QUERY_LIMITED_INFORMATION to extract
// the full image path, creation time, and token owner SID/account name.
func inspectWindowsProcessHandle(pid uint32) (exePath string, username string, startTimeUTC string) {
	if pid == 0 || pid == 4 {
		return "", `NT AUTHORITY\SYSTEM`, ""
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", "", ""
	}
	defer windows.CloseHandle(hProc)

	// 1. QueryFullProcessImageName
	buf := make([]uint16, windows.MAX_PATH*2)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); err == nil && size > 0 {
		exePath = windows.UTF16ToString(buf[:size])
	}

	// 2. GetProcessTimes for process creation timestamp
	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(hProc, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		nsec := creationTime.Nanoseconds()
		if nsec > 0 {
			startTimeUTC = models.FormatUTC(time.Unix(0, nsec).UTC())
		}
	}

	// 3. OpenProcessToken -> TokenUser -> LookupSid
	var token windows.Token
	if err := windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if tokenUser, err := token.GetTokenUser(); err == nil && tokenUser.User.Sid != nil {
			account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
			if err == nil {
				if domain != "" {
					username = domain + `\` + account
				} else {
					username = account
				}
			} else {
				username = tokenUser.User.Sid.String()
			}
		}
	}

	return exePath, username, startTimeUTC
}

// queryProcessCommandLines queries Win32_Process via PowerShell CSV output to enrich PIDs with full command lines.
func queryProcessCommandLines(ctx context.Context) map[int]string {
	result := make(map[int]string)
	qCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(qCtx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Csv -NoTypeInformation")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return result
	}

	r := csv.NewReader(bytes.NewReader(out))
	records, err := r.ReadAll()
	if err != nil {
		return result
	}
	for i, row := range records {
		if i == 0 || len(row) < 2 {
			continue
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(row[0])); err == nil && pid > 0 {
			result[pid] = strings.TrimSpace(row[1])
		}
	}
	return result
}

// CollectNetwork enumerates active TCP and UDP connections and correlates them with owning PIDs.
func (c *WindowsCollector) CollectNetwork(ctx context.Context) ([]models.NetworkArtifact, error) {
	pidToName := c.buildPIDNameMap()

	cmd := exec.CommandContext(ctx, "netstat.exe", "-ano")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat execution failed: %w", err)
	}

	return parseWindowsNetstatOutput(string(out), pidToName), nil
}

func (c *WindowsCollector) buildPIDNameMap() map[int]string {
	m := make(map[int]string)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return m
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snapshot, &pe); err != nil {
		return m
	}
	for {
		m[int(pe.ProcessID)] = windows.UTF16ToString(pe.ExeFile[:])
		pe.Size = uint32(unsafe.Sizeof(pe))
		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}
	return m
}

// parseWindowsNetstatOutput parses `netstat -ano` output into normalized NetworkArtifact entries.
func parseWindowsNetstatOutput(output string, pidToName map[int]string) []models.NetworkArtifact {
	var artifacts []models.NetworkArtifact
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if conn, ok := parseWindowsNetstatLine(scanner.Text(), pidToName); ok {
			artifacts = append(artifacts, conn)
		}
	}
	return artifacts
}

// parseWindowsNetstatLine parses a single TCP or UDP line from `netstat -ano`.
func parseWindowsNetstatLine(line string, pidToName map[int]string) (models.NetworkArtifact, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 4 {
		return models.NetworkArtifact{}, false
	}

	protoUpper := strings.ToUpper(fields[0])
	if protoUpper != "TCP" && protoUpper != "UDP" {
		return models.NetworkArtifact{}, false
	}

	localAddr, localPort, ok := splitWindowsHostPort(fields[1])
	if !ok {
		return models.NetworkArtifact{}, false
	}
	remoteAddr, remotePort, _ := splitWindowsHostPort(fields[2])

	var state string
	var pid int
	if protoUpper == "TCP" {
		if len(fields) < 5 {
			return models.NetworkArtifact{}, false
		}
		state = fields[3]
		pid, _ = strconv.Atoi(fields[4])
	} else {
		state = "STATELESS"
		pid, _ = strconv.Atoi(fields[3])
	}

	proto := strings.ToLower(protoUpper)
	if strings.Contains(localAddr, ":") {
		proto += "6"
	}

	var procName string
	if pidToName != nil {
		procName = pidToName[pid]
	}

	return models.NetworkArtifact{
		Protocol:      proto,
		LocalAddress:  localAddr,
		LocalPort:     localPort,
		RemoteAddress: remoteAddr,
		RemotePort:    remotePort,
		State:         state,
		PID:           pid,
		ProcessName:   procName,
	}, true
}

func splitWindowsHostPort(endpoint string) (string, uint16, bool) {
	if endpoint == "*:*" {
		return "*", 0, true
	}
	lastColon := strings.LastIndexByte(endpoint, ':')
	if lastColon <= 0 {
		return endpoint, 0, false
	}
	host := strings.Trim(endpoint[:lastColon], "[]")
	portStr := endpoint[lastColon+1:]
	if portStr == "*" {
		return host, 0, true
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return host, 0, false
	}
	return host, uint16(port), true
}

// filetimeToUTC helper converts a syscall.Filetime to a UTC ISO-8601 string.
func filetimeToUTC(ft syscall.Filetime) string {
	nsec := ft.Nanoseconds()
	if nsec <= 0 {
		return ""
	}
	return models.FormatUTC(time.Unix(0, nsec).UTC())
}
