//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

// userTickHz is the standard Linux USER_HZ clock tick rate (100 ticks/sec) exposed to /proc/[pid]/stat.
const userTickHz = 100

// LinuxCollector implements ArtifactCollector for Linux hosts using pure-Go procfs and filesystem inspection.
type LinuxCollector struct {
	logger *slog.Logger
}

// NewPlatformCollector returns a LinuxCollector when compiled with GOOS=linux.
func NewPlatformCollector(logger *slog.Logger) ArtifactCollector {
	return &LinuxCollector{logger: logger}
}

// IsElevated returns true when running with effective UID 0 (root).
func (c *LinuxCollector) IsElevated() bool {
	return os.Geteuid() == 0
}

// CollectHostInfo gathers volatile and static host metadata from /proc and /etc/os-release.
func (c *LinuxCollector) CollectHostInfo(ctx context.Context) (models.HostInfo, error) {
	info := models.HostInfo{
		OS:           "linux",
		Architecture: runtime.GOARCH,
	}

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	euid := os.Geteuid()
	uidMap := parsePasswdUsers("/etc/passwd")
	if uname, ok := uidMap[euid]; ok {
		info.CurrentUser = uname
	} else if envUser := os.Getenv("USER"); envUser != "" {
		info.CurrentUser = envUser
	} else {
		info.CurrentUser = strconv.Itoa(euid)
	}

	if euid == 0 {
		info.PrivilegeLevel = "root (UID 0)"
	} else {
		info.PrivilegeLevel = fmt.Sprintf("user (UID %d)", euid)
	}

	info.OSVersion = parseOSRelease("/etc/os-release")
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.KernelVersion = strings.TrimSpace(string(data))
	}

	if uptimeSec, err := parseProcUptime("/proc/uptime"); err == nil {
		info.UptimeSeconds = uptimeSec
	}
	if bootUnix, err := parseBootTimeUnix("/proc/stat"); err == nil && bootUnix > 0 {
		info.BootTimeUTC = models.FormatUTC(time.Unix(bootUnix, 0).UTC())
	} else if info.UptimeSeconds > 0 {
		boot := time.Now().UTC().Add(-time.Duration(info.UptimeSeconds) * time.Second)
		info.BootTimeUTC = models.FormatUTC(boot)
	}

	return info, nil
}

// CollectProcesses enumerates /proc/[pid] directories, extracting process hierarchy, command line,
// owner username, start time, and SHA-256 of the backing binary.
func (c *LinuxCollector) CollectProcesses(ctx context.Context) ([]models.ProcessArtifact, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	uidMap := parsePasswdUsers("/etc/passwd")
	bootUnix, _ := parseBootTimeUnix("/proc/stat")
	hashCache := make(map[string]string)

	var procs []models.ProcessArtifact
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return procs, ctx.Err()
		default:
		}

		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		procDir := filepath.Join("/proc", entry.Name())
		statData, err := os.ReadFile(filepath.Join(procDir, "stat"))
		if err != nil {
			continue
		}

		comm, ppid, startTicks, err := parseProcStatLine(string(statData))
		if err != nil {
			continue
		}

		exePath, _ := os.Readlink(filepath.Join(procDir, "exe"))
		exePath = strings.TrimSuffix(exePath, " (deleted)")

		cmdLine := readProcCmdline(filepath.Join(procDir, "cmdline"))
		if cmdLine == "" {
			cmdLine = "[" + comm + "]"
		}

		uid := readProcStatusUID(filepath.Join(procDir, "status"))
		username := strconv.Itoa(uid)
		if name, ok := uidMap[uid]; ok {
			username = name
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

		var startTimeUTC string
		if bootUnix > 0 && startTicks > 0 {
			startSec := bootUnix + int64(startTicks/userTickHz)
			startTimeUTC = models.FormatUTC(time.Unix(startSec, 0).UTC())
		}

		procs = append(procs, models.ProcessArtifact{
			PID:            pid,
			PPID:           ppid,
			Name:           comm,
			ExecutablePath: exePath,
			CommandLine:    cmdLine,
			Username:       username,
			SHA256:         sha256Hex,
			StartTimeUTC:   startTimeUTC,
		})
	}

	return procs, nil
}

// CollectNetwork parses /proc/net/{tcp,tcp6,udp,udp6} and maps socket inodes to owning PIDs.
func (c *LinuxCollector) CollectNetwork(ctx context.Context) ([]models.NetworkArtifact, error) {
	inodeToProc := buildSocketInodeMap(ctx)

	netFiles := []struct {
		proto string
		path  string
	}{
		{"tcp", "/proc/net/tcp"},
		{"tcp6", "/proc/net/tcp6"},
		{"udp", "/proc/net/udp"},
		{"udp6", "/proc/net/udp6"},
	}

	var results []models.NetworkArtifact
	for _, nf := range netFiles {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		f, err := os.Open(nf.path)
		if err != nil {
			continue
		}
		conns := parseProcNetFile(f, nf.proto, inodeToProc)
		f.Close()
		results = append(results, conns...)
	}

	return results, nil
}

type procSocketOwner struct {
	pid  int
	name string
}

// buildSocketInodeMap scans /proc/[pid]/fd/* symlinks for "socket:[inode]" targets.
func buildSocketInodeMap(ctx context.Context) map[string]procSocketOwner {
	inodeMap := make(map[string]procSocketOwner)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return inodeMap
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return inodeMap
		default:
		}

		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		var procName string
		if commBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm")); err == nil {
			procName = strings.TrimSpace(string(commBytes))
		}

		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode := target[len("socket:[") : len(target)-1]
				inodeMap[inode] = procSocketOwner{pid: pid, name: procName}
			}
		}
	}

	return inodeMap
}

// parseProcNetFile parses a /proc/net/{tcp,tcp6,udp,udp6} reader into NetworkArtifact structs.
func parseProcNetFile(r *os.File, proto string, inodeMap map[string]procSocketOwner) []models.NetworkArtifact {
	var artifacts []models.NetworkArtifact
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // skip header
		}
		conn, ok := parseProcNetLine(scanner.Text(), proto, inodeMap)
		if ok {
			artifacts = append(artifacts, conn)
		}
	}
	return artifacts
}

// parseProcNetLine parses a single data line from /proc/net/tcp[6] or /proc/net/udp[6].
func parseProcNetLine(line, proto string, inodeMap map[string]procSocketOwner) (models.NetworkArtifact, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return models.NetworkArtifact{}, false
	}

	localIP, localPort, err := decodeHexEndpoint(fields[1])
	if err != nil {
		return models.NetworkArtifact{}, false
	}
	remoteIP, remotePort, err := decodeHexEndpoint(fields[2])
	if err != nil {
		return models.NetworkArtifact{}, false
	}

	stateHex := fields[3]
	inode := fields[9]

	owner := inodeMap[inode]
	return models.NetworkArtifact{
		Protocol:      proto,
		LocalAddress:  localIP,
		LocalPort:     localPort,
		RemoteAddress: remoteIP,
		RemotePort:    remotePort,
		State:         decodeTCPState(stateHex, proto),
		PID:           owner.pid,
		ProcessName:   owner.name,
	}, true
}

// decodeHexEndpoint converts a /proc/net hex address:port token (e.g., "0100007F:0016")
// into a standard IP string and uint16 port.
func decodeHexEndpoint(endpoint string) (string, uint16, error) {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid endpoint %q", endpoint)
	}

	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}

	rawIP, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}

	switch len(rawIP) {
	case 4:
		// Little-endian 32-bit IPv4 word
		ip := net.IPv4(rawIP[3], rawIP[2], rawIP[1], rawIP[0])
		return ip.String(), uint16(portVal), nil
	case 16:
		// Four 32-bit words in host (little-endian) byte order
		ip := make(net.IP, 16)
		for i := 0; i < 16; i += 4 {
			ip[i] = rawIP[i+3]
			ip[i+1] = rawIP[i+2]
			ip[i+2] = rawIP[i+1]
			ip[i+3] = rawIP[i]
		}
		return ip.String(), uint16(portVal), nil
	default:
		return "", 0, fmt.Errorf("unexpected IP hex length %d", len(rawIP))
	}
}

func decodeTCPState(stateHex, proto string) string {
	if strings.HasPrefix(proto, "udp") {
		switch strings.ToUpper(stateHex) {
		case "01":
			return "ESTABLISHED"
		case "07":
			return "UNCONN"
		default:
			return "UDP_" + strings.ToUpper(stateHex)
		}
	}

	switch strings.ToUpper(stateHex) {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	case "0C":
		return "NEW_SYN_RECV"
	default:
		return "UNKNOWN_" + stateHex
	}
}

// parseProcStatLine extracts comm, ppid, and starttime (clock ticks) from /proc/[pid]/stat.
// Safely handles process names containing spaces or parentheses.
func parseProcStatLine(statLine string) (comm string, ppid int, startTicks uint64, err error) {
	openIdx := strings.IndexByte(statLine, '(')
	closeIdx := strings.LastIndexByte(statLine, ')')
	if openIdx < 0 || closeIdx <= openIdx || closeIdx+2 >= len(statLine) {
		return "", 0, 0, fmt.Errorf("malformed /proc/stat line")
	}

	comm = statLine[openIdx+1 : closeIdx]
	rest := strings.Fields(statLine[closeIdx+2:])
	// rest[0] is state (field 3), rest[1] is ppid (field 4), rest[19] is starttime (field 22)
	if len(rest) < 20 {
		return "", 0, 0, fmt.Errorf("truncated /proc/stat fields")
	}

	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, 0, err
	}
	startTicks, _ = strconv.ParseUint(rest[19], 10, 64)
	return comm, ppid, startTicks, nil
}

func readProcCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	data = bytes.TrimRight(data, "\x00")
	parts := bytes.Split(data, []byte{0})
	strs := make([]string, 0, len(parts))
	for _, p := range parts {
		strs = append(strs, string(p))
	}
	return strings.TrimSpace(strings.Join(strs, " "))
}

func readProcStatusUID(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					return uid
				}
			}
		}
	}
	return -1
}

func parseOSRelease(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "Linux"
	}
	defer f.Close()

	var prettyName, name, version string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"'`)
		} else if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"'`)
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), `"'`)
		}
	}
	if prettyName != "" {
		return prettyName
	}
	if name != "" {
		return strings.TrimSpace(name + " " + version)
	}
	return "Linux"
}

func parseProcUptime(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return uint64(val), nil
}

func parseBootTimeUnix(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseInt(fields[1], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("btime not found in %s", path)
}

type passwdUser struct {
	username string
	uid      int
	homeDir  string
	shell    string
}

func parsePasswdUsers(path string) map[int]string {
	users := parsePasswdEntries(path)
	m := make(map[int]string, len(users))
	for _, u := range users {
		m[u.uid] = u.username
	}
	return m
}

func parsePasswdEntries(path string) []passwdUser {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var list []passwdUser
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		list = append(list, passwdUser{
			username: parts[0],
			uid:      uid,
			homeDir:  parts[5],
			shell:    parts[6],
		})
	}
	return list
}
