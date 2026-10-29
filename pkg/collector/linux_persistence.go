//go:build linux

package collector

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

// CollectPersistence gathers Linux persistence mechanisms and privilege escalation / execution artifacts:
//   - Persistence: /etc/crontab, /etc/cron.*/*, /var/spool/cron/crontabs/*, /etc/systemd/system/*.service,
//     ~/.bashrc, and ~/.ssh/authorized_keys across all user home directories.
//   - Execution & PrivEsc: ~/.bash_history, ~/.zsh_history, and suspicious SUID/SGID binaries.
func (c *LinuxCollector) CollectPersistence(ctx context.Context) ([]models.PersistenceItem, []models.ExecutionArtifact, error) {
	var persistence []models.PersistenceItem
	var execution []models.ExecutionArtifact

	// 1. System-wide Crontabs & Cron directories
	persistence = append(persistence, c.collectCronPersistence(ctx)...)

	// 2. Systemd Service Unit files (/etc/systemd/system/*.service)
	persistence = append(persistence, c.collectSystemdUnits(ctx, "/etc/systemd/system")...)

	// 3. Per-user artifacts (.bashrc, .ssh/authorized_keys, .bash_history, .zsh_history)
	userPers, userExec := c.collectUserArtifacts(ctx)
	persistence = append(persistence, userPers...)
	execution = append(execution, userExec...)

	// 4. Suspicious SUID / SGID binaries across common executable & writable directories
	suidArtifacts := c.collectSUIDSGIDBinaries(ctx)
	execution = append(execution, suidArtifacts...)

	return persistence, execution, nil
}

func (c *LinuxCollector) collectCronPersistence(ctx context.Context) []models.PersistenceItem {
	var items []models.PersistenceItem

	// /etc/crontab (has user column)
	if entries, err := parseCronFile("/etc/crontab", true, ""); err == nil {
		items = append(items, entries...)
	}

	// /etc/cron.d/* (has user column) and script directories (/etc/cron.hourly, daily, weekly, monthly)
	cronGlobPatterns := []struct {
		pattern     string
		hasUserCol  bool
		isScriptDir bool
	}{
		{"/etc/cron.d/*", true, false},
		{"/etc/cron.hourly/*", false, true},
		{"/etc/cron.daily/*", false, true},
		{"/etc/cron.weekly/*", false, true},
		{"/etc/cron.monthly/*", false, true},
		{"/var/spool/cron/crontabs/*", false, false},
		{"/var/spool/cron/*", false, false},
	}

	seenPaths := make(map[string]bool)
	for _, g := range cronGlobPatterns {
		select {
		case <-ctx.Done():
			return items
		default:
		}

		matches, err := filepath.Glob(g.pattern)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if seenPaths[m] {
				continue
			}
			seenPaths[m] = true

			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			base := filepath.Base(m)
			if base == ".placeholder" || strings.HasPrefix(base, ".") {
				continue
			}

			if g.isScriptDir {
				sha, _ := HashFileSHA256(m)
				items = append(items, models.PersistenceItem{
					Category:       "cron_script",
					Name:           base,
					SourcePath:     m,
					User:           "root",
					CommandOrValue: m,
					TargetBinary:   m,
					TargetSHA256:   sha,
					ModifiedAtUTC:  models.FormatUTC(info.ModTime()),
				})
				continue
			}

			defaultUser := ""
			if !g.hasUserCol {
				defaultUser = base
			}
			if entries, err := parseCronFile(m, g.hasUserCol, defaultUser); err == nil {
				items = append(items, entries...)
			}
		}
	}

	return items
}

// parseCronFile parses standard crontab lines and @reboot/@daily special strings.
func parseCronFile(path string, hasUserField bool, defaultUser string) ([]models.PersistenceItem, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	modUTC := models.FormatUTC(info.ModTime())
	var items []models.PersistenceItem

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		item, ok := parseCronLine(scanner.Text(), path, modUTC, hasUserField, defaultUser)
		if ok {
			items = append(items, item)
		}
	}
	return items, nil
}

// parseCronLine parses an individual crontab line into a PersistenceItem.
func parseCronLine(rawLine, sourcePath, modUTC string, hasUserField bool, defaultUser string) (models.PersistenceItem, bool) {
	line := strings.TrimSpace(rawLine)
	if line == "" || strings.HasPrefix(line, "#") {
		return models.PersistenceItem{}, false
	}

	// Ignore environment variable assignments in crontabs (e.g., SHELL=/bin/sh, PATH=...)
	if eqIdx := strings.IndexByte(line, '='); eqIdx > 0 {
		prefix := strings.TrimSpace(line[:eqIdx])
		if !strings.ContainsAny(prefix, " \t*") {
			return models.PersistenceItem{}, false
		}
	}

	fields := strings.Fields(line)
	var schedule, user, command string

	if strings.HasPrefix(fields[0], "@") {
		schedule = fields[0]
		if hasUserField {
			if len(fields) < 3 {
				return models.PersistenceItem{}, false
			}
			user = fields[1]
			command = strings.Join(fields[2:], " ")
		} else {
			if len(fields) < 2 {
				return models.PersistenceItem{}, false
			}
			user = defaultUser
			command = strings.Join(fields[1:], " ")
		}
	} else {
		if hasUserField {
			if len(fields) < 7 {
				return models.PersistenceItem{}, false
			}
			schedule = strings.Join(fields[:5], " ")
			user = fields[5]
			command = strings.Join(fields[6:], " ")
		} else {
			if len(fields) < 6 {
				return models.PersistenceItem{}, false
			}
			schedule = strings.Join(fields[:5], " ")
			user = defaultUser
			command = strings.Join(fields[5:], " ")
		}
	}

	targetBin := extractFirstBinaryPath(command)
	var sha string
	if targetBin != "" {
		sha, _ = HashFileSHA256(targetBin)
	}

	return models.PersistenceItem{
		Category:       "cron",
		Name:           filepath.Base(sourcePath),
		SourcePath:     sourcePath,
		User:           user,
		CommandOrValue: command,
		TargetBinary:   targetBin,
		TargetSHA256:   sha,
		ModifiedAtUTC:  modUTC,
		Metadata: map[string]string{
			"schedule": schedule,
		},
	}, true
}

func (c *LinuxCollector) collectSystemdUnits(ctx context.Context, systemdDir string) []models.PersistenceItem {
	var items []models.PersistenceItem
	matches, err := filepath.Glob(filepath.Join(systemdDir, "*.service"))
	if err != nil {
		return items
	}

	for _, unitPath := range matches {
		select {
		case <-ctx.Done():
			return items
		default:
		}

		info, err := os.Stat(unitPath)
		if err != nil || info.IsDir() {
			continue
		}
		data, err := os.ReadFile(unitPath)
		if err != nil {
			continue
		}

		if item, ok := parseSystemdUnitContent(string(data), unitPath, models.FormatUTC(info.ModTime())); ok {
			items = append(items, item)
		}
	}
	return items
}

// parseSystemdUnitContent extracts ExecStart, ExecStartPre, User, and Description from a .service unit file.
func parseSystemdUnitContent(content, unitPath, modUTC string) (models.PersistenceItem, bool) {
	meta := make(map[string]string)
	var execStart, user, description string

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "Description=") {
			description = strings.TrimSpace(strings.TrimPrefix(line, "Description="))
			meta["description"] = description
		} else if strings.HasPrefix(line, "ExecStart=") {
			execStart = strings.TrimSpace(strings.TrimPrefix(line, "ExecStart="))
		} else if strings.HasPrefix(line, "ExecStartPre=") {
			meta["exec_start_pre"] = strings.TrimSpace(strings.TrimPrefix(line, "ExecStartPre="))
		} else if strings.HasPrefix(line, "User=") {
			user = strings.TrimSpace(strings.TrimPrefix(line, "User="))
		}
	}

	if execStart == "" && meta["exec_start_pre"] == "" {
		return models.PersistenceItem{}, false
	}
	if user == "" {
		user = "root"
	}

	cleanExec := strings.TrimLeft(execStart, "-+@!:")
	targetBin := extractFirstBinaryPath(cleanExec)
	var sha string
	if targetBin != "" {
		sha, _ = HashFileSHA256(targetBin)
	}

	return models.PersistenceItem{
		Category:       "systemd_service",
		Name:           filepath.Base(unitPath),
		SourcePath:     unitPath,
		User:           user,
		CommandOrValue: execStart,
		TargetBinary:   targetBin,
		TargetSHA256:   sha,
		ModifiedAtUTC:  modUTC,
		Metadata:       meta,
	}, true
}

func (c *LinuxCollector) collectUserArtifacts(ctx context.Context) ([]models.PersistenceItem, []models.ExecutionArtifact) {
	var pers []models.PersistenceItem
	var execArts []models.ExecutionArtifact

	homeDirs := discoverUserHomeDirs()
	for username, home := range homeDirs {
		select {
		case <-ctx.Done():
			return pers, execArts
		default:
		}

		// 1. ~/.bashrc inspection
		bashrcPath := filepath.Join(home, ".bashrc")
		if info, err := os.Stat(bashrcPath); err == nil && info.Mode().IsRegular() {
			sha, _ := HashFileSHA256(bashrcPath)
			suspiciousLines := extractSuspiciousRCCommands(bashrcPath)
			summary := "standard .bashrc"
			if len(suspiciousLines) > 0 {
				summary = strings.Join(suspiciousLines, " ; ")
			}
			pers = append(pers, models.PersistenceItem{
				Category:       "bashrc",
				Name:           ".bashrc",
				SourcePath:     bashrcPath,
				User:           username,
				CommandOrValue: summary,
				TargetBinary:   bashrcPath,
				TargetSHA256:   sha,
				ModifiedAtUTC:  models.FormatUTC(info.ModTime()),
			})
		}

		// 2. ~/.ssh/authorized_keys
		authKeysPath := filepath.Join(home, ".ssh", "authorized_keys")
		if info, err := os.Stat(authKeysPath); err == nil && info.Mode().IsRegular() {
			if data, err := os.ReadFile(authKeysPath); err == nil {
				keys := parseAuthorizedKeysContent(string(data), authKeysPath, username, models.FormatUTC(info.ModTime()))
				pers = append(pers, keys...)
			}
		}

		// 3. Shell Histories (~/.bash_history and ~/.zsh_history)
		historyFiles := []string{
			filepath.Join(home, ".bash_history"),
			filepath.Join(home, ".zsh_history"),
		}
		for _, hPath := range historyFiles {
			if info, err := os.Stat(hPath); err == nil && info.Mode().IsRegular() {
				if data, err := os.ReadFile(hPath); err == nil {
					entries := parseShellHistoryContent(string(data), hPath, username, models.FormatUTC(info.ModTime()), 200)
					execArts = append(execArts, entries...)
				}
			}
		}
	}

	return pers, execArts
}

func discoverUserHomeDirs() map[string]string {
	homes := make(map[string]string)
	for _, u := range parsePasswdEntries("/etc/passwd") {
		if u.homeDir == "" || u.homeDir == "/nonexistent" || u.homeDir == "/dev/null" {
			continue
		}
		if info, err := os.Stat(u.homeDir); err == nil && info.IsDir() {
			homes[u.username] = u.homeDir
		}
	}

	// Ensure /root and /home/* are checked even if /etc/passwd is minimal
	if info, err := os.Stat("/root"); err == nil && info.IsDir() {
		if _, exists := homes["root"]; !exists {
			homes["root"] = "/root"
		}
	}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				if _, exists := homes[e.Name()]; !exists {
					homes[e.Name()] = filepath.Join("/home", e.Name())
				}
			}
		}
	}
	return homes
}

func extractSuspiciousRCCommands(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	indicators := []string{
		"curl ", "wget ", "nc ", "ncat ", "netcat ", "/dev/tcp/",
		"base64 ", "python", "perl ", "socat ", "chmod +s", "nohup ",
		"/tmp/", "/var/tmp/", "/dev/shm/", "reverse", "bash -i",
	}

	var matched []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		for _, ind := range indicators {
			if strings.Contains(lower, ind) {
				matched = append(matched, line)
				break
			}
		}
	}
	return matched
}

// parseAuthorizedKeysContent parses SSH authorized_keys entries.
func parseAuthorizedKeysContent(content, path, username, modUTC string) []models.PersistenceItem {
	var items []models.PersistenceItem
	scanner := bufio.NewScanner(strings.NewReader(content))
	idx := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx++
		items = append(items, models.PersistenceItem{
			Category:       "ssh_authorized_keys",
			Name:           filepath.Base(path),
			SourcePath:     path,
			User:           username,
			CommandOrValue: line,
			ModifiedAtUTC:  modUTC,
			Metadata: map[string]string{
				"key_index": string(rune('0' + idx)),
			},
		})
	}
	return items
}

// parseShellHistoryContent parses .bash_history and extended .zsh_history (`: 1700000000:0;cmd`) lines,
// returning up to maxTail of the most recent commands.
func parseShellHistoryContent(content, path, username, modUTC string, maxTail int) []models.ExecutionArtifact {
	var all []models.ExecutionArtifact
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Skip bash history timestamp comment lines (#1700000000)
		if strings.HasPrefix(line, "#") && len(line) > 1 && line[1] >= '0' && line[1] <= '9' {
			continue
		}

		// Strip zsh extended history prefix `: <timestamp>:0;`
		if strings.HasPrefix(line, ": ") {
			if semiIdx := strings.IndexByte(line, ';'); semiIdx > 2 && semiIdx+1 < len(line) {
				line = line[semiIdx+1:]
			}
		}

		all = append(all, models.ExecutionArtifact{
			ArtifactType:  "shell_history",
			Path:          path,
			User:          username,
			Command:       line,
			LineNumber:    lineNum,
			ModifiedAtUTC: modUTC,
		})
	}

	if maxTail > 0 && len(all) > maxTail {
		return all[len(all)-maxTail:]
	}
	return all
}

// collectSUIDSGIDBinaries scans standard binary and writable staging paths for SUID/SGID files.
func (c *LinuxCollector) collectSUIDSGIDBinaries(ctx context.Context) []models.ExecutionArtifact {
	searchRoots := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/opt",
		"/tmp",
		"/var/tmp",
		"/dev/shm",
	}

	seenRealPaths := make(map[string]bool)
	var results []models.ExecutionArtifact

	for _, root := range searchRoots {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		info, err := os.Lstat(root)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			// Skip if directory doesn't exist or is a top-level symlink (e.g., /bin -> /usr/bin)
			// Only skip if the target is also in searchRoots.
			if realRoot, err := filepath.EvalSymlinks(root); err == nil {
				if seenRealPaths[realRoot] {
					continue
				}
				seenRealPaths[realRoot] = true
			} else {
				continue
			}
		} else {
			seenRealPaths[root] = true
		}

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if d.IsDir() {
				return nil
			}
			// Avoid following symlinks
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}

			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}

			mode := fi.Mode()
			hasSUID := mode&fs.ModeSetuid != 0
			hasSGID := mode&fs.ModeSetgid != 0
			if !hasSUID && !hasSGID {
				return nil
			}

			sha, _ := HashFileSHA256(path)
			privType := "SUID"
			if hasSUID && hasSGID {
				privType = "SUID+SGID"
			} else if hasSGID {
				privType = "SGID"
			}

			results = append(results, models.ExecutionArtifact{
				ArtifactType:  "suid_sgid_binary",
				Path:          path,
				Permissions:   mode.String(),
				SizeBytes:     fi.Size(),
				ModifiedAtUTC: models.FormatUTC(fi.ModTime()),
				SHA256:        sha,
				Metadata: map[string]string{
					"privilege_bits": privType,
					"gtfobins_risk":  classifySUIDRisk(path),
				},
			})
			return nil
		})
	}

	return results
}

// classifySUIDRisk flags SUID/SGID binaries located in temporary directories or matching known GTFOBins abuse binaries.
func classifySUIDRisk(path string) string {
	if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.HasPrefix(path, "/home/") {
		return "CRITICAL (non-standard path)"
	}

	gtfoBinaries := map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true, "python": true, "python3": true,
		"perl": true, "ruby": true, "php": true, "find": true, "vim": true, "vi": true,
		"nmap": true, "less": true, "more": true, "awk": true, "gawk": true, "cp": true,
		"mv": true, "nano": true, "tar": true, "zip": true, "env": true, "docker": true,
		"pkexec": true,
	}
	base := filepath.Base(path)
	if gtfoBinaries[base] {
		return "HIGH (GTFOBins candidate)"
	}
	return "STANDARD"
}

func extractFirstBinaryPath(cmd string) string {
	fields := strings.Fields(strings.TrimSpace(cmd))
	for _, f := range fields {
		// Skip env assignments or shell wrappers
		if strings.Contains(f, "=") {
			continue
		}
		clean := strings.Trim(f, `"'`)
		if strings.HasPrefix(clean, "/") {
			return clean
		}
		break
	}
	return ""
}
