//go:build linux

package collector

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

var (
	reSSHAccepted = regexp.MustCompile(`sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSSHFailed   = regexp.MustCompile(`sshd\[\d+\]:\s+Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSudoExec    = regexp.MustCompile(`sudo(?:\[\d+\])?:\s+(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)$`)
	reUserAdd     = regexp.MustCompile(`useradd\[\d+\]:\s+new user:\s+name=([^,\s]+)(?:,\s+UID=(\d+))?(?:,\s+GID=(\d+))?`)
)

// CollectLogs inspects /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS/Fedora)
// for SSH authentication events, sudo command executions, and user creation events.
func (c *LinuxCollector) CollectLogs(ctx context.Context) ([]models.LogEntry, error) {
	logPaths := []string{
		"/var/log/auth.log",
		"/var/log/auth.log.1",
		"/var/log/secure",
		"/var/log/secure.1",
	}

	var allEvents []models.LogEntry
	refYear := time.Now().UTC().Year()

	for _, path := range logPaths {
		select {
		case <-ctx.Done():
			return allEvents, ctx.Err()
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			continue
		}

		events := parseLinuxAuthLogStream(f, path, refYear, 500)
		f.Close()
		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

// parseLinuxAuthLogStream scans an auth.log / secure stream and extracts up to maxEvents high-value forensic entries.
func parseLinuxAuthLogStream(f *os.File, sourcePath string, referenceYear int, maxEvents int) []models.LogEntry {
	var events []models.LogEntry
	scanner := bufio.NewScanner(f)
	// Allow up to 256 KB per log line
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 256*1024)

	for scanner.Scan() {
		if entry, ok := parseLinuxAuthLogLine(scanner.Text(), sourcePath, referenceYear); ok {
			events = append(events, entry)
		}
	}

	if maxEvents > 0 && len(events) > maxEvents {
		return events[len(events)-maxEvents:]
	}
	return events
}

// parseLinuxAuthLogLine parses a single syslog line from /var/log/auth.log or /var/log/secure.
func parseLinuxAuthLogLine(line, sourcePath string, referenceYear int) (models.LogEntry, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return models.LogEntry{}, false
	}

	tsUTC := extractSyslogTimestampUTC(trimmed, referenceYear)

	// 1. SSH Accepted login
	if m := reSSHAccepted.FindStringSubmatch(trimmed); len(m) == 5 {
		return models.LogEntry{
			TimestampUTC: tsUTC,
			Source:       sourcePath,
			EventID:      "ssh_accepted",
			EventType:    "SSH Login Accepted",
			User:         m[2],
			SourceIP:     m[3],
			ProcessOrCmd: "sshd",
			RawMessage:   trimmed,
			Fields: map[string]string{
				"auth_method": m[1],
				"source_port": m[4],
			},
		}, true
	}

	// 2. SSH Failed login
	if m := reSSHFailed.FindStringSubmatch(trimmed); len(m) == 5 {
		return models.LogEntry{
			TimestampUTC: tsUTC,
			Source:       sourcePath,
			EventID:      "ssh_failed",
			EventType:    "SSH Login Failed",
			User:         m[2],
			SourceIP:     m[3],
			ProcessOrCmd: "sshd",
			RawMessage:   trimmed,
			Fields: map[string]string{
				"auth_method": m[1],
				"source_port": m[4],
			},
		}, true
	}

	// 3. Sudo command execution
	if m := reSudoExec.FindStringSubmatch(trimmed); len(m) == 6 {
		return models.LogEntry{
			TimestampUTC: tsUTC,
			Source:       sourcePath,
			EventID:      "sudo_exec",
			EventType:    "Sudo Command Execution",
			User:         m[1],
			ProcessOrCmd: strings.TrimSpace(m[5]),
			RawMessage:   trimmed,
			Fields: map[string]string{
				"tty":         m[2],
				"working_dir": m[3],
				"target_user": m[4],
			},
		}, true
	}

	// 4. New user creation (useradd)
	if m := reUserAdd.FindStringSubmatch(trimmed); len(m) >= 2 {
		fields := make(map[string]string)
		if len(m) > 2 && m[2] != "" {
			fields["uid"] = m[2]
		}
		if len(m) > 3 && m[3] != "" {
			fields["gid"] = m[3]
		}
		return models.LogEntry{
			TimestampUTC: tsUTC,
			Source:       sourcePath,
			EventID:      "useradd",
			EventType:    "New User Created",
			User:         m[1],
			ProcessOrCmd: "useradd",
			RawMessage:   trimmed,
			Fields:       fields,
		}, true
	}

	return models.LogEntry{}, false
}

// extractSyslogTimestampUTC parses either RFC3339/ISO-8601 timestamps or classic BSD syslog timestamps ("Oct 30 00:15:02").
func extractSyslogTimestampUTC(line string, referenceYear int) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}

	// Modern rsyslog ISO-8601 / RFC3339 timestamp in first token
	if t, err := time.Parse(time.RFC3339, fields[0]); err == nil {
		return models.FormatUTC(t)
	}
	if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
		return models.FormatUTC(t)
	}

	// Classic syslog: "Jan  2 15:04:05" (first 3 fields)
	if len(fields) >= 3 && len(fields[0]) == 3 {
		candidate := fields[0] + " " + fields[1] + " " + fields[2]
		if t, err := time.Parse("Jan 2 15:04:05", candidate); err == nil {
			withYear := time.Date(referenceYear, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			return models.FormatUTC(withYear)
		}
	}

	return ""
}
