// Package models defines the unified, SIEM/Sigma-compatible JSON schema
// for host triage artifacts across Windows and Linux platforms.
package models

import "time"

// TriageReport is the top-level document exported by dfir-triage-go.
// Timestamps are formatted in UTC ISO-8601 (RFC3339).
type TriageReport struct {
	ReportMetadata   ReportMetadata      `json:"report_metadata"`
	HostInfo         HostInfo            `json:"host_info"`
	Processes        []ProcessArtifact   `json:"processes,omitempty"`
	Network          []NetworkArtifact   `json:"network_connections,omitempty"`
	Persistence      []PersistenceItem   `json:"persistence,omitempty"`
	Execution        []ExecutionArtifact `json:"execution_artifacts,omitempty"`
	SecurityEvents   []LogEntry          `json:"security_events,omitempty"`
	CollectionErrors []ModuleError       `json:"collection_errors,omitempty"`
}

// ReportMetadata tracks forensic provenance of the triage execution itself.
type ReportMetadata struct {
	ToolName        string   `json:"tool_name"`
	ToolVersion     string   `json:"tool_version"`
	GeneratedAtUTC  string   `json:"generated_at_utc"`
	DurationMs      int64    `json:"duration_ms"`
	ModulesExecuted []string `json:"modules_executed"`
	Elevated        bool     `json:"elevated_privileges"`
}

// HostInfo captures volatile and static host metadata.
type HostInfo struct {
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	KernelVersion  string `json:"kernel_version"`
	Architecture   string `json:"architecture"`
	CurrentUser    string `json:"current_user"`
	PrivilegeLevel string `json:"privilege_level"`
	UptimeSeconds  uint64 `json:"uptime_seconds"`
	BootTimeUTC    string `json:"boot_time_utc,omitempty"`
}

// ProcessArtifact represents a running process and its binary forensic metadata.
type ProcessArtifact struct {
	PID            int    `json:"pid"`
	PPID           int    `json:"ppid"`
	Name           string `json:"name"`
	ExecutablePath string `json:"executable_path"`
	CommandLine    string `json:"command_line"`
	Username       string `json:"username"`
	SHA256         string `json:"sha256,omitempty"`
	StartTimeUTC   string `json:"start_time_utc,omitempty"`
}

// NetworkArtifact represents an active TCP/UDP socket and its owning process.
type NetworkArtifact struct {
	Protocol      string `json:"protocol"` // tcp, tcp6, udp, udp6
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	State         string `json:"state"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name,omitempty"`
}

// PersistenceItem represents a mechanism used to maintain survival across reboots
// (MITRE ATT&CK TA0003 - Persistence).
type PersistenceItem struct {
	Category       string            `json:"category"`        // e.g., "cron", "systemd_service", "bashrc", "ssh_authorized_keys", "registry_run", "startup_folder", "scheduled_task"
	Name           string            `json:"name"`            // Entry identifier or unit name
	SourcePath     string            `json:"source_path"`     // Registry path or file path on disk
	User           string            `json:"user,omitempty"`  // Context under which the item runs
	CommandOrValue string            `json:"command_value"`   // Executed command line, script content, or key payload
	TargetBinary   string            `json:"target_binary,omitempty"`
	TargetSHA256   string            `json:"target_sha256,omitempty"`
	ModifiedAtUTC  string            `json:"modified_at_utc,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ExecutionArtifact captures historical command execution, binary prefetching,
// or privilege escalation vectors (MITRE ATT&CK TA0002 / TA0004).
type ExecutionArtifact struct {
	ArtifactType  string            `json:"artifact_type"` // e.g., "shell_history", "suid_sgid_binary", "windows_prefetch"
	Path          string            `json:"path"`
	User          string            `json:"user,omitempty"`
	Command       string            `json:"command,omitempty"`
	LineNumber    int               `json:"line_number,omitempty"`
	Permissions   string            `json:"permissions,omitempty"`
	SizeBytes     int64             `json:"size_bytes,omitempty"`
	CreatedAtUTC  string            `json:"created_at_utc,omitempty"`
	ModifiedAtUTC string            `json:"modified_at_utc,omitempty"`
	SHA256        string            `json:"sha256,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// LogEntry represents a normalized security or authentication event extracted from
// host logs (/var/log/auth.log, /var/log/secure, or Windows Event Logs).
type LogEntry struct {
	TimestampUTC string            `json:"timestamp_utc"`
	Source       string            `json:"source"`     // e.g., "/var/log/auth.log", "Security", "System", "Microsoft-Windows-Sysmon/Operational"
	EventID      string            `json:"event_id"`   // e.g., "4624", "4688", "7045", "ssh_accepted", "ssh_failed", "sudo_exec", "useradd"
	EventType    string            `json:"event_type"` // Human/SIEM category
	User         string            `json:"user,omitempty"`
	SourceIP     string            `json:"source_ip,omitempty"`
	ProcessOrCmd string            `json:"process_or_command,omitempty"`
	RawMessage   string            `json:"raw_message"`
	Fields       map[string]string `json:"fields,omitempty"`
}

// ModuleError records non-fatal errors encountered during a module's execution
// so partial forensic evidence is preserved.
type ModuleError struct {
	Module       string `json:"module"`
	ErrorMessage string `json:"error_message"`
	TimestampUTC string `json:"timestamp_utc"`
}

// FormatUTC converts a time.Time value to a strict UTC ISO-8601 (RFC3339) string.
func FormatUTC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
