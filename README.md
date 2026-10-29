# dfir-triage-collector

Go host triage and forensic artifact collector for Windows and Linux endpoints (`CGO_ENABLED=0`), targeting Blue Team Level 1 (BTL1) and MITRE ATT&CK persistence, execution, and log triage domains.

## Architecture

- **Orchestration & OS Abstraction (`pkg/collector`)**: Defines the `ArtifactCollector` interface implemented via compile-time OS build constraints (`//go:build linux` and `//go:build windows`). `Engine` executes independent collection modules concurrently via `sync.WaitGroup` with bounded per-module `context.WithTimeout` deadlines, read-only SHA-256 binary hashing (`HashFileSHA256`), and startup privilege checks (`os.Geteuid() == 0` on Linux; `windows.GetCurrentProcessToken().IsElevated()` on Windows).
- **Linux Collector (`linux_*.go`)**: Parses `/proc/[pid]/{stat,cmdline,status,exe}` and correlates `/proc/[pid]/fd/*` socket inodes against `/proc/net/{tcp,tcp6,udp,udp6}`. Enumerates persistence across `/etc/crontab`, `/etc/cron.*/*`, `/var/spool/cron/crontabs/*`, `/etc/systemd/system/*.service`, `~/.bashrc`, and `~/.ssh/authorized_keys`. Collects `~/.bash_history`, `~/.zsh_history`, SUID/SGID binaries, and `/var/log/auth.log` or `/var/log/secure` events (`sshd`, `sudo`, `useradd`).
- **Windows Collector (`windows_*.go`, `windows_parsers.go`)**: Enumerates processes via `CreateToolhelp32Snapshot`, `QueryFullProcessImageName`, and `OpenProcessToken`, and correlates active sockets via `netstat -ano`. Queries `HKLM` and `HKCU` (`64-bit` and `WOW6432Node`) `Run`/`RunOnce` Registry keys via `golang.org/x/sys/windows/registry`, Startup directories, UTF-8/UTF-16 XML definitions in `C:\Windows\System32\Tasks`, and `C:\Windows\Prefetch\*.pf` metadata. Queries Windows Event Logs via XPath (`Security`: `4624`, `4625`, `4688`, `4720`; `System`: `7045`; `Sysmon`: `1`, `3`, `11`).
- **Output Schema (`pkg/models`)**: Serializes normalized artifacts with UTC ISO-8601 (`RFC3339`) timestamps to indented JSON alongside a `text/tabwriter` console summary.

```text
.
├── Makefile
├── go.mod
├── cmd/
│   └── triage/
│       └── main.go
└── pkg/
    ├── models/
    │   └── models.go
    └── collector/
        ├── collector.go
        ├── linux_collector.go
        ├── linux_collector_test.go
        ├── linux_logs.go
        ├── linux_persistence.go
        ├── windows_collector.go
        ├── windows_collector_test.go
        ├── windows_logs.go
        ├── windows_parsers.go
        └── windows_persistence.go
```

## MITRE ATT&CK Mapping

| Module | Platform | Artifacts | Technique |
| :--- | :--- | :--- | :--- |
| `host_info` | Linux, Windows | Hostname, OS/build, kernel, user, privilege level, uptime | `T1082`, `T1033` |
| `processes` | Linux, Windows | PID, PPID, executable path, command line, owner, binary SHA-256 | `T1057`, `T1059` |
| `network` | Linux, Windows | TCP/UDP (IPv4/IPv6) endpoints, socket state, owning PID & process | `T1049`, `T1071` |
| `persistence` | Linux | `/etc/crontab`, `/etc/cron.*/*`, `/var/spool/cron/crontabs/*`, `/etc/systemd/system/*.service`, `~/.bashrc`, `~/.ssh/authorized_keys`, `.bash_history`, `.zsh_history`, SUID/SGID binaries | `T1053.003`, `T1543.002`, `T1546.004`, `T1098.004`, `T1548.001` |
| `persistence` | Windows | `HKLM`/`HKCU` `Run` & `RunOnce`, Startup folders, `C:\Windows\System32\Tasks` XMLs, `C:\Windows\Prefetch\*.pf` | `T1547.001`, `T1053.005`, `T1204` |
| `logs` | Linux | `/var/log/auth.log`, `/var/log/secure` (`sshd` accepted/failed, `sudo`, `useradd`) | `T1110`, `T1021.004`, `T1548.003`, `T1136.001` |
| `logs` | Windows | `Security` (`4624`, `4625`, `4688`, `4720`), `System` (`7045`), `Sysmon` (`1`, `3`, `11`) | `T1078`, `T1543.003`, `T1136.001` |

## Dependencies

System requirements:
- Go >= 1.22

Managed via `go.mod`:
- [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) (`v0.26.0`)

## Build & Test

```bash
make all
make test
```

Or directly via `go build`:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/dfir-triage-linux-amd64 ./cmd/triage
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/dfir-triage-windows-amd64.exe ./cmd/triage
```

## Usage

```bash
./bin/dfir-triage-linux-amd64 [-o <path>] [-m <modules>] [-t <seconds>] [-v]
```

Example:

```bash
sudo ./bin/dfir-triage-linux-amd64 -m all -t 30 -o triage_report.json
```

> Note: All `triage_*.json` output reports and compiled binaries under `bin/` are ignored via `.gitignore` to prevent committing host artifacts.
