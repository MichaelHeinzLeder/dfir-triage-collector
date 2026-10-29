// Package collector defines the OS-agnostic interface and orchestration engine
// for concurrent forensic artifact collection.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

// ModuleName identifies a discrete collection module selectable via CLI flags.
type ModuleName string

const (
	ModuleAll         ModuleName = "all"
	ModuleProcesses   ModuleName = "processes"
	ModuleNetwork     ModuleName = "network"
	ModulePersistence ModuleName = "persistence"
	ModuleLogs        ModuleName = "logs"
)

// ValidModules lists the canonical runnable collection modules in deterministic order.
var ValidModules = []ModuleName{
	ModuleProcesses,
	ModuleNetwork,
	ModulePersistence,
	ModuleLogs,
}

// ArtifactCollector is the core OS-abstraction interface implemented by
// platform-specific collectors (//go:build linux and //go:build windows).
type ArtifactCollector interface {
	// IsElevated returns true if the current process has root (UID 0) or Windows Administrator privileges.
	IsElevated() bool

	// CollectHostInfo gathers volatile system metadata, OS version, kernel, user, and uptime.
	CollectHostInfo(ctx context.Context) (models.HostInfo, error)

	// CollectProcesses enumerates active processes, arguments, owners, and binary SHA-256 hashes.
	CollectProcesses(ctx context.Context) ([]models.ProcessArtifact, error)

	// CollectNetwork enumerates active TCP/UDP sockets and maps them to owning PIDs.
	CollectNetwork(ctx context.Context) ([]models.NetworkArtifact, error)

	// CollectPersistence gathers OS-specific persistence mechanisms and execution artifacts
	// (e.g., Cron/Systemd/SUID/History on Linux; Registry/Startup/Tasks/Prefetch on Windows).
	CollectPersistence(ctx context.Context) ([]models.PersistenceItem, []models.ExecutionArtifact, error)

	// CollectLogs parses high-value authentication, privilege, and security logs.
	CollectLogs(ctx context.Context) ([]models.LogEntry, error)
}

// Engine coordinates concurrent execution of selected modules with per-module context timeouts.
type Engine struct {
	collector ArtifactCollector
	timeout   time.Duration
	logger    *slog.Logger
}

// NewEngine initializes a collection orchestration engine.
func NewEngine(c ArtifactCollector, timeout time.Duration, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Engine{
		collector: c,
		timeout:   timeout,
		logger:    logger,
	}
}

// Run executes host metadata collection followed by concurrent execution of the requested modules.
func (e *Engine) Run(parentCtx context.Context, requestedModules []ModuleName) models.TriageReport {
	startTime := time.Now().UTC()
	elevated := e.collector.IsElevated()

	modulesToRun := ResolveModules(requestedModules)
	moduleStrings := make([]string, 0, len(modulesToRun))
	for _, m := range modulesToRun {
		moduleStrings = append(moduleStrings, string(m))
	}

	report := models.TriageReport{
		ReportMetadata: models.ReportMetadata{
			ToolName:        "dfir-triage-go",
			ToolVersion:     "1.0.0",
			GeneratedAtUTC:  models.FormatUTC(startTime),
			ModulesExecuted: moduleStrings,
			Elevated:        elevated,
		},
	}

	var mu sync.Mutex
	recordError := func(mod string, err error) {
		if err == nil {
			return
		}
		e.logger.Warn("module encountered error", "module", mod, "error", err.Error())
		mu.Lock()
		report.CollectionErrors = append(report.CollectionErrors, models.ModuleError{
			Module:       mod,
			ErrorMessage: err.Error(),
			TimestampUTC: models.FormatUTC(time.Now().UTC()),
		})
		mu.Unlock()
	}

	// Always collect baseline host info first with a bounded timeout.
	hostCtx, cancelHost := context.WithTimeout(parentCtx, e.timeout)
	hostInfo, err := e.collector.CollectHostInfo(hostCtx)
	cancelHost()
	if err != nil {
		recordError("host_info", err)
	}
	report.HostInfo = hostInfo

	// Run selected collection modules concurrently.
	var wg sync.WaitGroup
	for _, mod := range modulesToRun {
		mod := mod
		wg.Add(1)
		go func() {
			defer wg.Done()

			modCtx, cancel := context.WithTimeout(parentCtx, e.timeout)
			defer cancel()

			modStart := time.Now()
			e.logger.Debug("starting module", "module", string(mod), "timeout", e.timeout.String())

			switch mod {
			case ModuleProcesses:
				procs, err := e.collector.CollectProcesses(modCtx)
				if err != nil {
					recordError(string(mod), err)
				}
				mu.Lock()
				report.Processes = procs
				mu.Unlock()

			case ModuleNetwork:
				conns, err := e.collector.CollectNetwork(modCtx)
				if err != nil {
					recordError(string(mod), err)
				}
				mu.Lock()
				report.Network = conns
				mu.Unlock()

			case ModulePersistence:
				pers, execArts, err := e.collector.CollectPersistence(modCtx)
				if err != nil {
					recordError(string(mod), err)
				}
				mu.Lock()
				report.Persistence = pers
				report.Execution = execArts
				mu.Unlock()

			case ModuleLogs:
				logs, err := e.collector.CollectLogs(modCtx)
				if err != nil {
					recordError(string(mod), err)
				}
				mu.Lock()
				report.SecurityEvents = logs
				mu.Unlock()
			}

			e.logger.Debug("completed module", "module", string(mod), "duration_ms", time.Since(modStart).Milliseconds())
		}()
	}

	wg.Wait()
	report.ReportMetadata.DurationMs = time.Since(startTime).Milliseconds()
	return report
}

// ResolveModules parses and deduplicates module names, expanding "all" into all valid modules.
func ResolveModules(requested []ModuleName) []ModuleName {
	if len(requested) == 0 {
		return ValidModules
	}
	seen := make(map[ModuleName]bool)
	for _, m := range requested {
		normalized := ModuleName(strings.ToLower(strings.TrimSpace(string(m))))
		if normalized == ModuleAll {
			return ValidModules
		}
		seen[normalized] = true
	}

	var result []ModuleName
	for _, valid := range ValidModules {
		if seen[valid] {
			result = append(result, valid)
		}
	}
	return result
}

// ParseModulesFlag validates a comma-separated list of module names from CLI flags.
func ParseModulesFlag(raw string) ([]ModuleName, error) {
	if strings.TrimSpace(raw) == "" {
		return ValidModules, nil
	}
	parts := strings.Split(raw, ",")
	var parsed []ModuleName
	for _, p := range parts {
		clean := ModuleName(strings.ToLower(strings.TrimSpace(p)))
		if clean == "" {
			continue
		}
		switch clean {
		case ModuleAll, ModuleProcesses, ModuleNetwork, ModulePersistence, ModuleLogs:
			parsed = append(parsed, clean)
		default:
			return nil, fmt.Errorf("unknown module %q (valid: all, persistence, processes, network, logs)", p)
		}
	}
	if len(parsed) == 0 {
		return ValidModules, nil
	}
	return ResolveModules(parsed), nil
}

// maxHashFileSize limits SHA-256 hashing to files <= 128 MB to avoid stalling triage on huge files.
const maxHashFileSize = 128 * 1024 * 1024

// HashFileSHA256 computes the SHA-256 digest of a file in read-only mode without modifying
// target file metadata where possible. Returns an empty string if the file cannot be read or is not a regular file.
func HashFileSHA256(path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", fmt.Errorf("empty path")
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", cleanPath)
	}
	if info.Size() > maxHashFileSize {
		return "", fmt.Errorf("file exceeds max hash size (%d bytes)", info.Size())
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
