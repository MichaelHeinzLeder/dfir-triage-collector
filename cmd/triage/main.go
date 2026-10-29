// Package main provides the CLI entrypoint for dfir-triage-go.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/collector"
	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

func main() {
	var (
		outputPath string
		modulesRaw string
		timeoutSec int
		verbose    bool
	)

	flag.StringVar(&outputPath, "o", "", "Output JSON file path (default: triage_<hostname>_<timestamp>.json)")
	flag.StringVar(&outputPath, "output", "", "Output JSON file path (default: triage_<hostname>_<timestamp>.json)")
	flag.StringVar(&modulesRaw, "m", "all", "Comma-separated modules to run (all, persistence, processes, network, logs)")
	flag.StringVar(&modulesRaw, "modules", "all", "Comma-separated modules to run (all, persistence, processes, network, logs)")
	flag.IntVar(&timeoutSec, "t", 30, "Per-module execution timeout in seconds")
	flag.IntVar(&timeoutSec, "timeout", 30, "Per-module execution timeout in seconds")
	flag.BoolVar(&verbose, "v", false, "Structured debug logging to stderr")
	flag.BoolVar(&verbose, "verbose", false, "Structured debug logging to stderr")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "dfir-triage-go - Incident Response & Host Triage CLI Collector\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags]\n\nFlags:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  -o, --output <path>       Output JSON file path (default: triage_<hostname>_<timestamp>.json)\n")
		fmt.Fprintf(os.Stderr, "  -m, --modules <list>      Comma-separated modules to run (all, persistence, processes, network, logs) (default: \"all\")\n")
		fmt.Fprintf(os.Stderr, "  -t, --timeout <seconds>   Per-module execution timeout in seconds (default: 30)\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose             Structured debug logging to stderr\n")
	}

	flag.Parse()

	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	moduleTimeout := time.Duration(timeoutSec) * time.Second

	// Configure structured logger to stderr when verbose is enabled.
	var logWriter io.Writer = io.Discard
	logLevel := slog.LevelInfo
	if verbose {
		logWriter = os.Stderr
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: logLevel,
	}))

	selectedModules, err := collector.ParseModulesFlag(modulesRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error parsing --modules flag: %v\n", err)
		os.Exit(1)
	}

	// Instantiate the platform-specific collector (implemented via OS build tags).
	platformCollector := collector.NewPlatformCollector(logger)

	// Forensic privilege check at startup.
	if platformCollector.IsElevated() {
		logger.Info("privilege check passed: running with elevated privileges (root/Administrator)")
		fmt.Fprintf(os.Stderr, "[+] Privilege Check: ELEVATED (root / Administrator)\n")
	} else {
		logger.Warn("privilege check warning: running with unprivileged user context; some forensic artifacts may be inaccessible")
		fmt.Fprintf(os.Stderr, "[!] Privilege Check: UNPRIVILEGED (some forensic artifacts may be restricted)\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	engine := collector.NewEngine(platformCollector, moduleTimeout, logger)
	logger.Info("starting triage collection", "modules", selectedModules, "timeout_sec", timeoutSec)

	report := engine.Run(ctx, selectedModules)

	if strings.TrimSpace(outputPath) == "" {
		host := sanitizeFilename(report.HostInfo.Hostname)
		if host == "" {
			host = "unknown_host"
		}
		ts := time.Now().UTC().Format("20060102T150405Z")
		outputPath = fmt.Sprintf("triage_%s_%s.json", host, ts)
	}

	if err := writeJSONReport(outputPath, report); err != nil {
		logger.Error("failed to write JSON report", "path", outputPath, "error", err.Error())
		fmt.Fprintf(os.Stderr, "[!] Failed to write output report to %s: %v\n", outputPath, err)
		os.Exit(1)
	}

	printConsoleSummary(report, outputPath)
}

func writeJSONReport(path string, report models.TriageReport) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}

func printConsoleSummary(report models.TriageReport, outputPath string) {
	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Println("                       DFIR-TRIAGE-GO COLLECTION SUMMARY                        ")
	fmt.Println("================================================================================")

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Hostname:\t%s\n", report.HostInfo.Hostname)
	fmt.Fprintf(tw, "OS / Kernel:\t%s (%s) / %s\n", report.HostInfo.OS, report.HostInfo.OSVersion, report.HostInfo.KernelVersion)
	fmt.Fprintf(tw, "Current User:\t%s (%s)\n", report.HostInfo.CurrentUser, report.HostInfo.PrivilegeLevel)
	fmt.Fprintf(tw, "Uptime:\t%d seconds (Boot: %s)\n", report.HostInfo.UptimeSeconds, report.HostInfo.BootTimeUTC)
	fmt.Fprintf(tw, "Generated At (UTC):\t%s\n", report.ReportMetadata.GeneratedAtUTC)
	fmt.Fprintf(tw, "Execution Duration:\t%d ms\n", report.ReportMetadata.DurationMs)
	fmt.Fprintf(tw, "Modules Executed:\t%s\n", strings.Join(report.ReportMetadata.ModulesExecuted, ", "))
	tw.Flush()

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("ARTIFACT COUNTS BY CATEGORY")
	fmt.Println("--------------------------------------------------------------------------------")

	cw := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintf(cw, "CATEGORY\tCOUNT\tSTATUS\n")
	fmt.Fprintf(cw, "--------\t-----\t------\n")
	fmt.Fprintf(cw, "Running Processes\t%d\tCollected\n", len(report.Processes))
	fmt.Fprintf(cw, "Network Connections\t%d\tCollected\n", len(report.Network))
	fmt.Fprintf(cw, "Persistence Items\t%d\tCollected\n", len(report.Persistence))
	fmt.Fprintf(cw, "Execution Artifacts\t%d\tCollected\n", len(report.Execution))
	fmt.Fprintf(cw, "Security Log Events\t%d\tCollected\n", len(report.SecurityEvents))
	fmt.Fprintf(cw, "Collection Warnings\t%d\tRecorded\n", len(report.CollectionErrors))
	cw.Flush()

	fmt.Println("================================================================================")
	fmt.Printf("[+] JSON report written to: %s\n", outputPath)
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
