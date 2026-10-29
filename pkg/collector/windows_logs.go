//go:build windows

package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

// CollectLogs queries high-value Windows Event IDs across Security, System, and Sysmon channels:
//   - Security: 4624 (Logon Success), 4625 (Logon Failure), 4688 (Process Creation), 4720 (User Account Created)
//   - System:   7045 (New Service Installed)
//   - Sysmon:   1 (Process Create), 3 (Network Connection), 11 (FileCreate)
func (c *WindowsCollector) CollectLogs(ctx context.Context) ([]models.LogEntry, error) {
	type channelQuery struct {
		channel string
		xpath   string
		maxEvts int
	}

	queries := []channelQuery{
		{
			channel: "Security",
			xpath:   "*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720)]]",
			maxEvts: 150,
		},
		{
			channel: "System",
			xpath:   "*[System[(EventID=7045)]]",
			maxEvts: 100,
		},
		{
			channel: "Microsoft-Windows-Sysmon/Operational",
			xpath:   "*[System[(EventID=1 or EventID=3 or EventID=11)]]",
			maxEvts: 150,
		},
	}

	var allEntries []models.LogEntry
	var channelErrors []string

	for _, q := range queries {
		select {
		case <-ctx.Done():
			return allEntries, ctx.Err()
		default:
		}

		cmd := exec.CommandContext(ctx, "wevtutil.exe", "qe", q.channel,
			"/q:"+q.xpath,
			fmt.Sprintf("/c:%d", q.maxEvts),
			"/rd:true",
			"/f:xml")

		out, err := cmd.Output()
		if err != nil {
			// Sysmon might not be installed or Security log may require elevation; log and continue.
			c.logger.Debug("wevtutil query skipped or failed", "channel", q.channel, "error", err.Error())
			if q.channel != "Microsoft-Windows-Sysmon/Operational" {
				channelErrors = append(channelErrors, fmt.Sprintf("%s: %v", q.channel, err))
			}
			continue
		}

		entries := parseWindowsEventXMLStream(string(out), q.channel)
		allEntries = append(allEntries, entries...)
	}

	if len(allEntries) == 0 && len(channelErrors) > 0 {
		return nil, fmt.Errorf("event log queries failed (%s)", strings.Join(channelErrors, "; "))
	}

	return allEntries, nil
}
