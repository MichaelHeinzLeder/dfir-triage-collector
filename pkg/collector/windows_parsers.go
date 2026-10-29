// Package collector includes cross-platform XML and forensic artifact parsers
// so Windows Scheduled Task XML, Windows Event Log XML, and Prefetch filename parsers
// can be unit-tested on any host OS.
package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

// winScheduledTaskXML models the schema of C:\Windows\System32\Tasks\** XML files.
type winScheduledTaskXML struct {
	XMLName          xml.Name `xml:"Task"`
	RegistrationInfo struct {
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
		URI         string `xml:"URI"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal []struct {
			UserID    string `xml:"UserId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Actions struct {
		Exec []struct {
			Command          string `xml:"Command"`
			Arguments        string `xml:"Arguments"`
			WorkingDirectory string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// parseScheduledTaskXML decodes a Windows Task Scheduler XML buffer (supporting both UTF-8 and UTF-16LE/BE BOMs)
// into PersistenceItem entries.
func parseScheduledTaskXML(rawBytes []byte, sourcePath, modUTC string, hashFunc func(string) string) []models.PersistenceItem {
	utf8XML := normalizeXMLBytesToUTF8(rawBytes)

	decoder := xml.NewDecoder(bytes.NewReader(utf8XML))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	var task winScheduledTaskXML
	if err := decoder.Decode(&task); err != nil {
		return nil
	}

	if len(task.Actions.Exec) == 0 {
		return nil
	}

	var userID, runLevel string
	if len(task.Principals.Principal) > 0 {
		userID = strings.TrimSpace(task.Principals.Principal[0].UserID)
		runLevel = strings.TrimSpace(task.Principals.Principal[0].RunLevel)
	}

	taskName := strings.TrimSpace(task.RegistrationInfo.URI)
	if taskName == "" {
		taskName = filepath.Base(sourcePath)
	}

	var items []models.PersistenceItem
	for _, execAct := range task.Actions.Exec {
		cmd := strings.TrimSpace(execAct.Command)
		args := strings.TrimSpace(execAct.Arguments)
		if cmd == "" {
			continue
		}

		fullCmd := cmd
		if args != "" {
			fullCmd = cmd + " " + args
		}

		cleanBin := extractWindowsExecutablePath(cmd)
		var sha string
		if cleanBin != "" && hashFunc != nil {
			sha = hashFunc(cleanBin)
		}

		meta := make(map[string]string)
		if task.RegistrationInfo.Author != "" {
			meta["author"] = strings.TrimSpace(task.RegistrationInfo.Author)
		}
		if runLevel != "" {
			meta["run_level"] = runLevel
		}
		if execAct.WorkingDirectory != "" {
			meta["working_directory"] = strings.TrimSpace(execAct.WorkingDirectory)
		}

		items = append(items, models.PersistenceItem{
			Category:       "scheduled_task",
			Name:           taskName,
			SourcePath:     sourcePath,
			User:           userID,
			CommandOrValue: fullCmd,
			TargetBinary:   cleanBin,
			TargetSHA256:   sha,
			ModifiedAtUTC:  modUTC,
			Metadata:       meta,
		})
	}

	return items
}

// normalizeXMLBytesToUTF8 converts UTF-16LE or UTF-16BE XML files (common in C:\Windows\System32\Tasks) into UTF-8.
func normalizeXMLBytesToUTF8(data []byte) []byte {
	if len(data) >= 2 {
		// UTF-16LE BOM (FF FE)
		if data[0] == 0xFF && data[1] == 0xFE {
			return decodeUTF16ToUTF8(data[2:], binary.LittleEndian)
		}
		// UTF-16BE BOM (FE FF)
		if data[0] == 0xFE && data[1] == 0xFF {
			return decodeUTF16ToUTF8(data[2:], binary.BigEndian)
		}
		// Heuristic UTF-16LE without BOM (ASCII '<' followed by 0x00)
		if data[0] == '<' && data[1] == 0x00 {
			return decodeUTF16ToUTF8(data, binary.LittleEndian)
		}
	}
	// Strip UTF-8 BOM if present
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

func decodeUTF16ToUTF8(b []byte, order binary.ByteOrder) []byte {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = order.Uint16(b[i*2 : i*2+2])
	}
	runes := utf16.Decode(u16s)
	return []byte(string(runes))
}

// winEventXML models a single Windows Event Log `<Event>` node returned by `wevtutil qe /f:xml`.
type winEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// parseWindowsEventXMLStream parses a stream of `<Event>...</Event>` XML blocks from wevtutil output.
func parseWindowsEventXMLStream(xmlStream string, defaultChannel string) []models.LogEntry {
	wrapped := "<Events>" + xmlStream + "</Events>"
	decoder := xml.NewDecoder(strings.NewReader(wrapped))

	var entries []models.LogEntry
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}

		var ev winEventXML
		if err := decoder.DecodeElement(&ev, &se); err != nil {
			continue
		}

		if entry, ok := normalizeWindowsEvent(ev, defaultChannel); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func normalizeWindowsEvent(ev winEventXML, defaultChannel string) (models.LogEntry, bool) {
	if ev.System.EventID == 0 {
		return models.LogEntry{}, false
	}

	fields := make(map[string]string)
	for _, d := range ev.EventData.Data {
		k := strings.TrimSpace(d.Name)
		v := strings.TrimSpace(d.Value)
		if k != "" && v != "" {
			fields[k] = v
		}
	}

	channel := strings.TrimSpace(ev.System.Channel)
	if channel == "" {
		channel = defaultChannel
	}

	tsUTC := ev.System.TimeCreated.SystemTime
	if parsedTime, err := time.Parse(time.RFC3339Nano, tsUTC); err == nil {
		tsUTC = models.FormatUTC(parsedTime)
	}

	eventIDStr := strconv.Itoa(ev.System.EventID)
	entry := models.LogEntry{
		TimestampUTC: tsUTC,
		Source:       channel,
		EventID:      eventIDStr,
		Fields:       fields,
	}

	switch ev.System.EventID {
	case 4624:
		entry.EventType = "Windows Logon Success (4624)"
		entry.User = joinDomainUser(fields["TargetDomainName"], fields["TargetUserName"])
		entry.SourceIP = fields["IpAddress"]
		entry.ProcessOrCmd = fields["ProcessName"]
		entry.RawMessage = "LogonType=" + fields["LogonType"] + " User=" + entry.User + " IP=" + entry.SourceIP

	case 4625:
		entry.EventType = "Windows Logon Failure (4625)"
		entry.User = joinDomainUser(fields["TargetDomainName"], fields["TargetUserName"])
		entry.SourceIP = fields["IpAddress"]
		entry.ProcessOrCmd = fields["ProcessName"]
		entry.RawMessage = "Failed LogonType=" + fields["LogonType"] + " User=" + entry.User + " Status=" + fields["Status"]

	case 4688:
		entry.EventType = "Security Process Creation (4688)"
		entry.User = joinDomainUser(fields["SubjectDomainName"], fields["SubjectUserName"])
		cmd := fields["CommandLine"]
		if cmd == "" {
			cmd = fields["NewProcessName"]
		}
		entry.ProcessOrCmd = cmd
		entry.RawMessage = "Process=" + fields["NewProcessName"] + " CommandLine=" + cmd

	case 4720:
		entry.EventType = "User Account Created (4720)"
		entry.User = joinDomainUser(fields["TargetDomainName"], fields["TargetUserName"])
		entry.ProcessOrCmd = "Subject=" + joinDomainUser(fields["SubjectDomainName"], fields["SubjectUserName"])
		entry.RawMessage = "Created User=" + entry.User + " by " + entry.ProcessOrCmd

	case 7045:
		entry.EventType = "New Service Installed (7045)"
		entry.User = fields["AccountName"]
		entry.ProcessOrCmd = fields["ImagePath"]
		entry.RawMessage = "ServiceName=" + fields["ServiceName"] + " ImagePath=" + fields["ImagePath"]

	case 1:
		entry.EventType = "Sysmon Process Create (EventID 1)"
		entry.User = fields["User"]
		cmd := fields["CommandLine"]
		if cmd == "" {
			cmd = fields["Image"]
		}
		entry.ProcessOrCmd = cmd
		entry.RawMessage = "Image=" + fields["Image"] + " CommandLine=" + cmd + " Hashes=" + fields["Hashes"]

	case 3:
		entry.EventType = "Sysmon Network Connection (EventID 3)"
		entry.User = fields["User"]
		entry.SourceIP = fields["DestinationIp"]
		entry.ProcessOrCmd = fields["Image"]
		entry.RawMessage = "Image=" + fields["Image"] + " Dst=" + fields["DestinationIp"] + ":" + fields["DestinationPort"]

	case 11:
		entry.EventType = "Sysmon FileCreate (EventID 11)"
		entry.User = fields["User"]
		entry.ProcessOrCmd = fields["TargetFilename"]
		entry.RawMessage = "Image=" + fields["Image"] + " TargetFilename=" + fields["TargetFilename"]

	default:
		entry.EventType = "Windows Event " + eventIDStr
		entry.RawMessage = "EventID=" + eventIDStr
	}

	return entry, true
}

func joinDomainUser(domain, user string) string {
	if domain != "" && domain != "-" && user != "" {
		return domain + `\` + user
	}
	return user
}

// extractWindowsExecutablePath extracts the file path of the executable from a Windows command line or Registry value.
func extractWindowsExecutablePath(rawCmd string) string {
	trimmed := strings.TrimSpace(rawCmd)
	if trimmed == "" {
		return ""
	}

	var candidate string
	if strings.HasPrefix(trimmed, `"`) {
		endQuote := strings.IndexByte(trimmed[1:], '"')
		if endQuote >= 0 {
			candidate = trimmed[1 : endQuote+1]
		}
	} else {
		lower := strings.ToLower(trimmed)
		if idx := strings.Index(lower, ".exe"); idx > 0 {
			candidate = trimmed[:idx+4]
		} else {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				candidate = fields[0]
			}
		}
	}

	return expandWindowsEnvVars(candidate)
}

// expandWindowsEnvVars expands %SystemRoot%, %windir%, %ProgramFiles%, and %AppData% style variables.
func expandWindowsEnvVars(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	replacements := map[string]string{
		"%systemroot%":   sysRoot,
		"%windir%":       sysRoot,
		"%programfiles%": `C:\Program Files`,
		"%programdata%":  `C:\ProgramData`,
	}

	result := p
	lower := strings.ToLower(result)
	for k, v := range replacements {
		if idx := strings.Index(lower, k); idx >= 0 {
			result = result[:idx] + v + result[idx+len(k):]
			lower = strings.ToLower(result)
		}
	}
	return result
}

// splitPrefetchFilename splits a prefetch file name like "CMD.EXE-4A81B302.pf" into ("CMD.EXE", "4A81B302").
func splitPrefetchFilename(filename string) (exeName string, pfHash string) {
	base := strings.TrimSuffix(strings.TrimSuffix(filename, ".pf"), ".PF")
	dashIdx := strings.LastIndexByte(base, '-')
	if dashIdx > 0 && dashIdx+1 < len(base) {
		return base[:dashIdx], base[dashIdx+1:]
	}
	return base, ""
}
