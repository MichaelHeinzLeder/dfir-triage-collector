package collector

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseScheduledTaskXML_UTF8AndUTF16LE(t *testing.T) {
	xmlDoc := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>CORP\admin</Author>
    <Description>Updater Task</Description>
    <URI>\Microsoft\Windows\Maintenance\Updater</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>NT AUTHORITY\SYSTEM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\ProgramData\Updater\svc.exe"</Command>
      <Arguments>--silent --beacon 10.0.0.5</Arguments>
      <WorkingDirectory>C:\ProgramData\Updater</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`

	// Encode as UTF-16LE with BOM (FF FE) to mimic Windows System32\Tasks files
	u16 := utf16.Encode([]rune(xmlDoc))
	utf16Bytes := []byte{0xFF, 0xFE}
	for _, v := range u16 {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], v)
		utf16Bytes = append(utf16Bytes, b[:]...)
	}

	items := parseScheduledTaskXML(utf16Bytes, `C:\Windows\System32\Tasks\Updater`, "2026-10-30T00:00:00Z", func(p string) string {
		return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	})
	if len(items) != 1 {
		t.Fatalf("expected 1 scheduled task PersistenceItem, got %d", len(items))
	}

	got := items[0]
	if got.Category != "scheduled_task" || got.User != `NT AUTHORITY\SYSTEM` {
		t.Errorf("unexpected scheduled task user/category: %+v", got)
	}
	if got.TargetBinary != `C:\ProgramData\Updater\svc.exe` {
		t.Errorf("expected TargetBinary C:\\ProgramData\\Updater\\svc.exe, got %q", got.TargetBinary)
	}
	if got.Metadata["run_level"] != "HighestAvailable" {
		t.Errorf("expected run_level HighestAvailable, got %q", got.Metadata["run_level"])
	}
}

func TestParseWindowsEventXMLStream(t *testing.T) {
	sampleStream := `
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-10-30T00:10:00.0000000Z"/>
    <Channel>Security</Channel>
    <Computer>WIN-DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.20.30.40</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2026-10-30T00:11:00.0000000Z"/>
    <Channel>System</Channel>
    <Computer>WIN-DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">MalService</Data>
    <Data Name="ImagePath">%COMSPEC% /b /c powershell.exe -enc ZQBjAGgAbwA=</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-10-30T00:12:00.0000000Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="User">CORP\Administrator</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -c IEX</Data>
    <Data Name="Hashes">SHA256=AABBCCDDEEFF</Data>
  </EventData>
</Event>`

	entries := parseWindowsEventXMLStream(sampleStream, "Security")
	if len(entries) != 3 {
		t.Fatalf("expected 3 parsed Windows events, got %d", len(entries))
	}

	if entries[0].EventID != "4624" || entries[0].User != `CORP\Administrator` || entries[0].SourceIP != "10.20.30.40" {
		t.Errorf("unexpected 4624 event normalization: %+v", entries[0])
	}
	if entries[1].EventID != "7045" || entries[1].Fields["ServiceName"] != "MalService" {
		t.Errorf("unexpected 7045 event normalization: %+v", entries[1])
	}
	if entries[2].EventID != "1" || entries[2].ProcessOrCmd != "powershell.exe -nop -w hidden -c IEX" {
		t.Errorf("unexpected Sysmon EventID 1 normalization: %+v", entries[2])
	}
}

func TestSplitPrefetchFilename(t *testing.T) {
	exe, hash := splitPrefetchFilename("POWERSHELL.EXE-A1B2C3D4.pf")
	if exe != "POWERSHELL.EXE" || hash != "A1B2C3D4" {
		t.Errorf("expected (POWERSHELL.EXE, A1B2C3D4), got (%q, %q)", exe, hash)
	}
}
