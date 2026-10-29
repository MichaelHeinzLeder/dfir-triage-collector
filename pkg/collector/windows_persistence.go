//go:build windows

package collector

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"github.com/dfir-triage-collector/dfir-triage-go/pkg/models"
)

// CollectPersistence gathers Windows persistence mechanisms and execution artifacts:
//   - Persistence: Registry Run/RunOnce keys (HKLM & HKCU, 64-bit & WOW6432Node), Startup folders,
//     and Scheduled Tasks XML files in C:\Windows\System32\Tasks.
//   - Execution Artifacts: Windows Prefetch files (C:\Windows\Prefetch\*.pf) with creation/modification timestamps and sizes.
func (c *WindowsCollector) CollectPersistence(ctx context.Context) ([]models.PersistenceItem, []models.ExecutionArtifact, error) {
	var persistence []models.PersistenceItem
	var execution []models.ExecutionArtifact

	// 1. Registry Run & RunOnce Keys (HKLM & HKCU)
	persistence = append(persistence, c.collectRegistryRunKeys(ctx)...)

	// 2. Startup Folder Items (All Users + Per-User Startup Directories)
	persistence = append(persistence, c.collectStartupFolders(ctx)...)

	// 3. Scheduled Tasks XML Definitions (C:\Windows\System32\Tasks)
	persistence = append(persistence, c.collectScheduledTasks(ctx)...)

	// 4. Windows Prefetch Execution Artifacts (C:\Windows\Prefetch\*.pf)
	execution = append(execution, c.collectPrefetchArtifacts(ctx)...)

	return persistence, execution, nil
}

func (c *WindowsCollector) collectRegistryRunKeys(ctx context.Context) []models.PersistenceItem {
	type regTarget struct {
		root     registry.Key
		rootName string
		subKey   string
	}

	targets := []regTarget{
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.CURRENT_USER, "HKCU", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, "HKCU", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	}

	var items []models.PersistenceItem
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return items
		default:
		}

		k, err := registry.OpenKey(t.root, t.subKey, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		var keyModUTC string
		if stat, err := k.Stat(); err == nil {
			keyModUTC = models.FormatUTC(stat.ModTime())
		}

		valNames, err := k.ReadValueNames(-1)
		if err != nil {
			k.Close()
			continue
		}

		for _, name := range valNames {
			valStr, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}

			binPath := extractWindowsExecutablePath(valStr)
			var sha string
			if binPath != "" {
				sha, _ = HashFileSHA256(binPath)
			}

			items = append(items, models.PersistenceItem{
				Category:       "registry_run",
				Name:           name,
				SourcePath:     t.rootName + `\` + t.subKey,
				CommandOrValue: valStr,
				TargetBinary:   binPath,
				TargetSHA256:   sha,
				ModifiedAtUTC:  keyModUTC,
			})
		}
		k.Close()
	}

	return items
}

func (c *WindowsCollector) collectStartupFolders(ctx context.Context) []models.PersistenceItem {
	var startupDirs []string

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	startupDirs = append(startupDirs, filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`))

	usersDir := `C:\Users`
	if entries, err := os.ReadDir(usersDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				userStartup := filepath.Join(usersDir, e.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
				startupDirs = append(startupDirs, userStartup)
			}
		}
	}

	seenDirs := make(map[string]bool)
	var items []models.PersistenceItem

	for _, dir := range startupDirs {
		select {
		case <-ctx.Done():
			return items
		default:
		}

		cleanDir := filepath.Clean(dir)
		if seenDirs[strings.ToLower(cleanDir)] {
			continue
		}
		seenDirs[strings.ToLower(cleanDir)] = true

		entries, err := os.ReadDir(cleanDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.EqualFold(entry.Name(), "desktop.ini") {
				continue
			}
			fullPath := filepath.Join(cleanDir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			sha, _ := HashFileSHA256(fullPath)
			items = append(items, models.PersistenceItem{
				Category:       "startup_folder",
				Name:           entry.Name(),
				SourcePath:     fullPath,
				CommandOrValue: fullPath,
				TargetBinary:   fullPath,
				TargetSHA256:   sha,
				ModifiedAtUTC:  models.FormatUTC(info.ModTime()),
			})
		}
	}

	return items
}

func (c *WindowsCollector) collectScheduledTasks(ctx context.Context) []models.PersistenceItem {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	tasksDir := filepath.Join(sysRoot, "System32", "Tasks")

	var items []models.PersistenceItem
	_ = filepath.WalkDir(tasksDir, func(path string, d fs.DirEntry, walkErr error) error {
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
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
			return nil
		}

		rawBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		taskItems := parseScheduledTaskXML(rawBytes, path, models.FormatUTC(info.ModTime()), func(p string) string {
			expanded := expandWindowsEnvVars(p)
			h, _ := HashFileSHA256(expanded)
			return h
		})
		items = append(items, taskItems...)
		return nil
	})

	return items
}

func (c *WindowsCollector) collectPrefetchArtifacts(ctx context.Context) []models.ExecutionArtifact {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	prefetchDir := filepath.Join(sysRoot, "Prefetch")

	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		return nil
	}

	var results []models.ExecutionArtifact
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}

		fullPath := filepath.Join(prefetchDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		var createdUTC string
		if sysAttr, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
			createdUTC = filetimeToUTC(sysAttr.CreationTime)
		}

		sha, _ := HashFileSHA256(fullPath)
		exeName, pfHash := splitPrefetchFilename(entry.Name())

		results = append(results, models.ExecutionArtifact{
			ArtifactType:  "windows_prefetch",
			Path:          fullPath,
			Command:       exeName,
			SizeBytes:     info.Size(),
			CreatedAtUTC:  createdUTC,
			ModifiedAtUTC: models.FormatUTC(info.ModTime()),
			SHA256:        sha,
			Metadata: map[string]string{
				"prefetch_hash": pfHash,
			},
		})
	}

	return results
}
