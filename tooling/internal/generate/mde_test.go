package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromMDEConfigFilteredGeneratesIncludeAndExcludeModules(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "out")
	result, err := FromMDEConfigFileMode(config, outDir, MDEModeFiltered)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) < 4 {
		t.Fatalf("expected multiple generated files, got %#v", result)
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "<Rule", "cmd.exe", "CommandLine")
	assertFileContains(t, filepath.Join(outDir, "exclude_mde_processcreate.xml"), `C:\Program Files\App\app.exe`)
	assertFileContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), "TargetObject", "HKCU\\software\\classes")
	assertFileContains(t, filepath.Join(outDir, "include_mde_filecreate.xml"), "TargetFilename", `C:\Users\`)
	assertFileContains(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"), `C:\Temp`)
	assertFileNotContains(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"), `C:\\Temp`)
	if result.Stats.RulesSeen == 0 || result.Stats.RulesMapped == 0 {
		t.Fatalf("expected stats to count mapped rules, got %#v", result.Stats)
	}
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "skipped broad MDE path exclusion") {
			t.Fatalf("process-scoped broad path exclusion should not warn, got %q", warning)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"), `C:\Program Files (x86)\Office\winword.exe`)
}

func TestFromMDEConfigUnfilteredGeneratesOnlyIncludeModules(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "unfiltered")
	result, err := FromMDEConfigFileMode(config, outDir, MDEModeUnfiltered)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range result.Files {
		if strings.Contains(filepath.Base(file), "exclude") {
			t.Fatalf("unfiltered mode generated exclude file: %s", file)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "MDE unfiltered", "Image")
	assertFileNotContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "cmd.exe")
}

func TestFromMDEConfigInverseGeneratesFilteredBlindSpotsAsIncludes(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "inverse")
	result, err := FromMDEConfigFileMode(config, outDir, MDEModeInverse)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range result.Files {
		if strings.Contains(filepath.Base(file), "exclude") {
			t.Fatalf("inverse mode generated exclude file: %s", file)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "MsSense.exe", `C:\Program Files\App\app.exe`)
	assertFileContains(t, filepath.Join(outDir, "include_mde_filecreate.xml"), `C:\Windows\`)
}

func TestFromMDEConfigProcessesOnlySelectedArea(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "process-only")
	result, err := FromMDEConfigFileOptions(config, outDir, MDEOptions{
		Mode:  MDEModeFiltered,
		Areas: []string{"process-creation"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.RulesSeen != 1 || result.Stats.RulesMapped != 1 {
		t.Fatalf("expected only the process-creation rule to be processed, got %#v", result.Stats)
	}
	for _, file := range result.Files {
		if !strings.Contains(filepath.Base(file), "processcreate") {
			t.Fatalf("selected process-creation area generated unrelated file %s", file)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "cmd.exe")
	if _, err := os.Stat(filepath.Join(outDir, "include_mde_registryevent.xml")); !os.IsNotExist(err) {
		t.Fatalf("registry output should not be generated, stat error: %v", err)
	}
}

func TestFromMDEConfigAcceptsMultipleAreas(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "selected")
	result, err := FromMDEConfigFileOptions(config, outDir, MDEOptions{
		Mode:  MDEModeFiltered,
		Areas: []string{"process-creation", "registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "cmd.exe")
	assertFileContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), "TargetObject")
	for _, file := range result.Files {
		if strings.Contains(filepath.Base(file), "filecreate") {
			t.Fatalf("unselected file-create area generated %s", file)
		}
	}
}

func TestFromMDEConfigRejectsUnknownArea(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	_, err := FromMDEConfigFileOptions(config, filepath.Join(dir, "out"), MDEOptions{
		Mode:  MDEModeFiltered,
		Areas: []string{"not-an-area"},
	})
	if err == nil || !strings.Contains(err.Error(), "supported areas") {
		t.Fatalf("expected supported-area error, got %v", err)
	}
}

func TestFromMDEConfigDeduplicatesAgainstExistingModules(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	baselineDir := filepath.Join(dir, "baseline")
	baseline, err := FromMDEConfigFileOptions(config, baselineDir, MDEOptions{
		Mode:  MDEModeFiltered,
		Areas: []string{"process-creation"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Files) == 0 {
		t.Fatal("expected baseline modules")
	}

	result, err := FromMDEConfigFileOptions(config, filepath.Join(dir, "deduped"), MDEOptions{
		Mode:            MDEModeFiltered,
		Areas:           []string{"process-creation"},
		ExistingModules: baseline.Files,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 0 {
		t.Fatalf("expected every process rule to be deduplicated, generated %#v", result.Files)
	}
	if result.Stats.DuplicateRules == 0 {
		t.Fatalf("expected duplicate rule count, got %#v", result.Stats)
	}
	if !containsString(result.Warnings, "all generated MDE rules already exist") {
		t.Fatalf("expected all-rules-deduplicated warning, got %#v", result.Warnings)
	}
}

func TestMDEDeduplicationKeepsDifferentOnmatch(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.xml")
	if err := WriteModuleFromRules(existing, "ProcessCreate", "include", []RuleSpec{{
		GroupRelation: "and",
		Conditions:    []Condition{{Field: "Image", Operator: "is", Value: "cmd.exe"}},
	}}); err != nil {
		t.Fatal(err)
	}
	keys, err := loadExistingRuleKeys([]string{existing})
	if err != nil {
		t.Fatal(err)
	}
	g := &mdeGenerator{dedup: true, existing: keys}
	rules := []RuleSpec{{GroupRelation: "and", Conditions: []Condition{{Field: "Image", Operator: "is", Value: "cmd.exe"}}}}
	if kept := g.removeExistingRules("ProcessCreate", "include", rules); len(kept) != 0 {
		t.Fatalf("expected matching include to be removed, got %#v", kept)
	}
	if kept := g.removeExistingRules("ProcessCreate", "exclude", rules); len(kept) != 1 {
		t.Fatalf("expected differently scoped exclude to remain, got %#v", kept)
	}
}

func TestMDEDeduplicationNormalizesConditionOrderCaseAndNames(t *testing.T) {
	left := RuleSpec{
		Name:          "Existing display name",
		GroupRelation: "AND",
		Conditions: []Condition{
			{Field: "CommandLine", Operator: "contains", Value: " /C "},
			{Field: "Image", Operator: "IS", Value: "CMD.EXE"},
		},
	}
	right := RuleSpec{
		Name:          "Different generated name",
		GroupRelation: "and",
		Conditions: []Condition{
			{Field: "image", Operator: "is", Value: "cmd.exe"},
			{Field: "commandline", Operator: "CONTAINS", Value: "/c"},
		},
	}
	if got, want := mdeRuleKey("ProcessCreate", "include", left), mdeRuleKey("processcreate", "INCLUDE", right); got != want {
		t.Fatalf("normalized rule keys differ:\nleft  %q\nright %q", got, want)
	}
}

func TestMDEPathNormalizationCollapsesDoubleBackslashes(t *testing.T) {
	tests := map[string]string{
		`C:\\Windows\\System32\\cmd.exe`:            `C:\Windows\System32\cmd.exe`,
		`%SystemRoot%\\System32\\WindowsPowerShell`: `C:\Windows\System32\WindowsPowerShell`,
		`HKLM\\Software\\Microsoft`:                 `HKLM\Software\Microsoft`,
		`\\server\\share\\folder`:                   `\\server\share\folder`,
	}
	for input, want := range tests {
		if got := expandMDEPath(input); got != want {
			t.Errorf("expandMDEPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizePathPatternCollapsesDoubleBackslashes(t *testing.T) {
	if got, want := normalizePathPattern(`C:\\Users\\*\\.ssh\\*`), `C:\Users\.ssh\`; got != want {
		t.Fatalf("normalizePathPattern() = %q, want %q", got, want)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func writeMDEFixture(t *testing.T, dir string) string {
	t.Helper()
	config := filepath.Join(dir, "mde-config.json")
	data := `{
  "configTypes": [{
    "configType": "host",
    "ExclusionConfiguration": {
      "EnableExclusions": true,
      "Paths": [
        {"Value": "C:\\\\Temp", "Process": "%ProgramFiles%\\App\\app.exe"},
        {"Value": "\\\\", "Process": "%ProgramFiles(x86)%\\Office\\winword.exe"}
      ]
    },
    "FileMonitorConfiguration": {
      "FileMonitorEntries": [{"FilePath": "%SystemDrive%\\Users\\*\\.ssh\\*", "FileMonitorType": [1]}],
      "ExpandedCollectionExcludedFileMonitorEntries": [{"FilePath": "%SystemDrive%\\Windows\\*", "FileMonitorType": [1]}]
    },
    "RegistryMonitoringConfiguration": {
      "registryEntries": [{"registryKey": "hkcu\\software\\classes\\ms-settings\\shell\\open\\command\\", "registryValue": "delegateexecute"}]
    },
    "Provider": {
      "Rules": [{
        "name": "Create process using G-ETW",
        "taskName": "GenericEtwCreateProcess",
        "filters": {
          "expressionType": "Operator",
          "operator": "And",
          "expressions": [
            {"expressionType": "Predicate", "source": "ProcessEntity:PROCESS_NAME", "values": ["cmd.exe"], "filter": "EQ"},
            {"expressionType": "Predicate", "source": "ProcessEntity:PROCESS_CMD_LINE", "values": ["/c"], "filter": "Contains"},
            {"expressionType": "Operator", "operator": "Not", "expressions": [
              {"expressionType": "Predicate", "source": "InitiatingProcess:PROCESS_NAME", "values": ["MsSense.exe"], "filter": "EQ"}
            ]}
          ]
        }
      }]
    }
  }]
}`
	if err := os.WriteFile(config, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return config
}

func assertFileContains(t *testing.T, path string, needles ...string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range needles {
		if !strings.Contains(string(content), needle) {
			t.Fatalf("expected %s to contain %q, got:\n%s", path, needle, content)
		}
	}
}

func assertFileNotContains(t *testing.T, path string, needles ...string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range needles {
		if strings.Contains(string(content), needle) {
			t.Fatalf("expected %s not to contain %q, got:\n%s", path, needle, content)
		}
	}
}
