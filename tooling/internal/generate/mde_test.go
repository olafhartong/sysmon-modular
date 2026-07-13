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

func writeMDEFixture(t *testing.T, dir string) string {
	t.Helper()
	config := filepath.Join(dir, "mde-config.json")
	data := `{
  "configTypes": [{
    "configType": "host",
    "ExclusionConfiguration": {
      "EnableExclusions": true,
      "Paths": [
        {"Value": "C:\\Temp", "Process": "%ProgramFiles%\\App\\app.exe"},
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
