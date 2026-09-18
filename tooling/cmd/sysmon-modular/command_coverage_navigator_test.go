package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageNavigatorFromModules(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(moduleDir, "include_powershell.xml")
	writeCoverageNavigatorFile(t, module, `<Sysmon schemaversion="4.90"><EventFiltering>
		<ProcessCreate onmatch="include">
			<Image name="technique_id=T1059.001,technique_name=PowerShell" condition="end with">powershell.exe</Image>
			<CommandLine name="technique_id=T1059.001,technique_name=PowerShell" condition="contains">-enc</CommandLine>
		</ProcessCreate>
	</EventFiltering></Sysmon>`)
	output := filepath.Join(base, "navigator.json")
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeBase, err := filepath.Rel(workingDirectory, base)
	if err != nil {
		t.Fatal(err)
	}

	if err := runCoverage([]string{
		"--all", "--base-path", relativeBase,
		"--format", "navigator", "--output", output,
	}); err != nil {
		t.Fatal(err)
	}
	layer := readCoverageNavigatorLayer(t, output)
	if layer["versions"].(map[string]any)["attack"] != "18" {
		t.Fatalf("default ATT&CK version = %#v, want 18", layer["versions"])
	}
	techniques := layer["techniques"].([]any)
	if len(techniques) != 1 {
		t.Fatalf("got %d techniques, want 1", len(techniques))
	}
	technique := techniques[0].(map[string]any)
	if technique["techniqueID"] != "T1059.001" || technique["score"] != float64(2) {
		t.Fatalf("unexpected technique: %#v", technique)
	}
	if technique["comment"] != "1_process_creation/include_powershell.xml" {
		t.Fatalf("unexpected module comment: %#v", technique["comment"])
	}
}

func TestCoverageNavigatorFromCompleteConfigWithTemplate(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "custom.xml")
	writeCoverageNavigatorFile(t, config, `<Sysmon schemaversion="4.90"><EventFiltering>
		<RegistryEvent onmatch="include">
			<TargetObject name="technique_id=T1547.001,technique_name=Registry Run Keys / Startup Folder" condition="contains">CurrentVersion\\Run</TargetObject>
		</RegistryEvent>
	</EventFiltering></Sysmon>`)
	template := filepath.Join(dir, "template.json")
	writeCoverageNavigatorFile(t, template, `{"gradient":{"maxValue":100},"layout":{"showID":true}}`)
	output := filepath.Join(dir, "navigator.json")

	if err := runCoverage([]string{
		"--path", config,
		"--format", "navigator",
		"--name", "Custom coverage",
		"--description", "Coverage for the custom configuration.",
		"--template", template,
		"--output", output,
	}); err != nil {
		t.Fatal(err)
	}
	layer := readCoverageNavigatorLayer(t, output)
	if layer["name"] != "Custom coverage" || layer["description"] != "Coverage for the custom configuration." {
		t.Fatalf("unexpected layer identity: %#v", layer)
	}
	if layer["layout"].(map[string]any)["showID"] != true {
		t.Fatalf("template setting was not retained: %#v", layer["layout"])
	}
	technique := layer["techniques"].([]any)[0].(map[string]any)
	if technique["comment"] != "custom.xml" {
		t.Fatalf("complete config label = %#v, want custom.xml", technique["comment"])
	}
}

func TestCoverageAppliesIncludeAndExcludeLists(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(moduleDir, "keep.xml")
	drop := filepath.Join(moduleDir, "drop.xml")
	writeCoverageNavigatorFile(t, keep, `<Sysmon schemaversion="4.90"><EventFiltering><ProcessCreate onmatch="include"><Image name="technique_id=T1059.001,technique_name=PowerShell" condition="end with">powershell.exe</Image></ProcessCreate></EventFiltering></Sysmon>`)
	writeCoverageNavigatorFile(t, drop, `<Sysmon schemaversion="4.90"><EventFiltering><ProcessCreate onmatch="include"><Image name="technique_id=T1547.001,technique_name=Registry Run Keys / Startup Folder" condition="end with">reg.exe</Image></ProcessCreate></EventFiltering></Sysmon>`)
	includeList := filepath.Join(base, "include.txt")
	excludeList := filepath.Join(base, "exclude.txt")
	writeCoverageNavigatorFile(t, includeList, "1_process_creation\n")
	writeCoverageNavigatorFile(t, excludeList, "1_process_creation/drop.xml\n")
	output := filepath.Join(base, "navigator.json")

	if err := runCoverage([]string{
		"--base-path", base,
		"--include-list", includeList,
		"--exclude-list", excludeList,
		"--format", "navigator",
		"--output", output,
	}); err != nil {
		t.Fatal(err)
	}
	techniques := readCoverageNavigatorLayer(t, output)["techniques"].([]any)
	if len(techniques) != 1 || techniques[0].(map[string]any)["techniqueID"] != "T1059.001" {
		t.Fatalf("unexpected selected techniques: %#v", techniques)
	}
}

func TestCoverageRejectsNavigatorFlagsForOtherFormats(t *testing.T) {
	err := runCoverage([]string{"--path", "config.xml", "--name", "Layer"})
	if err == nil {
		t.Fatal("expected Navigator flag usage error")
	}
	ce, ok := err.(*commandError)
	if !ok || ce.code != exitUsage {
		t.Fatalf("got %#v, want usage error", err)
	}
}

func TestCoverageNavigatorAcceptsATTACK19AndRejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "custom.xml")
	writeCoverageNavigatorFile(t, config, `<Sysmon schemaversion="4.90"><EventFiltering><ProcessCreate onmatch="include"><Image name="technique_id=T1685,technique_name=Disable or Modify Tools" condition="end with">tool.exe</Image></ProcessCreate></EventFiltering></Sysmon>`)
	output := filepath.Join(dir, "navigator.json")
	if err := runCoverage([]string{
		"--path", config, "--format", "navigator", "--attack-version", "19", "--output", output,
	}); err != nil {
		t.Fatal(err)
	}
	layer := readCoverageNavigatorLayer(t, output)
	if layer["versions"].(map[string]any)["attack"] != "19" {
		t.Fatalf("ATT&CK version = %#v, want 19", layer["versions"])
	}
	technique := layer["techniques"].([]any)[0].(map[string]any)
	if technique["techniqueID"] != "T1685" {
		t.Fatalf("ATT&CK 19 technique was remapped: %#v", technique)
	}

	err := runCoverage([]string{"--path", config, "--format", "navigator", "--attack-version", "20"})
	if err == nil {
		t.Fatal("expected unsupported ATT&CK version error")
	}
	ce, ok := err.(*commandError)
	if !ok || ce.code != exitUsage {
		t.Fatalf("got %#v, want usage error", err)
	}
}

func writeCoverageNavigatorFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readCoverageNavigatorLayer(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var layer map[string]any
	if err := json.Unmarshal(data, &layer); err != nil {
		t.Fatalf("decode Navigator layer: %v", err)
	}
	return layer
}
