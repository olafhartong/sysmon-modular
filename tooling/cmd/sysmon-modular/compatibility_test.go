package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeTargetVersionExcludesUnsupportedItems(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.xml")
	output := filepath.Join(dir, "output.xml")
	xml := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><ProcessCreate onmatch="include"><Image condition="is">cmd.exe</Image><ParentUser condition="is">alice</ParentUser></ProcessCreate><FileExecutableDetected onmatch="include"><Image condition="is">drop.exe</Image></FileExecutableDetected></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(input, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runMerge([]string{"--path", input, "--output", output, "--sysmon-version", "12", "--unsupported", "exclude"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, `schemaversion="4.40"`) || !strings.Contains(got, "cmd.exe") {
		t.Fatalf("target schema or supported condition missing:\n%s", got)
	}
	if strings.Contains(got, "ParentUser") || strings.Contains(got, "FileExecutableDetected") {
		t.Fatalf("unsupported items survived merge exclusion:\n%s", got)
	}
}

func TestMergeTargetVersionWarnsAndRetainsByDefault(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.xml")
	output := filepath.Join(dir, "output.xml")
	xml := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><FileExecutableDetected onmatch="include"><Image condition="is">drop.exe</Image></FileExecutableDetected></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(input, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runMerge([]string{"--path", input, "--output", output, "--sysmon-version", "12", "--schema-validate=false"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, `schemaversion="4.40"`) || !strings.Contains(got, "FileExecutableDetected") {
		t.Fatalf("default warning policy should retain unsupported event with target schema:\n%s", got)
	}
}

func TestMergeDefaultsToSysmon15Schema(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.xml")
	output := filepath.Join(dir, "output.xml")
	xml := `<Sysmon schemaversion="4.30"><EventFiltering><RuleGroup><ProcessCreate onmatch="include"><Image condition="is">cmd.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(input, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runMerge([]string{"--path", input, "--output", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, `schemaversion="4.90"`) {
		t.Fatalf("default merge should target Sysmon 15 schema 4.90:\n%s", got)
	}
}

func TestMergeDiscoversModulesFromRelativeBasePath(t *testing.T) {
	dir := t.TempDir()
	ruleDir := filepath.Join(dir, "1_process_creation")
	if err := os.MkdirAll(ruleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(ruleDir, "include_test.xml")
	output := filepath.Join(dir, "output.xml")
	xml := `<Sysmon schemaversion="4.30"><EventFiltering><RuleGroup><ProcessCreate onmatch="include"><Image condition="is">cmd.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(input, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeBase, err := filepath.Rel(workingDirectory, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := runMerge([]string{"--base-path", relativeBase, "--output", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "cmd.exe") {
		t.Fatalf("relative base-path discovery omitted input:\n%s", data)
	}
}

func TestValidateWarningsAsErrors(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "warning.xml")
	xml := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><ProcessCreate onmatch="include"><Image condition="is"></Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(input, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runValidate([]string{"--path", input, "--mitre=false"}); err != nil {
		t.Fatalf("warning should be non-blocking by default: %v", err)
	}
	if err := runValidate([]string{"--path", input, "--mitre=false", "--warnings-as-errors"}); err == nil {
		t.Fatal("warning should fail validation with --warnings-as-errors")
	}
}
