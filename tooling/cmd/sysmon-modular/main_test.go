package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/generate"
)

func TestRunGenerateMDEAcceptsPositionalConfig(t *testing.T) {
	config := filepath.Join(t.TempDir(), "custom-sense-config.json")
	err := runGenerateMDE([]string{config}, generate.MDEModeInverse)
	if err == nil {
		t.Fatal("expected missing config error")
	}
	if !strings.Contains(err.Error(), config) {
		t.Fatalf("error does not reference positional config %q: %v", config, err)
	}
}

func TestRunMergeWarningsAsErrorsIncludesListWarnings(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.xml", "b.xml"} {
		data := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">` + name + `</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	include := filepath.Join(dir, "include.txt")
	exclude := filepath.Join(dir, "exclude.txt")
	if err := os.WriteFile(include, []byte("a.xml\nb.xml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exclude, []byte("a.xml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runMerge([]string{
		"--base-path", dir, "--include-list", include, "--exclude-list", exclude,
		"--validate=false", "--schema-validate=false", "--sysmon-version=",
		"--warnings-as-errors", "--output", filepath.Join(dir, "merged.xml"),
	})
	if err == nil || !strings.Contains(err.Error(), "findings were emitted") {
		t.Fatalf("expected list warning to fail warnings-as-errors, got %v", err)
	}
}

func TestRunGenerateMDERejectsAmbiguousConfig(t *testing.T) {
	err := runGenerateMDE([]string{"--mde-config", "flag.json", "positional.json"}, generate.MDEModeInverse)
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected ambiguous config usage error, got %v", err)
	}
}

func TestRunGenerateMDERejectsExtraArguments(t *testing.T) {
	err := runGenerateMDE([]string{"one.json", "two.json"}, generate.MDEModeInverse)
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("expected extra argument usage error, got %v", err)
	}
}

func TestRunGenerateMDERejectsUnknownAreaBeforeReadingConfig(t *testing.T) {
	err := runGenerateMDE([]string{"--area", "not-an-area", "missing.json"}, generate.MDEModeFiltered)
	if err == nil || !strings.Contains(err.Error(), "unknown MDE area") {
		t.Fatalf("expected unknown area error, got %v", err)
	}
}

func TestRunGenerateKQLRequiresOneInputMode(t *testing.T) {
	for _, args := range [][]string{nil, {"--kql", "rule.kql", "--directory", "rules"}} {
		err := runGenerateKQL(args)
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("expected input mode usage error for %v, got %v", args, err)
		}
	}
}
