package main

import (
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
