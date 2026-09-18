package main

import (
	"strings"
	"testing"
)

func TestGenerateProducesSortedTacticsAndReplacement(t *testing.T) {
	input := `{"objects":[
		{"type":"attack-pattern","id":"attack-pattern--new","name":"New","modified":"2026-01-02T00:00:00.000Z","external_references":[{"source_name":"mitre-attack","external_id":"T1001"}],"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"execution"},{"kill_chain_name":"mitre-attack","phase_name":"defense-evasion"}]},
		{"type":"attack-pattern","id":"attack-pattern--old","name":"Old","modified":"2026-01-01T00:00:00.000Z","revoked":true,"external_references":[{"source_name":"mitre-attack","external_id":"T1000"}]},
		{"type":"relationship","relationship_type":"revoked-by","source_ref":"attack-pattern--old","target_ref":"attack-pattern--new"}
	]}`
	generated, err := generate([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	text := string(generated)
	oldIndex, newIndex := strings.Index(text, `"T1000"`), strings.Index(text, `"T1001"`)
	if oldIndex < 0 || newIndex < 0 || oldIndex >= newIndex {
		t.Fatalf("techniques are not sorted:\n%s", text)
	}
	for _, expected := range []string{
		`Tactics: []string{"defense-evasion", "execution"}`,
		`Revoked: true`,
		`Replacement: "T1001"`,
		`Bundle latest attack-pattern modified timestamp: 2026-01-02T00:00:00.000Z`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated output is missing %q:\n%s", expected, text)
		}
	}
}

func TestGenerateRejectsBundleWithoutTechniques(t *testing.T) {
	if _, err := generate([]byte(`{"objects":[]}`)); err == nil {
		t.Fatal("expected an empty bundle to fail")
	}
}
