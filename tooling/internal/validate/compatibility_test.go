package validate

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestResolveBinarySchema(t *testing.T) {
	tests := map[string]string{
		"12": "4.40", "v13": "4.50", "13.1": "4.60", "13.15": "4.60",
		"14.0": "4.82", "14.1": "4.83", "14.16": "4.83", "15.2": "4.90",
		"15.19": "4.90", "15.20": "4.91", "15.21": "4.91",
	}
	for version, want := range tests {
		got, err := ResolveBinarySchema(version)
		if err != nil {
			t.Fatalf("ResolveBinarySchema(%q): %v", version, err)
		}
		if got.SchemaVersion != want {
			t.Errorf("ResolveBinarySchema(%q) schema = %s, want %s", version, got.SchemaVersion, want)
		}
	}
	for _, version := range []string{"", "11", "16", "not-a-version"} {
		if _, err := ResolveBinarySchema(version); err == nil {
			t.Errorf("ResolveBinarySchema(%q) unexpectedly succeeded", version)
		}
	}
}

func TestBinaryCompatibilityFindsVersionedEventsAndFields(t *testing.T) {
	doc := mustParseCompatibility(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup>
<ProcessCreate onmatch="include"><Image condition="is">cmd.exe</Image><ParentUser condition="is">alice</ParentUser></ProcessCreate>
<ProcessTampering onmatch="include"><Image condition="is">cmd.exe</Image></ProcessTampering>
</RuleGroup></EventFiltering></Sysmon>`)
	findings, err := BinaryCompatibility(doc, "test.xml", "12")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected event and field findings, got %#v", findings)
	}
	details := findings[0].Detail + "\n" + findings[1].Detail
	if !strings.Contains(details, "ProcessCreate.ParentUser") || !strings.Contains(details, "ProcessTampering") {
		t.Fatalf("unexpected compatibility details: %s", details)
	}
}

func TestExcludeBinaryUnsupportedAvoidsEmptyMatchAllEvent(t *testing.T) {
	doc := mustParseCompatibility(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup>
<ProcessCreate onmatch="include"><ParentUser condition="is">alice</ParentUser></ProcessCreate>
<NetworkConnect onmatch="include"><DestinationPort condition="is">443</DestinationPort></NetworkConnect>
<FileExecutableDetected onmatch="include"><Image condition="is">drop.exe</Image></FileExecutableDetected>
</RuleGroup></EventFiltering></Sysmon>`)
	findings, err := ExcludeBinaryUnsupported(doc, "merged", "12")
	if err != nil {
		t.Fatal(err)
	}
	out := doc.String()
	if !strings.Contains(out, `schemaversion="4.40"`) || !strings.Contains(out, "<NetworkConnect") {
		t.Fatalf("expected target schema and supported event, got:\n%s", out)
	}
	if strings.Contains(out, "<ProcessCreate") || strings.Contains(out, "FileExecutableDetected") || strings.Contains(out, "ParentUser") {
		t.Fatalf("unsupported or unsafe empty event survived exclusion:\n%s", out)
	}
	if len(findings) != 3 {
		t.Fatalf("expected field, empty-event, and unsupported-event findings, got %#v", findings)
	}
}

func TestCurrentSchemaAcceptsWmiUser(t *testing.T) {
	doc := mustParseCompatibility(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><WmiEvent onmatch="include"><User condition="is">alice</User></WmiEvent></RuleGroup></EventFiltering></Sysmon>`)
	for _, finding := range Schema(doc, "test.xml") {
		if finding.Code == "SYS202" {
			t.Fatalf("WmiEvent.User should be valid: %#v", finding)
		}
	}
}

func TestFileBlockShreddingStartsAtSysmon141(t *testing.T) {
	doc := mustParseCompatibility(t, `<Sysmon schemaversion="4.83"><EventFiltering><RuleGroup><FileBlockShredding onmatch="include"><Image condition="is">sdelete.exe</Image></FileBlockShredding></RuleGroup></EventFiltering></Sysmon>`)
	findings, err := BinaryCompatibility(doc, "test.xml", "14")
	if err != nil || len(findings) != 1 || findings[0].Code != "SYS204" {
		t.Fatalf("Sysmon 14.0 should reject FileBlockShredding: findings=%#v err=%v", findings, err)
	}
	findings, err = BinaryCompatibility(doc, "test.xml", "14.1")
	if err != nil || len(findings) != 0 {
		t.Fatalf("Sysmon 14.1 should support FileBlockShredding: findings=%#v err=%v", findings, err)
	}
}

func mustParseCompatibility(t *testing.T, input string) *sysmonxml.Document {
	t.Helper()
	doc, err := sysmonxml.Parse([]byte(input), false)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
