package validate

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/internal/sysmonxml"
)

func TestSchemaFlagsUnknownEventAndInvalidOnmatch(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="maybe"><Nope onmatch="bad"/></RuleGroup></EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Schema(doc, "test")
	var messages []string
	for _, finding := range findings {
		messages = append(messages, finding.Message)
	}
	joined := strings.Join(messages, "\n")
	if !strings.Contains(joined, "invalid groupRelation") || !strings.Contains(joined, "unknown Sysmon event") {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestSyntaxFileReturnsError(t *testing.T) {
	findings := SyntaxFile("does-not-exist.xml", false)
	if len(findings) != 1 || findings[0].Severity != Error {
		t.Fatalf("expected syntax error finding, got %#v", findings)
	}
}

func TestMITREReturnsFinding(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon><EventFiltering><RuleGroup><ProcessCreate><Image name="technique_id=T1105,technique_name=Remote File Copy"/></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := MITRE(doc, "test.xml")
	if len(findings) != 1 {
		t.Fatalf("expected one MITRE finding, got %#v", findings)
	}
	if findings[0].Severity != Error || !strings.Contains(findings[0].Message, "MITRE") {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
