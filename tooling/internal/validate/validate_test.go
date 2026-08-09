package validate

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
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

func TestSchemaRejectsSemicolonForSingleValueCondition(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><ProcessCreate><Image condition="contains">one;two</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Schema(doc, "test.xml")
	for _, finding := range findings {
		if finding.Code == "SYS107" && finding.Severity == Error && finding.Line == 1 {
			return
		}
	}
	t.Fatalf("expected SYS107 error, got %#v", findings)
}

func TestSchemaAllowsSemicolonForMultiValueConditions(t *testing.T) {
	conditions := []string{"is any", "contains any", "contains all", "excludes any", "excludes all"}
	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			xmlConfig := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><ProcessCreate><Image condition="` + condition + `">one;two</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
			doc, err := sysmonxml.Parse([]byte(xmlConfig), false)
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range Schema(doc, "test.xml") {
				if finding.Code == "SYS107" {
					t.Fatalf("unexpected SYS107 finding: %#v", finding)
				}
			}
		})
	}
}
