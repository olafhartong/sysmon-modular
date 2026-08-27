package expression

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestFromXMLPreservesNestedBooleanStructure(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or"><ProcessCreate onmatch="include">
	<Rule name="encoded" groupRelation="and"><Image condition="image">powershell.exe</Image><CommandLine condition="contains">-enc</CommandLine></Rule>
	<Image condition="image">pwsh.exe</Image>
	</ProcessCreate></RuleGroup></EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	config := FromXML(doc)
	if len(config.Events) != 1 || len(config.Techniques) != 1 || config.Techniques[0] != "T1059.001" {
		t.Fatalf("unexpected extracted config: %#v", config)
	}
	if len(config.Events[0].Techniques) != 1 || config.Events[0].Techniques[0] != "T1059.001" {
		t.Fatalf("RuleGroup technique was not associated with its event: %#v", config.Events[0])
	}
	canonical := config.Events[0].Expression.Canonical()
	if !strings.HasPrefix(canonical, "or(") || !strings.Contains(canonical, "and(") {
		t.Fatalf("nested relations were lost: %s", canonical)
	}
	if len(config.Events[0].Expression.Conditions()) != 3 {
		t.Fatalf("expected three leaf conditions: %#v", config.Events[0].Expression)
	}
}

func TestFromXMLAcceptsDirectEventFilteringLayout(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<ProcessCreate onmatch="exclude"><Image condition="image">cmd.exe</Image><Image condition="image">conhost.exe</Image></ProcessCreate>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	config := FromXML(doc)
	if len(config.Events) != 1 || config.Events[0].Onmatch != "exclude" || !strings.HasPrefix(config.Events[0].Expression.Canonical(), "or(") {
		t.Fatalf("direct event layout was not represented correctly: %#v", config)
	}
}

func TestCanonicalIgnoresCommutativeConditionOrder(t *testing.T) {
	a := Combine(AndNode, Leaf(Condition{Field: "Image", Operator: "is", Value: "cmd.exe"}), Leaf(Condition{Field: "CommandLine", Operator: "contains", Value: "/c"}))
	b := Combine(AndNode, Leaf(Condition{Field: "CommandLine", Operator: "contains", Value: "/c"}), Leaf(Condition{Field: "Image", Operator: "is", Value: "CMD.EXE"}))
	if a.Canonical() != b.Canonical() {
		t.Fatalf("equivalent expressions have different keys:\n%s\n%s", a.Canonical(), b.Canonical())
	}
}

func TestDNFExpandsOrInsideAnd(t *testing.T) {
	node := Combine(AndNode,
		Combine(OrNode, Leaf(Condition{Field: "Image", Operator: "image", Value: "cmd.exe"}), Leaf(Condition{Field: "Image", Operator: "image", Value: "powershell.exe"})),
		Leaf(Condition{Field: "CommandLine", Operator: "contains", Value: "/c"}),
	)
	branches, tooLarge := node.DNF(256)
	if tooLarge || len(branches) != 2 || len(branches[0]) != 2 || len(branches[1]) != 2 {
		t.Fatalf("unexpected DNF expansion: branches=%#v tooLarge=%v", branches, tooLarge)
	}
	if _, tooLarge := node.DNF(1); !tooLarge {
		t.Fatal("expected the configured DNF limit to be enforced")
	}
}
