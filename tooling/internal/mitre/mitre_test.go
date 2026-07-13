package mitre

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestCheckDocumentFindsMITREIssues(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon>
  <EventFiltering>
    <RuleGroup>
      <ProcessCreate onmatch="include">
        <Image name="technique=T1105,technique_name=Remote File Copy" condition="is">ftp.exe</Image>
        <Image name="technique_id=T1574.002,technique_name=DLL Side-Loading" condition="is">odbcconf.exe</Image>
        <Image name="technique_id=T,technique_name=" condition="is">makecab.exe</Image>
        <Image name="technique_name=Outlook Server 95/98 Identity Keys" condition="contains">Identities</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	issues := CheckDocument(doc, "test.xml")
	kinds := map[IssueKind]int{}
	for _, issue := range issues {
		kinds[issue.Kind]++
	}
	if kinds[IssueAttributeKey] != 1 {
		t.Fatalf("expected one attribute-key issue, got %#v", issues)
	}
	if kinds[IssueRetiredID] != 1 {
		t.Fatalf("expected one retired-id issue, got %#v", issues)
	}
	if kinds[IssueMalformed] != 2 {
		t.Fatalf("expected two malformed issues, got %#v", issues)
	}
}

func TestFixValueUpdatesKeyIDAndName(t *testing.T) {
	got, changed := FixValue("technique=T1574.002,technique_name=DLL Side-Loading")
	if !changed {
		t.Fatal("expected change")
	}
	want := "technique_id=T1574.001,technique_name=DLL"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFixFilePreservesCommentsAndWritesActiveAttributes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module.xml")
	input := `<Sysmon>
  <!-- <Image name="technique_id=T,technique_name=" condition="is">commented.exe</Image> -->
  <EventFiltering>
    <RuleGroup>
      <ProcessCreate onmatch="include">
        <Image name="technique=T1105,technique_name=Remote File Copy" condition="is">ftp.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>`
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := FixFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changes != 1 || !result.Changed {
		t.Fatalf("unexpected result: %#v", result)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `name="technique_id=T1105,technique_name=Ingress Tool Transfer"`) {
		t.Fatalf("active attribute was not fixed:\n%s", text)
	}
	if !strings.Contains(text, `<!-- <Image name="technique_id=T,technique_name="`) {
		t.Fatalf("commented placeholder should be preserved:\n%s", text)
	}
}

func TestFixFileReportsUnfixedMalformedMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module.xml")
	input := `<Sysmon><EventFiltering><RuleGroup><ProcessCreate><Image name="technique_id=T,technique_name=" condition="is">makecab.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := FixFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changes != 0 || len(result.Unfixed) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Unfixed[0].Kind != IssueMalformed {
		t.Fatalf("expected malformed issue, got %#v", result.Unfixed[0])
	}
}

func TestReviewFileCanApproveIndividualChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review.xml")
	input := `<Sysmon><EventFiltering><RuleGroup><ProcessCreate>` +
		`<Image name="technique_id=T1003,technique_name=Credential Dumping">one.exe</Image>` +
		`<Image name="technique_id=T1105,technique_name=Remote File Copy">two.exe</Image>` +
		`</ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	seen := 0
	result, err := ReviewFile(path, true, func(change Change) bool {
		seen++
		return seen == 2
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Proposed != 2 || result.Changes != 1 || result.Skipped != 1 {
		t.Fatalf("unexpected review result: %#v", result)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "technique_name=Credential Dumping") {
		t.Fatalf("declined change was applied: %s", got)
	}
	if !strings.Contains(got, "technique_name=Ingress Tool Transfer") {
		t.Fatalf("approved change was not applied: %s", got)
	}
}
