package analyze

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/tooling/internal/validate"
)

func TestConfigFindsConflictAndNativePathRecommendation(t *testing.T) {
	xml := `<Sysmon schemaversion="4.90"><HashAlgorithms>MD5</HashAlgorithms><EventFiltering>
	<RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate></RuleGroup>
	<RuleGroup groupRelation="or"><ProcessCreate onmatch="exclude"><Image condition="image">cmd.exe</Image></ProcessCreate></RuleGroup>
	</EventFiltering></Sysmon>`
	doc, err := sysmonxml.Parse([]byte(xml), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	var text []string
	for _, finding := range findings {
		text = append(text, finding.Message)
	}
	joined := strings.Join(text, "\n")
	if !strings.Contains(joined, "same condition appears") {
		t.Fatalf("expected conflict finding, got %#v", findings)
	}
	if !strings.Contains(joined, "exclude rule matches a known binary by image name only") || !strings.Contains(findingDetails(findings), "for exclusions, prefer full paths") {
		t.Fatalf("expected exclude-focused path recommendation, got %#v", findings)
	}
	if strings.Contains(joined, "known binary is matched by image name only") {
		t.Fatalf("include rules must not receive path-narrowing recommendations: %#v", findings)
	}
}

func TestConfigDoesNotNarrowImageLoadedIncludeToKnownPath(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup groupRelation="or"><ImageLoad onmatch="include"><ImageLoaded condition="end with">scrobj.dll</ImageLoaded></ImageLoad></RuleGroup>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	if strings.Contains(findingDetails(findings), `C:\Windows\System32\scrobj.dll`) {
		t.Fatalf("include rule should retain location-independent detection intent, got %#v", findings)
	}
}

func TestConfigDoesNotEmitSpeculativePerformanceFindings(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><HashAlgorithms>*</HashAlgorithms><EventFiltering>
	<RuleGroup groupRelation="or"><ImageLoad onmatch="include"><ImageLoaded condition="contains">a</ImageLoaded><ImageLoaded condition="contains">b</ImageLoaded></ImageLoad></RuleGroup>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range Config(doc, "test") {
		if finding.Code == "ANL007" || finding.Code == "ANL008" || finding.Code == "ANL009" {
			t.Fatalf("heuristic performance finding %s must remain disabled until it has evidence-backed thresholds: %#v", finding.Code, finding)
		}
	}
}

func TestConfigRecommendsMultiValueExcludeImageFullPaths(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup groupRelation="or"><ImageLoad onmatch="exclude"><Image condition="is any">powershell.exe;powershell_ise.exe</Image></ImageLoad></RuleGroup>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	details := findingDetails(findings)
	if !strings.Contains(details, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`) || !strings.Contains(details, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe`) {
		t.Fatalf("expected multi-value path recommendations, got %#v", findings)
	}
}

func TestConfigDoesNotTreatEmptyIncludeAsFullStream(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><HashAlgorithms>*</HashAlgorithms><EventFiltering><RuleGroup><ImageLoad onmatch="include"/></RuleGroup></EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	for _, finding := range findings {
		if strings.Contains(finding.Message, "logs the full event stream") {
			t.Fatalf("empty include disables collection and must not be reported as full-stream logging: %#v", findings)
		}
	}
	if len(findings) != 0 {
		t.Fatalf("empty include should not produce an analyzer finding, got %#v", findings)
	}
}

func TestConfigDoesNotFlattenNestedExcludeIntoConflict(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup groupRelation="or"><FileCreate onmatch="include"><TargetFilename condition="contains">Roaming\Microsoft\Outlook\Outlook.xml</TargetFilename></FileCreate></RuleGroup>
	<RuleGroup groupRelation="or"><FileCreate onmatch="exclude"><Rule groupRelation="and"><Image condition="image">Outlook.exe</Image><TargetFilename condition="contains">Roaming\Microsoft\Outlook\Outlook.xml</TargetFilename></Rule></FileCreate></RuleGroup>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	for _, finding := range findings {
		if finding.Code == "ANL005" {
			t.Fatalf("a condition inside an AND exclusion is not equivalent to the include rule: %#v", findings)
		}
	}
}

func findingDetails(findings []validate.Finding) string {
	var text []string
	for _, finding := range findings {
		text = append(text, finding.Detail)
	}
	return strings.Join(text, "\n")
}
