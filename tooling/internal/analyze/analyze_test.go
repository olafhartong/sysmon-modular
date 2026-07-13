package analyze

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/internal/validate"
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
	if !strings.Contains(joined, "known binary is matched by image name only") || !strings.Contains(findingDetails(findings), `C:\Windows\System32\cmd.exe`) {
		t.Fatalf("expected known path recommendation, got %#v", findings)
	}
	if !strings.Contains(joined, "exclude rule matches a known binary by image name only") || !strings.Contains(findingDetails(findings), "for exclusions, prefer full paths") {
		t.Fatalf("expected exclude-focused path recommendation, got %#v", findings)
	}
}

func TestConfigRecommendsImageLoadedFullPath(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup groupRelation="or"><ImageLoad onmatch="include"><ImageLoaded condition="end with">scrobj.dll</ImageLoaded></ImageLoad></RuleGroup>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	if !strings.Contains(findingDetails(findings), `C:\Windows\System32\scrobj.dll`) {
		t.Fatalf("expected ImageLoaded path recommendation, got %#v", findings)
	}
}

func TestConfigRecommendsMultiValueImageFullPaths(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup groupRelation="or"><ImageLoad onmatch="include"><Image condition="excludes any">powershell.exe;powershell_ise.exe</Image></ImageLoad></RuleGroup>
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

func TestConfigFlagsEmptyInclude(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup><ImageLoad onmatch="include"/></RuleGroup></EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	findings := Config(doc, "test")
	for _, finding := range findings {
		if strings.Contains(finding.Message, "logs the full event stream") {
			return
		}
	}
	t.Fatalf("expected performance finding, got %#v", findings)
}

func findingDetails(findings []validate.Finding) string {
	var text []string
	for _, finding := range findings {
		text = append(text, finding.Detail)
	}
	return strings.Join(text, "\n")
}
