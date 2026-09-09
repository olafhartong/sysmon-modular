package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticLocations(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	mustMkdirAll(t, moduleDir)
	module := filepath.Join(moduleDir, "warning.xml")
	writeCLIFile(t, module, `<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="typo">a.exe</Image>
      <Image condition="typo">b.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>`)
	clean := filepath.Join(base, "clean.xml")
	writeCLIFile(t, clean, cliConfig("cmd.exe", ""))

	for _, command := range []string{"analyze", "validate", "verify"} {
		selections := []struct {
			name       string
			args       []string
			showPath   bool
			showSource bool
		}{
			{name: "single file", args: []string{"--path", module}},
			{name: "duplicate file", args: []string{"--path", module, "--path", module}},
			{name: "multiple files", args: []string{"--path", module, "--path", clean}, showPath: true},
			{name: "directory with one module", args: []string{"--all", "--base-path", base}, showPath: true},
			{name: "XML directory", args: []string{"--all-xml", "--base-path", base}, showPath: true},
			{name: "verbose", args: []string{"--path", module, "--verbose"}, showSource: true},
		}
		if command == "analyze" {
			selections = selections[:3]
			selections[0].args = []string{"--config", module}
			selections[0].showSource = true
			selections[1].name = "verbose"
			selections[1].args = []string{"--config", module, "--verbose"}
			selections[1].showSource = true
			selections[2].name = "source disabled"
			selections[2].args = []string{"--config", module, "--verbose=false"}
			selections[2].showPath = false
		}
		for _, selection := range selections {
			t.Run(command+"/"+selection.name, func(t *testing.T) {
				var code int
				stdout, stderr := captureCommandOutput(t, func() {
					code = run(append([]string{command}, selection.args...))
				})
				if code != exitOK || stdout != "" {
					t.Fatalf("unexpected result: code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
				for _, line := range []string{"5", "6"} {
					location := "line " + line
					if selection.showPath {
						location = module + ":" + line
					}
					if !strings.Contains(stderr, "[SYS106] "+location+": unknown condition operator") {
						t.Errorf("missing location %q:\n%s", location, stderr)
					}
				}
				if strings.Count(stderr, "[SYS106]") != 2 || strings.Contains(stderr, "×2") {
					t.Errorf("findings on different lines were collapsed:\n%s", stderr)
				}
				if !selection.showPath && strings.Contains(stderr, module) {
					t.Errorf("single-file findings should use line numbers without filenames:\n%s", stderr)
				}
				for _, source := range []string{
					`5 │ <Image condition="typo">a.exe</Image>`,
					`6 │ <Image condition="typo">b.exe</Image>`,
				} {
					if strings.Contains(stderr, source) != selection.showSource {
						t.Errorf("source display for %q should be %t:\n%s", source, selection.showSource, stderr)
					}
				}
			})
		}
	}
}

func TestDiagnosticErrorsIncludeLocations(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, test := range []struct {
		name    string
		xml     string
		finding string
		source  string
	}{
		{
			name:    "schema",
			xml:     "<Sysmon schemaversion=\"4.90\">\n  <HashAlgorithms>*</HashAlgorithms>\n  <EventFiltering><UnknownEvent/></EventFiltering>\n</Sysmon>",
			finding: "[SYS102] line 3:",
			source:  "3 │ <EventFiltering><UnknownEvent/></EventFiltering>",
		},
		{
			name:    "XML syntax",
			xml:     "<Sysmon>\n  <EventFiltering>\n  </Wrong>\n</Sysmon>",
			finding: "[XML001] line 3:",
			source:  "3 │ </Wrong>",
		},
		{
			name:    "multiple roots",
			xml:     "<Sysmon/>\n<Other/>",
			finding: "[XML001] line 2:",
			source:  "2 │ <Other/>",
		},
	} {
		for _, command := range []string{"analyze", "validate", "verify"} {
			t.Run(command+"/"+test.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "invalid.xml")
				writeCLIFile(t, path, test.xml)
				flag := "--path"
				if command == "analyze" {
					flag = "--config"
				}
				var code int
				_, stderr := captureCommandOutput(t, func() { code = run([]string{command, flag, path}) })
				if code == exitOK || !strings.Contains(stderr, test.finding) {
					t.Fatalf("expected error with %q: code=%d stderr=%q", test.finding, code, stderr)
				}
				if command == "analyze" && !strings.Contains(stderr, test.source) {
					t.Errorf("analysis error is missing source %q:\n%s", test.source, stderr)
				}
			})
		}
	}
}
