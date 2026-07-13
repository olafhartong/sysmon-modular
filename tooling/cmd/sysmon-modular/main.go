package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/olafhartong/sysmon-modular/internal/analyze"
	"github.com/olafhartong/sysmon-modular/internal/generate"
	"github.com/olafhartong/sysmon-modular/internal/merger"
	"github.com/olafhartong/sysmon-modular/internal/mitre"
	"github.com/olafhartong/sysmon-modular/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/internal/validate"
)

const (
	exitOK           = 0
	exitInternal     = 1
	exitUsage        = 2
	exitInvalidInput = 3
	exitFindings     = 4
)

type commandError struct {
	code int
	err  error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }
func usageError(format string, args ...any) error {
	return &commandError{code: exitUsage, err: fmt.Errorf(format, args...)}
}
func inputError(format string, args ...any) error {
	return &commandError{code: exitInvalidInput, err: fmt.Errorf(format, args...)}
}
func findingsError(format string, args ...any) error {
	return &commandError{code: exitFindings, err: fmt.Errorf(format, args...)}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return exitUsage
	}
	var err error
	switch args[0] {
	case "merge":
		err = runMerge(args[1:])
	case "validate":
		err = runValidate(args[1:])
	case "verify":
		err = runValidate(args[1:])
	case "fix-mitre":
		err = runFixMITRE(args[1:])
	case "analyze":
		err = runAnalyze(args[1:])
	case "generate-kql":
		err = runGenerateKQL(args[1:])
	case "generate-mde":
		err = runGenerateMDE(args[1:], generate.MDEModeFiltered)
	case "generate-mde-unfiltered":
		err = runGenerateMDE(args[1:], generate.MDEModeUnfiltered)
	case "generate-mde-inverse":
		err = runGenerateMDE(args[1:], generate.MDEModeInverse)
	case "list-rules":
		err = runListRules(args[1:])
	case "diff":
		err = runDiff(args[1:])
	case "coverage":
		err = runCoverage(args[1:])
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		err = usageError("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, paint(ansiBold+ansiRed, err.Error()))
		var ce *commandError
		if errors.As(err, &ce) {
			return ce.code
		}
		return exitInternal
	}
	return exitOK
}

func usage() {
	fmt.Fprintln(os.Stderr, `sysmon-modular is a Go Sysmon-Modular configuration tool.

Commands:
  merge         merge Sysmon module XML files
  validate      run XML syntax and optional Sysmon schema validation
  verify        alias for validate
  fix-mitre     fix MITRE ATT&CK technique metadata in XML name attributes
  analyze       recommend improvements and flag conflicts/performance risks
  generate-kql  convert simple MDE KQL detections into a Sysmon module
  generate-mde  convert MDE telemetry rules and filters into Sysmon modules
  generate-mde-unfiltered
                generate include-only Sysmon modules for MDE telemetry families
  generate-mde-inverse
                generate include-only Sysmon modules for MDE-filtered blind spots
  list-rules    list rule modules discovered below a base path`)
	fmt.Fprintln(os.Stderr, `  diff          compare two configurations semantically
  coverage      report event, ATT&CK, tactic, module, and include/exclude coverage`)
}

func runMerge(args []string) error {
	fs := newFlagSet("merge")
	var paths multiFlag
	basePath := fs.String("base-path", defaultBasePath(), "repository base path")
	includeList := fs.String("include-list", "", "newline-delimited module include list")
	excludeList := fs.String("exclude-list", "", "newline-delimited module exclude list")
	fileList := fs.String("file-list", "", "CSV/TSV/JSON priority list with filepath and priority")
	format := fs.String("format", "", "priority list format: csv, tsv, or json")
	template := fs.String("template", "", "base Sysmon config template")
	output := fs.String("output", "-", "output file, or - for stdout")
	preserveComments := fs.Bool("preserve-comments", false, "preserve XML comments from source modules")
	forceGroupRelation := fs.Bool("force-grouprelation-or", false, "override every merged RuleGroup groupRelation as or")
	doValidate := fs.Bool("validate", true, "run XML syntax validation before merge")
	doSchema := fs.Bool("schema-validate", true, "run versioned Sysmon event and field validation")
	doAnalyze := fs.Bool("analyze", false, "print analysis warnings for the merged output")
	sysmonVersion := fs.String("sysmon-version", "15", "target Sysmon executable version (12 through 15; default 15)")
	unsupported := fs.String("unsupported", "warn", "unsupported target items: warn or exclude")
	verbose := fs.Bool("verbose", false, "show source XML lines for findings")
	warningsAsErrors := fs.Bool("warnings-as-errors", false, "exit non-zero when warnings/recommendations are emitted")
	fs.Var(&paths, "path", "input XML module path; may be repeated")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	absoluteBasePath, err := filepath.Abs(*basePath)
	if err != nil {
		return inputError("resolve base path: %v", err)
	}
	*basePath = absoluteBasePath
	if err := validateCompatibilityFlags(*sysmonVersion, *unsupported); err != nil {
		return err
	}
	if *fileList != "" {
		listPaths, err := merger.ReadPriorityList(*fileList, *format)
		if err != nil {
			return err
		}
		paths = append(paths, listPaths...)
	}
	var input []string
	if len(paths) == 0 && *includeList == "" {
		found, err := merger.FindRuleFiles(*basePath)
		if err != nil {
			return err
		}
		input = found
	} else {
		input = append(input, paths...)
	}
	resolved, listWarnings, err := merger.ResolveLists(*basePath, input, *includeList, *excludeList)
	if err != nil {
		return err
	}
	printWarnings(listWarnings)
	if len(resolved) < 1 {
		return inputError("no input rules after include/exclude processing")
	}
	if *doValidate {
		for _, path := range resolved {
			findings := validate.SyntaxFile(path, *preserveComments)
			printFindings(findings, *verbose)
			if validate.HasErrors(findings) {
				return findingsError("XML syntax validation failed")
			}
		}
	}
	result, err := merger.Merge(resolved, merger.Options{Template: resolveTemplate(*basePath, *template), PreserveComments: *preserveComments, ForceGroupRelationOr: *forceGroupRelation})
	if err != nil {
		return err
	}
	printWarnings(result.Warnings)
	var findings []validate.Finding
	if *sysmonVersion != "" {
		target, _ := validate.ResolveBinarySchema(*sysmonVersion)
		result.Document.Root.SetAttr("schemaversion", target.SchemaVersion)
		var compatibility []validate.Finding
		if *unsupported == "exclude" {
			compatibility, err = validate.ExcludeBinaryUnsupported(result.Document, "merged", *sysmonVersion)
		} else {
			compatibility, err = validate.BinaryCompatibility(result.Document, "merged", *sysmonVersion)
		}
		if err != nil {
			return inputError("%v", err)
		}
		findings = append(findings, compatibility...)
	}
	if *doSchema {
		for _, finding := range validate.Schema(result.Document, "merged") {
			// Target compatibility emits a more precise SYS204 finding for the
			// same event/schema mismatch after we set the target schema version.
			if *sysmonVersion != "" && finding.Code == "SYS201" {
				continue
			}
			findings = append(findings, finding)
		}
	}
	if *doAnalyze {
		findings = append(findings, analyze.Config(result.Document, "merged")...)
	}
	printFindings(findings, *verbose)
	if validate.HasErrors(findings) || (*warningsAsErrors && len(findings) > 0) {
		return findingsError("validation or analysis findings were emitted")
	}
	return writeOutput(*output, result.Document.Bytes())
}

func runValidate(args []string) error {
	fs := newFlagSet("validate")
	var paths multiFlag
	basePath := fs.String("base-path", defaultBasePath(), "repository base path")
	all := fs.Bool("all", false, "validate all modules below base path")
	allXML := fs.Bool("all-xml", false, "validate every XML file below base path")
	schema := fs.Bool("schema", true, "run structural Sysmon schema validation")
	sysmonVersion := fs.String("sysmon-version", "", "target Sysmon executable version (12 through 15)")
	unsupported := fs.String("unsupported", "warn", "unsupported target items: warn or exclude (exclude is a dry run)")
	mitreCheck := fs.Bool("mitre", true, "run MITRE ATT&CK technique id/name validation")
	preserveComments := fs.Bool("preserve-comments", false, "preserve XML comments while parsing")
	verbose := fs.Bool("verbose", false, "show source XML lines for findings")
	fs.Var(&paths, "path", "XML file to validate; may be repeated")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if err := validateCompatibilityFlags(*sysmonVersion, *unsupported); err != nil {
		return err
	}
	if *all {
		found, err := merger.FindRuleFiles(*basePath)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return inputError("no Sysmon module XML files found below %s", *basePath)
		}
		paths = append(paths, found...)
	}
	if *allXML {
		found, err := findXMLFiles(*basePath)
		if err != nil {
			return err
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		return usageError("provide --path, --all, or --all-xml")
	}
	paths = dedupeStrings(paths)
	var allFindings []validate.Finding
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return inputError("--path expects an XML file, but %s is a directory; use --all --base-path %s to validate repository modules", path, path)
		}
		findings := validate.SyntaxFile(path, *preserveComments)
		allFindings = append(allFindings, findings...)
		if len(findings) == 0 && (*schema || *mitreCheck || *sysmonVersion != "") {
			doc, err := sysmonxml.ParseFile(path, *preserveComments)
			if err != nil {
				return err
			}
			if *schema {
				allFindings = append(allFindings, validate.Schema(doc, path)...)
			}
			if *mitreCheck {
				allFindings = append(allFindings, validate.MITRE(doc, path)...)
			}
			if *sysmonVersion != "" {
				var compatibility []validate.Finding
				if *unsupported == "exclude" {
					compatibility, err = validate.ExcludeBinaryUnsupported(doc, path, *sysmonVersion)
				} else {
					compatibility, err = validate.BinaryCompatibility(doc, path, *sysmonVersion)
				}
				if err != nil {
					return inputError("%v", err)
				}
				allFindings = append(allFindings, compatibility...)
			}
		}
	}
	printFindings(allFindings, *verbose)
	printFindingSummary(allFindings, len(paths))
	if validate.HasErrors(allFindings) {
		return findingsError("validation failed")
	}
	fmt.Fprintf(os.Stderr, "%s %d file(s)\n", paint(ansiBold+ansiGreen, "✓ VALIDATED"), len(paths))
	return nil
}

func validateCompatibilityFlags(version, unsupported string) error {
	if unsupported != "warn" && unsupported != "exclude" {
		return usageError("--unsupported must be warn or exclude")
	}
	if version == "" {
		if unsupported != "warn" {
			return usageError("--unsupported requires --sysmon-version")
		}
		return nil
	}
	if _, err := validate.ResolveBinarySchema(version); err != nil {
		return inputError("%v", err)
	}
	return nil
}

func runFixMITRE(args []string) error {
	fs := newFlagSet("fix-mitre")
	var paths multiFlag
	basePath := fs.String("base-path", defaultBasePath(), "repository base path")
	all := fs.Bool("all", false, "fix all modules below base path")
	allXML := fs.Bool("all-xml", false, "fix every XML file below base path")
	dryRun := fs.Bool("dry-run", false, "report changes without writing files")
	yes := fs.Bool("yes", false, "apply all fixes without prompting")
	fs.Var(&paths, "path", "XML file to fix; may be repeated")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if *all {
		found, err := merger.FindRuleFiles(*basePath)
		if err != nil {
			return err
		}
		paths = append(paths, found...)
	}
	if *allXML {
		found, err := findXMLFiles(*basePath)
		if err != nil {
			return err
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		return usageError("provide --path, --all, or --all-xml")
	}
	paths = dedupeStrings(paths)
	totalChanges := 0
	totalProposed := 0
	totalSkipped := 0
	totalUnfixed := 0
	reviewer := newMITREReviewer()
	interactive := !*dryRun && !*yes && stdinIsTerminal()
	for _, path := range paths {
		var approve func(mitre.Change) bool
		if interactive {
			approve = reviewer.approve
		}
		result, err := mitre.ReviewFile(path, !*dryRun, approve)
		if err != nil {
			return err
		}
		totalChanges += result.Changes
		totalProposed += result.Proposed
		totalSkipped += result.Skipped
		totalUnfixed += len(result.Unfixed)
		if result.Proposed > 0 {
			action := "fixed"
			if *dryRun {
				action = "would fix"
			}
			fmt.Fprintf(os.Stderr, "%s: %s %d MITRE metadata value(s)", displayPath(path), action, result.Changes)
			if result.Skipped > 0 {
				fmt.Fprintf(os.Stderr, ", skipped %d", result.Skipped)
			}
			fmt.Fprintln(os.Stderr)
		}
		for _, issue := range result.Unfixed {
			fmt.Fprintf(os.Stderr, "%s: %s (%s)\n", paint(ansiBold+ansiYellow, displayPath(path)), mitre.IssueMessage(issue), mitre.IssueDetail(issue))
		}
		if reviewer.quit {
			break
		}
	}
	if *dryRun {
		fmt.Fprintf(os.Stderr, "mitre dry-run: files=%d proposed=%d unfixed=%d\n", len(paths), totalProposed, totalUnfixed)
	} else {
		fmt.Fprintf(os.Stderr, "mitre fix: files=%d applied=%d skipped=%d unfixed=%d\n", len(paths), totalChanges, totalSkipped, totalUnfixed)
	}
	if totalUnfixed > 0 {
		return findingsError("some MITRE metadata issues require manual fixes")
	}
	return nil
}

func runAnalyze(args []string) error {
	fs := newFlagSet("analyze")
	config := fs.String("config", "", "Sysmon config XML to analyze")
	preserveComments := fs.Bool("preserve-comments", false, "preserve XML comments while parsing")
	verbose := fs.Bool("verbose", false, "show source XML lines for findings")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if *config == "" {
		return usageError("provide --config")
	}
	doc, err := sysmonxml.ParseFile(*config, *preserveComments)
	if err != nil {
		return err
	}
	findings := append(validate.Schema(doc, *config), analyze.Config(doc, *config)...)
	printFindings(findings, *verbose)
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "no findings")
	}
	if validate.HasErrors(findings) {
		return findingsError("analysis found invalid configuration")
	}
	return nil
}

func runGenerateKQL(args []string) error {
	fs := newFlagSet("generate-kql")
	kqlPath := fs.String("kql", "", "KQL detection file")
	output := fs.String("output", "-", "output module XML file, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if *kqlPath == "" {
		return usageError("provide --kql")
	}
	data, err := os.ReadFile(*kqlPath)
	if err != nil {
		return err
	}
	doc, warnings, err := generate.KQLModule(string(data))
	printWarnings(warnings)
	if err != nil {
		return err
	}
	return writeOutput(*output, doc.Bytes())
}

func runGenerateMDE(args []string, mode generate.MDEMode) error {
	fs := newFlagSet("generate-mde")
	config := fs.String("mde-config", "mde-config.json", "MDE JSON config")
	outputDir := fs.String("output-dir", defaultMDEOutputDir(mode), "directory for generated Sysmon modules")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	result, err := generate.FromMDEConfigFileMode(*config, *outputDir, mode)
	if err != nil {
		return err
	}
	printWarnings(result.Warnings)
	fmt.Fprintf(os.Stderr, "mde analysis: rules_seen=%d rules_mapped=%d unsupported_rules=%d unsupported_predicates=%d\n",
		result.Stats.RulesSeen, result.Stats.RulesMapped, result.Stats.UnsupportedRules, result.Stats.UnsupportedPredicates)
	for _, file := range result.Files {
		fmt.Fprintln(os.Stderr, "generated", file)
	}
	return nil
}

func defaultMDEOutputDir(mode generate.MDEMode) string {
	switch mode {
	case generate.MDEModeUnfiltered:
		return "0_custom_configuration/generated_mde_unfiltered"
	case generate.MDEModeInverse:
		return "0_custom_configuration/generated_mde_inverse"
	default:
		return "0_custom_configuration/generated_mde"
	}
}

func runListRules(args []string) error {
	fs := newFlagSet("list-rules")
	basePath := fs.String("base-path", defaultBasePath(), "repository base path")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	paths, err := merger.FindRuleFiles(*basePath)
	if err != nil {
		return err
	}
	for _, path := range paths {
		rel, err := filepath.Rel(*basePath, path)
		if err != nil {
			rel = path
		}
		fmt.Println(filepath.ToSlash(rel))
	}
	return nil
}

func findXMLFiles(basePath string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(basePath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".xml") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dedupeStrings(paths), nil
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func resolveTemplate(basePath, template string) string {
	if template != "" {
		return template
	}
	candidate := filepath.Join(basePath, "templates", "sysmon_template.xml")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func writeOutput(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sysmon-modular-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0o644)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func defaultBasePath() string {
	if hasNumberedModuleDirs(".") {
		return "."
	}
	if hasNumberedModuleDirs("..") {
		return ".."
	}
	return "."
}

func hasNumberedModuleDirs(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			return true
		}
	}
	return false
}

func flagParseError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return &commandError{code: exitUsage, err: err}
}

func printWarnings(warnings []string) {
	for _, warning := range warnings {
		if warning != "" {
			fmt.Fprintln(os.Stderr, paint(ansiBold+ansiYellow, warning))
		}
	}
}
