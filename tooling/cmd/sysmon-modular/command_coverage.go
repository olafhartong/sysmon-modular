package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	coveragepkg "github.com/olafhartong/sysmon-modular/tooling/internal/coverage"
	"github.com/olafhartong/sysmon-modular/tooling/internal/merger"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func runCoverage(args []string) error {
	fs := newFlagSet("coverage")
	var paths multiFlag
	base := fs.String("base-path", defaultBasePath(), "repository base path")
	all := fs.Bool("all", false, "analyze all repository modules")
	includeList := fs.String("include-list", "", "newline-delimited module include list")
	excludeList := fs.String("exclude-list", "", "newline-delimited module exclude list")
	format := fs.String("format", "text", "output format: text, json, csv, or navigator")
	output := fs.String("output", "-", "output file, or - for stdout")
	attackVersion := fs.String("attack-version", "18", "Navigator ATT&CK version: 18 or 19")
	name := fs.String("name", "Sysmon Modular coverage", "Navigator layer name")
	description := fs.String("description", "ATT&CK technique coverage generated from Sysmon configuration metadata.", "Navigator layer description")
	template := fs.String("template", "", "optional ATT&CK Navigator layer template")
	fs.Var(&paths, "path", "configuration or module path; may be repeated")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if *format != "navigator" {
		var navigatorFlag string
		fs.Visit(func(flag *flag.Flag) {
			switch flag.Name {
			case "attack-version", "name", "description", "template":
				navigatorFlag = flag.Name
			}
		})
		if navigatorFlag != "" {
			return usageError("--%s requires --format navigator", navigatorFlag)
		}
	} else if *attackVersion != "18" && *attackVersion != "19" {
		return usageError("unsupported ATT&CK version %q; use 18 or 19", *attackVersion)
	}
	absoluteBase, err := filepath.Abs(*base)
	if err != nil {
		return inputError("resolve base path: %v", err)
	}
	*base = absoluteBase
	selected := make([]string, 0, len(paths))
	for _, path := range paths {
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return inputError("resolve input path %s: %v", path, err)
		}
		selected = append(selected, absolutePath)
	}
	if *all {
		found, err := merger.FindRuleFiles(*base)
		if err != nil {
			return inputError("discover modules: %v", err)
		}
		selected = append(selected, found...)
	}
	if len(selected) == 0 && *includeList == "" {
		return usageError("coverage requires --path or --all, or use --include-list")
	}
	resolved, warnings, err := merger.ResolveLists(*base, selected, *includeList, *excludeList)
	if err != nil {
		return inputError("resolve module selection: %v", err)
	}
	printWarnings(warnings)
	if len(resolved) == 0 {
		return inputError("no inputs remain after include/exclude processing")
	}
	docs := map[string]*sysmonxml.Document{}
	for _, path := range resolved {
		doc, err := sysmonxml.ParseFile(path, false)
		if err != nil {
			return inputError("%s: %v", path, err)
		}
		name, relErr := filepath.Rel(*base, path)
		if relErr != nil || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			name = filepath.Base(path)
		}
		docs[filepath.ToSlash(name)] = doc
	}
	r := coveragepkg.Build(docs)
	var b bytes.Buffer
	var renderErr error
	switch *format {
	case "text":
		renderErr = coveragepkg.WriteText(&b, r)
	case "json":
		renderErr = coveragepkg.WriteJSON(&b, r)
	case "csv":
		renderErr = coveragepkg.WriteCSV(&b, r)
	case "navigator":
		var templateData []byte
		if *template != "" {
			templateData, renderErr = os.ReadFile(*template)
			if renderErr != nil {
				return inputError("read Navigator template: %v", renderErr)
			}
		}
		if len(r.Techniques) == 0 {
			fmt.Fprintln(os.Stderr, "no ATT&CK technique metadata found; generated an empty Navigator layer")
		}
		for _, remapping := range coveragepkg.NavigatorRemappings(r, *attackVersion) {
			fmt.Fprintf(os.Stderr, "ATT&CK 18 compatibility: remapped %s to %s\n", remapping.From, remapping.To)
		}
		if *attackVersion == "19" {
			fmt.Fprintln(os.Stderr, "ATT&CK 19 layers may not load in hosted Navigator 5.3.2; use --attack-version 18 for compatibility")
		}
		renderErr = coveragepkg.WriteNavigatorWithOptions(&b, r, coveragepkg.NavigatorOptions{
			Name: *name, Description: *description, Template: templateData, AttackVersion: *attackVersion,
		})
		if renderErr != nil {
			return inputError("render Navigator layer: %v", renderErr)
		}
	default:
		return usageError("unsupported coverage format %q", *format)
	}
	if renderErr != nil {
		return fmt.Errorf("render coverage: %w", renderErr)
	}
	return writeOutput(*output, b.Bytes())
}
