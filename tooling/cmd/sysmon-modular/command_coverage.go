package main

import (
	"bytes"
	"fmt"
	"path/filepath"

	coveragepkg "github.com/olafhartong/sysmon-modular/tooling/internal/coverage"
	"github.com/olafhartong/sysmon-modular/tooling/internal/merger"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func runCoverage(args []string) error {
	fs := newFlagSet("coverage")
	var paths multiFlag
	base := fs.String("base-path", defaultBasePath(), "repository base path")
	all := fs.Bool("all", false, "analyze all repository modules")
	format := fs.String("format", "text", "output format: text, json, csv, or navigator")
	output := fs.String("output", "-", "output file, or - for stdout")
	fs.Var(&paths, "path", "configuration or module path; may be repeated")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if *all {
		found, err := merger.FindRuleFiles(*base)
		if err != nil {
			return err
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		return usageError("coverage requires --path or --all")
	}
	docs := map[string]*sysmonxml.Document{}
	for _, path := range paths {
		doc, err := sysmonxml.ParseFile(path, false)
		if err != nil {
			return inputError("%s: %v", path, err)
		}
		name, relErr := filepath.Rel(*base, path)
		if relErr != nil {
			name = path
		}
		docs[filepath.ToSlash(name)] = doc
	}
	r := coveragepkg.Build(docs)
	var b bytes.Buffer
	var err error
	switch *format {
	case "text":
		err = coveragepkg.WriteText(&b, r)
	case "json":
		err = coveragepkg.WriteJSON(&b, r)
	case "csv":
		err = coveragepkg.WriteCSV(&b, r)
	case "navigator":
		err = coveragepkg.WriteNavigator(&b, r)
	default:
		return usageError("unsupported coverage format %q", *format)
	}
	if err != nil {
		return fmt.Errorf("render coverage: %w", err)
	}
	return writeOutput(*output, b.Bytes())
}
