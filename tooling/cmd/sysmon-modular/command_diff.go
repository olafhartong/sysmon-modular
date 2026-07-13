package main

import (
	"encoding/json"
	"fmt"

	"github.com/olafhartong/sysmon-modular/tooling/internal/semantic"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func runDiff(args []string) error {
	fs := newFlagSet("diff")
	before := fs.String("before", "", "configuration before the change")
	after := fs.String("after", "", "configuration after the change")
	format := fs.String("format", "text", "output format: text or json")
	output := fs.String("output", "-", "output file, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if *before == "" || *after == "" {
		return usageError("diff requires --before and --after")
	}
	b, err := sysmonxml.ParseFile(*before, false)
	if err != nil {
		return inputError("read before config: %v", err)
	}
	a, err := sysmonxml.ParseFile(*after, false)
	if err != nil {
		return inputError("read after config: %v", err)
	}
	d := semantic.Compare(semantic.Extract(b), semantic.Extract(a))
	var data []byte
	switch *format {
	case "json":
		data, err = json.MarshalIndent(d, "", "  ")
		data = append(data, '\n')
	case "text":
		var text string
		for _, c := range d.Changes {
			if c.Filter != nil {
				text += fmt.Sprintf("%-18s %-15s %s %s.%s %s %q\n", c.Kind, c.Impact, c.Filter.Onmatch, c.Filter.Event, c.Filter.Field, c.Filter.Condition, c.Filter.Value)
			} else {
				text += fmt.Sprintf("%-18s %-15s %s\n", c.Kind, c.Impact, c.Technique)
			}
		}
		if text == "" {
			text = "no semantic changes\n"
		}
		data = []byte(text)
	default:
		return usageError("unsupported diff format %q", *format)
	}
	if err != nil {
		return err
	}
	return writeOutput(*output, data)
}
