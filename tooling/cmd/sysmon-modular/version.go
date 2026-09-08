package main

import (
	"fmt"
	"os"
)

// buildVersion can be overridden with -ldflags "-X main.buildVersion=1.1".
var buildVersion = "1.0"

func versionString() string {
	return "sysmon-modular " + buildVersion
}

func runVersion(args []string) error {
	fs := newFlagSet("version")
	if err := fs.Parse(args); err != nil {
		return flagParseError(err)
	}
	if fs.NArg() != 0 {
		return usageError("version does not accept positional arguments")
	}
	_, err := fmt.Fprintln(os.Stdout, versionString())
	return err
}
