package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/mitre"
)

type mitreReviewer struct {
	reader     *bufio.Reader
	approveAll bool
	quit       bool
}

func newMITREReviewer() *mitreReviewer {
	return &mitreReviewer{reader: bufio.NewReader(os.Stdin)}
}

func (r *mitreReviewer) approve(change mitre.Change) bool {
	if r.approveAll {
		return true
	}
	if r.quit {
		return false
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", paint(ansiBold+ansiBlue, fmt.Sprintf("%s:%d", displayPath(change.Path), change.Line)))
	fmt.Fprintf(os.Stderr, "  %s %s\n", paint(ansiBold+ansiRed, "−"), change.Before)
	fmt.Fprintf(os.Stderr, "  %s %s\n", paint(ansiBold+ansiGreen, "+"), change.After)
	for {
		fmt.Fprintf(os.Stderr, "%s ", paint(ansiBold+ansiCyan, "Apply? [Enter=all/y/n/q]"))
		answer, err := r.reader.ReadString('\n')
		if err != nil && strings.TrimSpace(answer) == "" {
			// Closed input is non-interactive in practice; retain the documented
			// default of applying all fixes.
			r.approveAll = true
			fmt.Fprintln(os.Stderr, "all")
			return true
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "", "a", "all":
			r.approveAll = true
			return true
		case "y", "yes":
			return true
		case "n", "no":
			return false
		case "q", "quit":
			r.quit = true
			return false
		default:
			fmt.Fprintln(os.Stderr, "Enter y (yes), n (no), a (all), or q (quit).")
		}
	}
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
