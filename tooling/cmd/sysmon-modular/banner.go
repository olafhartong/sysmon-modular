package main

import (
	_ "embed"
	"fmt"
	"io"
)

//go:embed banner.txt
var banner string

func printBanner(output io.Writer) {
	fmt.Fprintln(output, paint(ansiOrange, banner))
}
