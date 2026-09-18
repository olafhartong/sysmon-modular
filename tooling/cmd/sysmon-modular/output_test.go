package main

import "testing"

func TestSourceLineWithoutComments(t *testing.T) {
	lines := []string{
		`<Image>cmd.exe</Image> <!-- explanation -->`,
		`<!-- comment starts`,
		`and ends --> <Image>pwsh.exe</Image> <!-- trailing -->`,
	}
	if got := sourceLineWithoutComments(lines, 0); got != `<Image>cmd.exe</Image> ` {
		t.Fatalf("same-line comment was not removed: %q", got)
	}
	if got := sourceLineWithoutComments(lines, 2); got != ` <Image>pwsh.exe</Image> ` {
		t.Fatalf("multi-line comment was not removed: %q", got)
	}
}
