package sysmonxml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFormatAndPreserveComments(t *testing.T) {
	doc, err := Parse([]byte(`<Sysmon z="last" a="first">
  <!-- kept -->
  <EventFiltering><RuleGroup><ProcessCreate onmatch="include"><Image condition="is">a&amp;b.exe</Image></ProcessCreate></RuleGroup></EventFiltering>
</Sysmon>`), true)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Root.Name != "Sysmon" || doc.Root.Line != 1 || len(doc.Root.ElementChildren()) != 1 {
		t.Fatalf("unexpected parsed root: %#v", doc.Root)
	}
	formatted := doc.String()
	if !strings.Contains(formatted, `<Sysmon a="first" z="last">`) || !strings.Contains(formatted, `<!-- kept -->`) || !strings.Contains(formatted, `a&amp;b.exe`) {
		t.Fatalf("formatting lost ordering, comments, or escaping:\n%s", formatted)
	}
	if _, err := Parse(doc.Bytes(), true); err != nil {
		t.Fatalf("formatted XML is not parseable: %v", err)
	}
}

func TestNodeCloneAndMutationAreIndependent(t *testing.T) {
	root := Element("Sysmon", map[string]string{"schemaversion": "4.90"},
		Element("EventFiltering", nil, TextElement("Image", "cmd.exe", map[string]string{"condition": "image"})),
	)
	clone := root.Clone()
	clone.SetAttr("schemaversion", "4.91")
	clone.SetAttr("new", "value")
	clone.RemoveAttr("new")
	clone.FirstChild("EventFiltering").Children[0].Text = "powershell.exe"
	if root.AttrValue("schemaversion") != "4.90" || root.FirstChild("EventFiltering").Children[0].Text != "cmd.exe" {
		t.Fatalf("clone mutation changed the original: original=%#v clone=%#v", root, clone)
	}
	var names []string
	clone.Walk(func(node *Node) { names = append(names, node.Name) })
	if strings.Join(names, ",") != "Sysmon,EventFiltering,Image" {
		t.Fatalf("unexpected walk order: %v", names)
	}
}

func TestParseRecordsOpeningTagLines(t *testing.T) {
	input := "<?xml version=\"1.0\"?>\n<!-- before root -->\n<Sysmon\n  schemaversion=\"4.90\">\n  <EventFiltering>\n    <!-- before event\n         still a comment -->\n    <ProcessCreate\n      onmatch=\"include\">\n      <Image\n        condition=\"is\">cmd.exe</Image>\n      <Image/>\n    </ProcessCreate>\n  </EventFiltering>\n</Sysmon>"
	for _, newline := range []string{"\n", "\r\n"} {
		for _, preserveComments := range []bool{false, true} {
			doc, err := Parse([]byte(strings.ReplaceAll(input, "\n", newline)), preserveComments)
			if err != nil {
				t.Fatal(err)
			}
			want := []int{3, 5, 8, 10, 12}
			index := 0
			doc.Root.Walk(func(node *Node) {
				if node.Name == "" {
					return
				}
				if index >= len(want) || node.Line != want[index] {
					t.Fatalf("wrong opening line for %s: got %d at index %d, want %v", node.Name, node.Line, index, want)
				}
				index++
			})
			if index != len(want) {
				t.Fatalf("got %d elements, want %d", index, len(want))
			}
		}
	}
}

func TestParseFileAndInvalidDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.xml")
	if err := os.WriteFile(path, []byte(`<Sysmon/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if doc, err := ParseFile(path, false); err != nil || doc.Root.Name != "Sysmon" {
		t.Fatalf("ParseFile failed: doc=%#v err=%v", doc, err)
	}
	for _, input := range []string{"", `<Sysmon/><Other/>`, `<Sysmon>`} {
		if _, err := Parse([]byte(input), false); err == nil {
			t.Fatalf("invalid XML was accepted: %q", input)
		}
	}
}

func TestFormatWritesTrailingCommentAndEmptyElement(t *testing.T) {
	node := TextElement("Image", "cmd.exe", map[string]string{"condition": "image"})
	node.TrailingComment = "reviewed"
	doc := &Document{Root: Element("Sysmon", nil, node, Element("Empty", nil))}
	formatted := doc.String()
	if !strings.Contains(formatted, `</Image> <!-- reviewed -->`) || !strings.Contains(formatted, `<Empty/>`) {
		t.Fatalf("unexpected formatted XML:\n%s", formatted)
	}
}
