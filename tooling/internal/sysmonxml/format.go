package sysmonxml

import (
	"bytes"
	"encoding/xml"
	"io"
	"sort"
	"strings"
)

func (d *Document) Bytes() []byte {
	var b bytes.Buffer
	writeNode(&b, d.Root, 0)
	return b.Bytes()
}

func (d *Document) String() string {
	return string(d.Bytes())
}

func writeNode(w io.Writer, n *Node, depth int) {
	indent := strings.Repeat("  ", depth)
	if n.Comment != "" {
		io.WriteString(w, indent+"<!--"+n.Comment+"-->\n")
		return
	}
	io.WriteString(w, indent+"<"+n.Name)
	attrs := cloneAttrs(n.Attr)
	sort.SliceStable(attrs, func(i, j int) bool { return attrs[i].Name.Local < attrs[j].Name.Local })
	for _, attr := range attrs {
		io.WriteString(w, " "+attr.Name.Local+"=\"")
		xml.EscapeText(w, []byte(attr.Value))
		io.WriteString(w, "\"")
	}
	if len(n.Children) == 0 && strings.TrimSpace(n.Text) == "" {
		io.WriteString(w, "/>")
		writeTrailingComment(w, n)
		io.WriteString(w, "\n")
		return
	}
	io.WriteString(w, ">")
	text := n.Text
	if len(n.Children) == 0 {
		xml.EscapeText(w, []byte(text))
		io.WriteString(w, "</"+n.Name+">")
		writeTrailingComment(w, n)
		io.WriteString(w, "\n")
		return
	}
	if text != "" {
		xml.EscapeText(w, []byte(text))
	}
	io.WriteString(w, "\n")
	for _, child := range n.Children {
		writeNode(w, child, depth+1)
	}
	io.WriteString(w, indent+"</"+n.Name+">\n")
}

func writeTrailingComment(w io.Writer, n *Node) {
	if n.TrailingComment != "" {
		io.WriteString(w, " <!-- "+n.TrailingComment+" -->")
	}
}
