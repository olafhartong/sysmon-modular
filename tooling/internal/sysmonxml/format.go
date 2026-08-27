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
	_ = writeNode(&b, d.Root, 0)
	return b.Bytes()
}

func (d *Document) String() string {
	return string(d.Bytes())
}

func writeNode(w io.Writer, n *Node, depth int) error {
	indent := strings.Repeat("  ", depth)
	if n.Comment != "" {
		_, err := io.WriteString(w, indent+"<!--"+n.Comment+"-->\n")
		return err
	}
	if _, err := io.WriteString(w, indent+"<"+n.Name); err != nil {
		return err
	}
	attrs := cloneAttrs(n.Attr)
	sort.SliceStable(attrs, func(i, j int) bool { return attrs[i].Name.Local < attrs[j].Name.Local })
	for _, attr := range attrs {
		if _, err := io.WriteString(w, " "+attr.Name.Local+"=\""); err != nil {
			return err
		}
		if err := xml.EscapeText(w, []byte(attr.Value)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\""); err != nil {
			return err
		}
	}
	if len(n.Children) == 0 && strings.TrimSpace(n.Text) == "" {
		if _, err := io.WriteString(w, "/>"); err != nil {
			return err
		}
		if err := writeTrailingComment(w, n); err != nil {
			return err
		}
		_, err := io.WriteString(w, "\n")
		return err
	}
	if _, err := io.WriteString(w, ">"); err != nil {
		return err
	}
	text := n.Text
	if len(n.Children) == 0 {
		if err := xml.EscapeText(w, []byte(text)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "</"+n.Name+">"); err != nil {
			return err
		}
		if err := writeTrailingComment(w, n); err != nil {
			return err
		}
		_, err := io.WriteString(w, "\n")
		return err
	}
	if text != "" {
		if err := xml.EscapeText(w, []byte(text)); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	for _, child := range n.Children {
		if err := writeNode(w, child, depth+1); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, indent+"</"+n.Name+">\n")
	return err
}

func writeTrailingComment(w io.Writer, n *Node) error {
	if n.TrailingComment != "" {
		_, err := io.WriteString(w, " <!-- "+n.TrailingComment+" -->")
		return err
	}
	return nil
}
