package sysmonxml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

type Node struct {
	Name            string
	Line            int
	Attr            []xml.Attr
	Text            string
	Comment         string
	TrailingComment string
	Children        []*Node
}

type Document struct {
	Root *Node
}

func ParseFile(path string, preserveComments bool) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, preserveComments)
}

func Parse(data []byte, preserveComments bool) (*Document, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var root *Node
	var stack []*Node
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			line, _ := decoder.InputPos()
			n := &Node{Name: t.Name.Local, Line: line, Attr: cloneAttrs(t.Attr)}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple document roots")
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("unexpected closing tag %s", t.Name.Local)
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			text := string([]byte(t))
			if strings.TrimSpace(text) != "" {
				cur := stack[len(stack)-1]
				cur.Text += text
			}
		case xml.Comment:
			if preserveComments && len(stack) > 0 {
				cur := stack[len(stack)-1]
				cur.Children = append(cur.Children, &Node{Comment: string([]byte(t))})
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("empty XML document")
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unclosed XML element %s", stack[len(stack)-1].Name)
	}
	return &Document{Root: root}, nil
}

func cloneAttrs(in []xml.Attr) []xml.Attr {
	out := make([]xml.Attr, len(in))
	copy(out, in)
	return out
}

func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	out := &Node{Name: n.Name, Line: n.Line, Attr: cloneAttrs(n.Attr), Text: n.Text, Comment: n.Comment, TrailingComment: n.TrailingComment}
	out.Children = make([]*Node, 0, len(n.Children))
	for _, child := range n.Children {
		out.Children = append(out.Children, child.Clone())
	}
	return out
}

func (n *Node) AttrValue(name string) string {
	for _, attr := range n.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func (n *Node) SetAttr(name, value string) {
	for i := range n.Attr {
		if n.Attr[i].Name.Local == name {
			n.Attr[i].Value = value
			return
		}
	}
	n.Attr = append(n.Attr, xml.Attr{Name: xml.Name{Local: name}, Value: value})
}

func (n *Node) RemoveAttr(name string) {
	var attrs []xml.Attr
	for _, attr := range n.Attr {
		if attr.Name.Local != name {
			attrs = append(attrs, attr)
		}
	}
	n.Attr = attrs
}

func (n *Node) FirstChild(name string) *Node {
	for _, child := range n.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}

func (n *Node) Walk(fn func(*Node)) {
	if n == nil {
		return
	}
	fn(n)
	for _, child := range n.Children {
		child.Walk(fn)
	}
}

func (n *Node) ElementChildren() []*Node {
	out := make([]*Node, 0, len(n.Children))
	for _, child := range n.Children {
		if child.Name != "" {
			out = append(out, child)
		}
	}
	return out
}

func Element(name string, attrs map[string]string, children ...*Node) *Node {
	n := &Node{Name: name}
	for k, v := range attrs {
		n.Attr = append(n.Attr, xml.Attr{Name: xml.Name{Local: k}, Value: v})
	}
	n.Children = append(n.Children, children...)
	return n
}

func TextElement(name, text string, attrs map[string]string) *Node {
	n := Element(name, attrs)
	n.Text = text
	return n
}
