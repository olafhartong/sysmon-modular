package semantic

import (
	"fmt"
	"sort"
	"strings"

	"github.com/olafhartong/sysmon-modular/internal/mitre"
	"github.com/olafhartong/sysmon-modular/internal/sysmonxml"
)

type Filter struct {
	Event     string `json:"event"`
	Onmatch   string `json:"onmatch"`
	Field     string `json:"field"`
	Condition string `json:"condition"`
	Value     string `json:"value"`
	Group     string `json:"group,omitempty"`
}

func (f Filter) Key() string {
	return strings.Join([]string{f.Event, f.Onmatch, f.Field, f.Condition, strings.ToLower(f.Value), f.Group}, "\x00")
}

type Config struct {
	Filters    []Filter `json:"filters"`
	Techniques []string `json:"techniques"`
}

func Extract(doc *sysmonxml.Document) Config {
	var c Config
	techniques := map[string]bool{}
	if doc == nil || doc.Root == nil {
		return c
	}
	ef := doc.Root.FirstChild("EventFiltering")
	if ef == nil {
		ef = doc.Root
	}
	for _, rg := range ef.ElementChildren() {
		if rg.Name != "RuleGroup" {
			continue
		}
		group := rg.AttrValue("name") + ":" + strings.ToLower(rg.AttrValue("groupRelation"))
		for _, event := range rg.ElementChildren() {
			onmatch := strings.ToLower(event.AttrValue("onmatch"))
			if onmatch == "" {
				onmatch = "include"
			}
			collect(event, event.Name, onmatch, group, &c.Filters, techniques)
		}
	}
	for id := range techniques {
		c.Techniques = append(c.Techniques, id)
	}
	sort.Strings(c.Techniques)
	sort.Slice(c.Filters, func(i, j int) bool { return c.Filters[i].Key() < c.Filters[j].Key() })
	return c
}

func collect(n *sysmonxml.Node, event, onmatch, group string, filters *[]Filter, techniques map[string]bool) {
	for _, attr := range n.Attr {
		if attr.Name.Local == "name" {
			for _, id := range mitre.IDsFromValue(attr.Value) {
				techniques[id] = true
			}
		}
	}
	for _, child := range n.ElementChildren() {
		if child.Name == "Rule" {
			collect(child, event, onmatch, group+":"+child.AttrValue("name")+":"+child.AttrValue("groupRelation"), filters, techniques)
			continue
		}
		*filters = append(*filters, Filter{Event: event, Onmatch: onmatch, Field: child.Name, Condition: strings.ToLower(child.AttrValue("condition")), Value: strings.TrimSpace(child.Text), Group: group})
		for _, attr := range child.Attr {
			if attr.Name.Local == "name" {
				for _, id := range mitre.IDsFromValue(attr.Value) {
					techniques[id] = true
				}
			}
		}
	}
}

type Change struct {
	Kind      string  `json:"kind"`
	Impact    string  `json:"impact"`
	Filter    *Filter `json:"filter,omitempty"`
	Technique string  `json:"technique,omitempty"`
	Detail    string  `json:"detail"`
}

type Diff struct {
	Changes []Change       `json:"changes"`
	Summary map[string]int `json:"summary"`
}

func Compare(before, after Config) Diff {
	d := Diff{Summary: map[string]int{}}
	bm, am := map[string]Filter{}, map[string]Filter{}
	for _, f := range before.Filters {
		bm[f.Key()] = f
	}
	for _, f := range after.Filters {
		am[f.Key()] = f
	}
	for k, f := range am {
		if _, ok := bm[k]; !ok {
			impact := "widened"
			if f.Onmatch == "exclude" {
				impact = "narrowed"
			}
			add(&d, Change{Kind: "filter-added", Impact: impact, Filter: &f, Detail: fmt.Sprintf("added %s %s filter", f.Event, f.Onmatch)})
		}
	}
	for k, f := range bm {
		if _, ok := am[k]; !ok {
			impact := "narrowed"
			if f.Onmatch == "exclude" {
				impact = "widened"
			}
			add(&d, Change{Kind: "filter-removed", Impact: impact, Filter: &f, Detail: fmt.Sprintf("removed %s %s filter", f.Event, f.Onmatch)})
		}
	}
	bt, at := set(before.Techniques), set(after.Techniques)
	for id := range at {
		if !bt[id] {
			add(&d, Change{Kind: "technique-added", Impact: "coverage-added", Technique: id, Detail: "ATT&CK coverage added"})
		}
	}
	for id := range bt {
		if !at[id] {
			add(&d, Change{Kind: "technique-removed", Impact: "coverage-removed", Technique: id, Detail: "ATT&CK coverage removed"})
		}
	}
	sort.Slice(d.Changes, func(i, j int) bool {
		return d.Changes[i].Kind+d.Changes[i].Detail < d.Changes[j].Kind+d.Changes[j].Detail
	})
	return d
}

func add(d *Diff, c Change) {
	d.Changes = append(d.Changes, c)
	d.Summary[c.Kind]++
	if c.Impact != "" {
		d.Summary[c.Impact]++
	}
}
func set(v []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		m[s] = true
	}
	return m
}
