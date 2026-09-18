package semantic

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/expression"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type Config struct {
	Rules      []expression.Event `json:"rules"`
	Techniques []string           `json:"techniques"`
}

func Extract(doc *sysmonxml.Document) Config {
	model := expression.FromXML(doc)
	return Config{Rules: model.Events, Techniques: model.Techniques}
}

type Change struct {
	Kind      string            `json:"kind"`
	Impact    string            `json:"impact"`
	Rule      *expression.Event `json:"rule,omitempty"`
	Technique string            `json:"technique,omitempty"`
	Detail    string            `json:"detail"`
}

type Diff struct {
	Changes []Change       `json:"changes"`
	Summary map[string]int `json:"summary"`
}

func Compare(before, after Config) Diff {
	d := Diff{Summary: map[string]int{}}
	bm, am := map[string][]expression.Event{}, map[string][]expression.Event{}
	for _, rule := range before.Rules {
		bm[rule.Key()] = append(bm[rule.Key()], rule)
	}
	for _, rule := range after.Rules {
		am[rule.Key()] = append(am[rule.Key()], rule)
	}
	keys := map[string]bool{}
	for key := range bm {
		keys[key] = true
	}
	for key := range am {
		keys[key] = true
	}
	for _, key := range sortedKeys(keys) {
		beforeRules, afterRules := bm[key], am[key]
		sort.Slice(beforeRules, func(i, j int) bool { return eventSortKey(beforeRules[i]) < eventSortKey(beforeRules[j]) })
		sort.Slice(afterRules, func(i, j int) bool { return eventSortKey(afterRules[i]) < eventSortKey(afterRules[j]) })
		common := min(len(beforeRules), len(afterRules))
		for _, rule := range afterRules[common:] {
			copy := rule
			add(&d, Change{Kind: "expression-added", Impact: "unknown", Rule: &copy, Detail: fmt.Sprintf("added %s %s expression %s", rule.Name, rule.Onmatch, rule.Expression.Canonical())})
		}
		for _, rule := range beforeRules[common:] {
			copy := rule
			add(&d, Change{Kind: "expression-removed", Impact: "unknown", Rule: &copy, Detail: fmt.Sprintf("removed %s %s expression %s", rule.Name, rule.Onmatch, rule.Expression.Canonical())})
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
		return changeSortKey(d.Changes[i]) < changeSortKey(d.Changes[j])
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

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func eventSortKey(event expression.Event) string {
	return strings.Join([]string{
		event.Key(), event.GroupName, event.GroupRelation,
		strings.Join(event.Techniques, ","), strconv.Itoa(event.Line),
	}, "\x00")
}

func changeSortKey(change Change) string {
	parts := []string{change.Kind, change.Impact, change.Technique, change.Detail}
	if change.Rule != nil {
		parts = append(parts, eventSortKey(*change.Rule))
	}
	return strings.Join(parts, "\x00")
}
