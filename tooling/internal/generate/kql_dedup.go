package generate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

const existingKQLConditionComment = "already present in main tree"

type existingConditionSources map[string]string

func loadExistingConditionSources(paths []string) (existingConditionSources, error) {
	sources := existingConditionSources{}
	for _, path := range paths {
		doc, err := sysmonxml.ParseFile(path, false)
		if err != nil {
			return nil, fmt.Errorf("read KQL deduplication module %s: %w", path, err)
		}
		collectExistingConditionSources(doc, shortModulePath(path), sources)
	}
	return sources, nil
}

func collectExistingConditionSources(doc *sysmonxml.Document, source string, sources existingConditionSources) {
	if doc == nil || doc.Root == nil {
		return
	}
	doc.Root.Walk(func(group *sysmonxml.Node) {
		if group.Name != "RuleGroup" {
			return
		}
		for _, event := range group.ElementChildren() {
			onmatch := strings.ToLower(strings.TrimSpace(event.AttrValue("onmatch")))
			if onmatch == "" {
				onmatch = "include"
			}
			event.Walk(func(node *sysmonxml.Node) {
				if strings.TrimSpace(node.AttrValue("condition")) == "" {
					return
				}
				key := kqlConditionKey(event.Name, onmatch, conditionFromXML(node))
				if _, exists := sources[key]; !exists {
					sources[key] = source
				}
			})
		}
	})
}

func annotateExistingConditions(conditions []Condition, event, onmatch string, sources existingConditionSources, count int) ([]Condition, int) {
	if len(sources) == 0 {
		return conditions, count
	}
	out := append([]Condition(nil), conditions...)
	for i := range out {
		source, exists := sources[kqlConditionKey(event, onmatch, out[i])]
		if !exists {
			continue
		}
		comment := existingKQLConditionComment
		if source != "" {
			comment += ": " + strings.ReplaceAll(source, "--", "-")
		}
		if out[i].Comment == "" {
			out[i].Comment = comment
		} else if !strings.Contains(out[i].Comment, existingKQLConditionComment) {
			out[i].Comment += "; " + comment
		}
		count++
	}
	return out, count
}

func kqlConditionKey(event, onmatch string, condition Condition) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(event)),
		strings.ToLower(strings.TrimSpace(onmatch)),
		strings.ToLower(strings.TrimSpace(condition.Field)),
		strings.ToLower(strings.TrimSpace(condition.Operator)),
		strings.ToLower(strings.TrimSpace(collapseRepeatedBackslashes(condition.Value))),
	}, "\x00")
}

func shortModulePath(path string) string {
	path = filepath.Clean(path)
	dir := filepath.Base(filepath.Dir(path))
	if dir == "." || dir == string(filepath.Separator) {
		return filepath.Base(path)
	}
	return filepath.ToSlash(filepath.Join(dir, filepath.Base(path)))
}

func AnnotateExistingKQLConditions(conditions []Condition, event, onmatch string, paths []string) ([]Condition, int, error) {
	sources, err := loadExistingConditionSources(paths)
	if err != nil {
		return nil, 0, err
	}
	annotated, count := annotateExistingConditions(conditions, event, onmatch, sources, 0)
	return annotated, count, nil
}
