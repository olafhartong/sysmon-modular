package coverage

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/expression"
	"github.com/olafhartong/sysmon-modular/tooling/internal/mitre"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type Event struct {
	Name    string   `json:"name"`
	Include int      `json:"include"`
	Exclude int      `json:"exclude"`
	Modules []string `json:"modules"`
}
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	Modules []string `json:"modules"`
	Count   int      `json:"count"`
}
type Report struct {
	Events     []Event        `json:"events"`
	Techniques []Technique    `json:"techniques"`
	Tactics    map[string]int `json:"tactics"`
	Modules    map[string]int `json:"modules"`
	Include    int            `json:"include"`
	Exclude    int            `json:"exclude"`
}

func Build(docs map[string]*sysmonxml.Document) Report {
	type ec struct {
		in, ex  int
		modules map[string]bool
	}
	events := map[string]*ec{}
	tmods := map[string]map[string]bool{}
	tcounts := map[string]int{}
	modules := map[string]int{}
	for module, doc := range docs {
		if doc == nil || doc.Root == nil {
			continue
		}
		config := expression.FromXML(doc)
		doc.Root.Walk(func(node *sysmonxml.Node) {
			for _, id := range mitre.IDsFromValue(node.AttrValue("name")) {
				tcounts[id]++
			}
		})
		for _, event := range config.Events {
			conditions := event.Expression.Conditions()
			modules[module] += len(conditions)
			e := events[event.Name]
			if e == nil {
				e = &ec{modules: map[string]bool{}}
				events[event.Name] = e
			}
			if event.Onmatch == "exclude" {
				e.ex += len(conditions)
			} else {
				e.in += len(conditions)
			}
			e.modules[module] = true
		}
		for _, id := range config.Techniques {
			if tmods[id] == nil {
				tmods[id] = map[string]bool{}
			}
			tmods[id][module] = true
		}
	}
	r := Report{Tactics: map[string]int{}, Modules: modules}
	for name, e := range events {
		mods := keys(e.modules)
		r.Events = append(r.Events, Event{Name: name, Include: e.in, Exclude: e.ex, Modules: mods})
		r.Include += e.in
		r.Exclude += e.ex
	}
	for id, mods := range tmods {
		name := id
		if t, ok := mitre.Lookup(id); ok {
			name = t.Name
		}
		tactics := mitre.Tactics(id)
		if len(tactics) == 0 {
			tactics = []string{"unmapped"}
		}
		for _, t := range tactics {
			r.Tactics[t]++
		}
		r.Techniques = append(r.Techniques, Technique{ID: id, Name: name, Tactics: tactics, Modules: keys(mods), Count: tcounts[id]})
	}
	sort.Slice(r.Events, func(i, j int) bool { return r.Events[i].Name < r.Events[j].Name })
	sort.Slice(r.Techniques, func(i, j int) bool { return r.Techniques[i].ID < r.Techniques[j].ID })
	return r
}

func WriteJSON(w io.Writer, r Report) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}
func WriteText(w io.Writer, r Report) error {
	if _, err := fmt.Fprintf(w, "filters: include=%d exclude=%d modules=%d techniques=%d\n", r.Include, r.Exclude, len(r.Modules), len(r.Techniques)); err != nil {
		return err
	}
	for _, e := range r.Events {
		if _, err := fmt.Fprintf(w, "%-24s include=%-5d exclude=%-5d modules=%d\n", e.Name, e.Include, e.Exclude, len(e.Modules)); err != nil {
			return err
		}
	}
	return nil
}
func WriteCSV(w io.Writer, r Report) error {
	c := csv.NewWriter(w)
	_ = c.Write([]string{"type", "id", "name", "include", "exclude", "tactics", "modules"})
	for _, e := range r.Events {
		_ = c.Write([]string{"event", e.Name, e.Name, strconv.Itoa(e.Include), strconv.Itoa(e.Exclude), "", strings.Join(e.Modules, ";")})
	}
	for _, t := range r.Techniques {
		_ = c.Write([]string{"technique", t.ID, t.Name, "", "", strings.Join(t.Tactics, ";"), strings.Join(t.Modules, ";")})
	}
	c.Flush()
	return c.Error()
}

type NavigatorOptions struct {
	Name          string
	Description   string
	Template      []byte
	AttackVersion string
}

const (
	navigatorDefaultAttackVersion = "18"
	navigatorApplicationVersion   = "5.3.2"
	navigatorLayerFormatVersion   = "4.5"
)

type NavigatorRemapping struct {
	From string
	To   string
}

var navigatorV18TechniqueRemappings = map[string]string{
	"T1685":     "T1562.001",
	"T1685.001": "T1562.002",
	"T1685.005": "T1070.001",
}

func WriteNavigator(w io.Writer, r Report) error {
	return WriteNavigatorWithOptions(w, r, NavigatorOptions{
		Name:        "Sysmon Modular coverage",
		Description: "ATT&CK technique coverage generated from Sysmon configuration metadata.",
	})
}

func WriteNavigatorWithOptions(w io.Writer, r Report, options NavigatorOptions) error {
	attackVersion := options.AttackVersion
	if attackVersion == "" {
		attackVersion = navigatorDefaultAttackVersion
	}
	if attackVersion != "18" && attackVersion != "19" {
		return fmt.Errorf("unsupported Navigator ATT&CK version %q", attackVersion)
	}
	type nt struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Comment     string `json:"comment,omitempty"`
	}
	layer := defaultNavigatorLayer()
	if len(options.Template) > 0 {
		var template map[string]any
		if err := json.Unmarshal(options.Template, &template); err != nil {
			return fmt.Errorf("decode Navigator template: %w", err)
		}
		if template == nil {
			return fmt.Errorf("decode Navigator template: root must be a JSON object")
		}
		mergeNavigatorMaps(layer, template)
	}
	versions, ok := layer["versions"].(map[string]any)
	if !ok {
		versions = map[string]any{}
		layer["versions"] = versions
	}
	versions["attack"] = attackVersion
	versions["navigator"] = navigatorApplicationVersion
	versions["layer"] = navigatorLayerFormatVersion
	if strings.TrimSpace(options.Name) != "" {
		layer["name"] = options.Name
	}
	layer["description"] = options.Description
	type aggregate struct {
		score   int
		modules map[string]bool
	}
	aggregates := map[string]*aggregate{}
	for _, t := range r.Techniques {
		id := navigatorTechniqueID(t.ID, attackVersion)
		a := aggregates[id]
		if a == nil {
			a = &aggregate{modules: map[string]bool{}}
			aggregates[id] = a
		}
		score := t.Count
		if score < 1 {
			score = len(t.Modules)
		}
		a.score += score
		for _, module := range t.Modules {
			a.modules[module] = true
		}
	}
	ids := make([]string, 0, len(aggregates))
	for id := range aggregates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	techniques := make([]nt, 0, len(ids))
	maxScore := 1
	for _, id := range ids {
		a := aggregates[id]
		if a.score > maxScore {
			maxScore = a.score
		}
		techniques = append(techniques, nt{id, a.score, strings.Join(keys(a.modules), ", ")})
	}
	layer["techniques"] = techniques
	if len(options.Template) == 0 {
		if gradient, ok := layer["gradient"].(map[string]any); ok {
			gradient["maxValue"] = maxScore
		}
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(layer)
}

func NavigatorRemappings(r Report, attackVersion string) []NavigatorRemapping {
	if attackVersion != "18" {
		return nil
	}
	var remappings []NavigatorRemapping
	for _, technique := range r.Techniques {
		if replacement, ok := navigatorV18TechniqueRemappings[technique.ID]; ok {
			remappings = append(remappings, NavigatorRemapping{From: technique.ID, To: replacement})
		}
	}
	sort.Slice(remappings, func(i, j int) bool { return remappings[i].From < remappings[j].From })
	return remappings
}

func navigatorTechniqueID(id, attackVersion string) string {
	if attackVersion == "18" {
		if replacement, ok := navigatorV18TechniqueRemappings[id]; ok {
			return replacement
		}
	}
	return id
}

func defaultNavigatorLayer() map[string]any {
	return map[string]any{
		"name": "Sysmon Modular coverage",
		"versions": map[string]any{
			"attack":    navigatorDefaultAttackVersion,
			"navigator": navigatorApplicationVersion,
			"layer":     navigatorLayerFormatVersion,
		},
		"domain":      "enterprise-attack",
		"description": "ATT&CK technique coverage generated from Sysmon configuration metadata.",
		"filters": map[string]any{
			"platforms": []string{"Windows"},
		},
		"sorting": 0,
		"layout": map[string]any{
			"layout": "side", "aggregateFunction": "average", "showID": false,
			"showName": true, "showAggregateScores": false, "countUnscored": false,
			"expandedSubtechniques": "none",
		},
		"hideDisabled": false,
		"techniques":   []any{},
		"gradient": map[string]any{
			"colors":   []string{"#18e8ff", "#37b6ff", "#1a60ff"},
			"minValue": 0, "maxValue": 1,
		},
		"legendItems":                   []any{},
		"metadata":                      []any{},
		"links":                         []any{},
		"showTacticRowBackground":       false,
		"tacticRowBackground":           "#dddddd",
		"selectTechniquesAcrossTactics": true,
		"selectSubtechniquesWithParent": false,
		"selectVisibleTechniques":       false,
	}
}

func mergeNavigatorMaps(target, source map[string]any) {
	for key, value := range source {
		sourceMap, sourceIsMap := value.(map[string]any)
		targetMap, targetIsMap := target[key].(map[string]any)
		if sourceIsMap && targetIsMap {
			mergeNavigatorMaps(targetMap, sourceMap)
			continue
		}
		target[key] = value
	}
}
func keys(m map[string]bool) []string {
	v := make([]string, 0, len(m))
	for k := range m {
		v = append(v, k)
	}
	sort.Strings(v)
	return v
}
