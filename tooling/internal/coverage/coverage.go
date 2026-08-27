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
	modules := map[string]int{}
	for module, doc := range docs {
		config := expression.FromXML(doc)
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
		r.Techniques = append(r.Techniques, Technique{ID: id, Name: name, Tactics: tactics, Modules: keys(mods)})
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
func WriteNavigator(w io.Writer, r Report) error {
	type nt struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Comment     string `json:"comment,omitempty"`
	}
	layer := struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Domain     string `json:"domain"`
		Techniques []nt   `json:"techniques"`
	}{"Sysmon Modular coverage", "4.5", "enterprise-attack", nil}
	for _, t := range r.Techniques {
		layer.Techniques = append(layer.Techniques, nt{t.ID, len(t.Modules), strings.Join(t.Modules, ", ")})
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(layer)
}
func keys(m map[string]bool) []string {
	v := make([]string, 0, len(m))
	for k := range m {
		v = append(v, k)
	}
	sort.Strings(v)
	return v
}
