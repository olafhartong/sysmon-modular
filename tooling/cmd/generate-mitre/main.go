package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"sort"
	"strings"
)

const sourceURL = "https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack"

var techniqueIDPattern = regexp.MustCompile(`^T\d{4}(?:\.\d{3})?$`)

type bundle struct {
	Objects []json.RawMessage `json:"objects"`
}

type stixObject struct {
	Type             string              `json:"type"`
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	Modified         string              `json:"modified"`
	Revoked          bool                `json:"revoked"`
	Deprecated       bool                `json:"x_mitre_deprecated"`
	RelationshipType string              `json:"relationship_type"`
	SourceRef        string              `json:"source_ref"`
	TargetRef        string              `json:"target_ref"`
	ExternalRefs     []externalReference `json:"external_references"`
	KillChainPhases  []killChainPhase    `json:"kill_chain_phases"`
}

type externalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type killChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type technique struct {
	Name        string
	Tactics     []string
	Revoked     bool
	Deprecated  bool
	Replacement string
}

func main() {
	input := flag.String("input", "", "MITRE Enterprise ATT&CK STIX bundle")
	output := flag.String("output", "internal/mitre/techniques_gen.go", "generated Go output")
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "generate-mitre requires --input")
		os.Exit(2)
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		fatal(err)
	}
	generated, err := generate(data)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, generated, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func generate(data []byte) ([]byte, error) {
	var source bundle
	if err := json.Unmarshal(data, &source); err != nil {
		return nil, fmt.Errorf("decode STIX bundle: %w", err)
	}
	objects := make([]stixObject, 0, len(source.Objects))
	techniques := map[string]technique{}
	stixToTechnique := map[string]string{}
	latestModified := ""
	for _, raw := range source.Objects {
		var object stixObject
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, fmt.Errorf("decode STIX object: %w", err)
		}
		objects = append(objects, object)
		if object.Type != "attack-pattern" {
			continue
		}
		id := externalTechniqueID(object.ExternalRefs)
		if id == "" {
			continue
		}
		if _, exists := techniques[id]; exists {
			return nil, fmt.Errorf("duplicate ATT&CK technique ID %s", id)
		}
		techniques[id] = technique{
			Name: object.Name, Tactics: tacticNames(object.KillChainPhases),
			Revoked: object.Revoked, Deprecated: object.Deprecated,
		}
		stixToTechnique[object.ID] = id
		if object.Modified > latestModified {
			latestModified = object.Modified
		}
	}
	for _, object := range objects {
		if object.Type != "relationship" || object.RelationshipType != "revoked-by" {
			continue
		}
		sourceID, sourceOK := stixToTechnique[object.SourceRef]
		targetID, targetOK := stixToTechnique[object.TargetRef]
		if !sourceOK || !targetOK {
			continue
		}
		item := techniques[sourceID]
		item.Replacement = targetID
		techniques[sourceID] = item
	}
	if len(techniques) == 0 {
		return nil, fmt.Errorf("STIX bundle contains no Enterprise ATT&CK techniques")
	}
	checksum := sha256.Sum256(data)
	return render(techniques, latestModified, hex.EncodeToString(checksum[:]))
}

func externalTechniqueID(references []externalReference) string {
	for _, reference := range references {
		id := strings.ToUpper(strings.TrimSpace(reference.ExternalID))
		if reference.SourceName == "mitre-attack" && techniqueIDPattern.MatchString(id) {
			return id
		}
	}
	return ""
}

func tacticNames(phases []killChainPhase) []string {
	seen := map[string]bool{}
	var tactics []string
	for _, phase := range phases {
		name := strings.TrimSpace(phase.PhaseName)
		if phase.KillChainName != "mitre-attack" || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		tactics = append(tactics, name)
	}
	sort.Strings(tactics)
	return tactics
}

func render(techniques map[string]technique, latestModified, checksum string) ([]byte, error) {
	ids := make([]string, 0, len(techniques))
	for id := range techniques {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var output strings.Builder
	output.WriteString("package mitre\n\n")
	output.WriteString("// Code generated from MITRE ATT&CK Enterprise STIX data; DO NOT EDIT.\n")
	fmt.Fprintf(&output, "// Source: %s\n", sourceURL)
	fmt.Fprintf(&output, "// Bundle SHA-256: %s\n", checksum)
	fmt.Fprintf(&output, "// Bundle latest attack-pattern modified timestamp: %s\n\n", latestModified)
	output.WriteString("var techniques = map[string]Technique{\n")
	for _, id := range ids {
		item := techniques[id]
		fmt.Fprintf(&output, "\t%q: {Name: %q", id, item.Name)
		if len(item.Tactics) > 0 {
			output.WriteString(", Tactics: []string{")
			for index, tactic := range item.Tactics {
				if index > 0 {
					output.WriteString(", ")
				}
				fmt.Fprintf(&output, "%q", tactic)
			}
			output.WriteString("}")
		}
		if item.Revoked {
			output.WriteString(", Revoked: true")
		}
		if item.Deprecated {
			output.WriteString(", Deprecated: true")
		}
		if item.Replacement != "" {
			fmt.Fprintf(&output, ", Replacement: %q", item.Replacement)
		}
		output.WriteString("},\n")
	}
	output.WriteString("}\n")
	formatted, err := format.Source([]byte(output.String()))
	if err != nil {
		return nil, fmt.Errorf("format generated Go: %w", err)
	}
	return formatted, nil
}
