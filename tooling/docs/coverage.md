# `coverage`

`coverage` counts include and exclude conditions, maps conditions back to modules and events, and reports ATT&CK technique and tactic coverage found in rule metadata.

Names and tactics come from the embedded Enterprise ATT&CK 19.1 STIX bundle.
Techniques assigned to several tactics retain every assignment; `unmapped`
is reserved for unknown IDs or techniques without a tactic. Reports do not
need a live lookup. See [generate-mitre](generate-mitre.md) to update the
catalogue.

```text
sysmon-modular coverage [flags]
```

Supply at least one `--path`, use `--all`, or provide `--include-list`. `--path`
and `--all` may be combined. When `--include-list` is supplied, its entries
replace the direct selection. `--exclude-list` then removes matching inputs.

`--path <file>`

Adds a Sysmon configuration or module. Repeat it for multiple files. The report labels each input with its path relative to `--base-path` when possible.

`--all`

Adds all `*.xml` modules directly inside numbered directories below `--base-path`.

`--include-list <file>`

Reads a newline-delimited list of module paths. Blank lines and lines beginning
with `#` are ignored. Relative entries are resolved against `--base-path`.

`--exclude-list <file>`

Reads a newline-delimited list of module paths to remove from the selected
inputs. It uses the same path and comment rules as `--include-list`.

`--base-path <directory>`

Sets the module discovery root for `--all` and the reference path used to label input modules.

`--format <text|json|csv|navigator>`

Sets the output format. The default is `text`.

- `text` prints total include and exclude condition counts, module and technique totals, then one line per Sysmon event.
- `json` includes events, techniques, tactic counts, module condition counts, and overall include and exclude totals.
- `csv` writes event and technique rows with columns for IDs, names, counts, tactics, and modules.
- `navigator` writes a layer for ATT&CK Navigator 5.3.2 using layer file format 4.5. Each technique's score is the number of ATT&CK metadata occurrences, and its comment lists the modules that reference it.

`--attack-version <18|19>`

Sets the Enterprise ATT&CK version for Navigator output. The default is `18`
because the hosted Navigator 5.3.2 currently remains stuck loading ATT&CK 19
layers, including layers created by its own interface. When writing version 18,
the command applies these compatibility mappings and prints a message for each
one used:

| ATT&CK 19 | ATT&CK 18 |
| --- | --- |
| `T1685` | `T1562.001` |
| `T1685.001` | `T1562.002` |
| `T1685.005` | `T1070.001` |

Use `--attack-version 19` to keep the current IDs for another Navigator
deployment or after the hosted application fixes ATT&CK 19 loading. The
selected version replaces the ATT&CK version found in `--template`. This flag
requires `--format navigator`.

`--name <text>`

Sets the Navigator layer name. The default is `Sysmon Modular coverage`. This
flag requires `--format navigator`.

`--description <text>`

Sets the Navigator layer description. This flag requires `--format navigator`.

`--template <file>`

Uses an existing Navigator layer as a style and settings template. The command
retains its layout, filters, colors, legend, metadata, links, and other layer
settings. It replaces the template's name, description, and techniques. This
flag requires `--format navigator`. The repository template at
`attack_matrix/Sysmon-modular.json` is suitable for this option.

`--output <file|->`

Writes the report to a file. The default, `-`, writes to standard output.

## Examples

Summarize all repository modules:

```bash
./sysmon-modular coverage --base-path .. --all
```

Create an ATT&CK Navigator layer for selected modules:

```bash
./sysmon-modular coverage \
  --base-path .. \
  --path ../1_process_creation/include_living_off_the_land.xml \
  --path ../3_network_connection_initiated/include_native_windows_tools.xml \
  --format navigator \
  --output ./sysmon-coverage.json
```

Keep ATT&CK 19 IDs when the target Navigator supports them:

```bash
./sysmon-modular coverage \
  --base-path .. \
  --all \
  --format navigator \
  --attack-version 19 \
  --output ./sysmon-coverage-v19.json
```

Create a styled layer from a complete configuration:

```bash
./sysmon-modular coverage \
  --path ../sysmonconfig.xml \
  --format navigator \
  --template ../attack_matrix/Sysmon-modular.json \
  --name "Sysmon configuration coverage" \
  --description "ATT&CK coverage for the generated Sysmon configuration." \
  --output ../attack-navigator.json
```

Create a layer from include and exclude lists:

```bash
./sysmon-modular coverage \
  --base-path .. \
  --include-list ../0_custom_configuration/example_include_rules.txt \
  --exclude-list ../0_custom_configuration/example_exclude_rules.txt \
  --format navigator \
  --output ../selected-coverage.json
```
