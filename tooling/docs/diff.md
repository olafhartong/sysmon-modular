# `diff`

`diff` compares two Sysmon configurations by their parsed rule expressions and ATT&CK metadata. Formatting changes, element order, and other XML-only edits do not appear unless they change the extracted meaning.

```text
sysmon-modular diff --before <file> --after <file> [flags]
```

`--before <file>`

Selects the configuration before the change. This flag is required.

`--after <file>`

Selects the configuration after the change. This flag is required.

`--format <text|json>`

Sets the report format. The default is `text`.

Text output prints one line per semantic change with its change kind, impact, and normalized rule or technique. If there are no changes, it prints `no semantic changes`.

JSON output contains a `changes` array and a `summary` count map. Rule changes use `expression-added` or `expression-removed`. ATT&CK changes use `technique-added` or `technique-removed`, with `coverage-added` or `coverage-removed` impact labels.

Complete expressions retain their Boolean context, so an AND-to-OR change is
visible. Expression changes currently have `unknown` impact: an added or
removed expression alone does not establish whether effective collection
widens or narrows.

`--output <file|->`

Writes the report to a file. The default, `-`, writes to standard output.

## Examples

Read a semantic comparison in the terminal:

```bash
./sysmon-modular diff --before ./old.xml --after ./new.xml
```

Write machine-readable output:

```bash
./sysmon-modular diff \
  --before ./old.xml \
  --after ./new.xml \
  --format json \
  --output ./changes.json
```
