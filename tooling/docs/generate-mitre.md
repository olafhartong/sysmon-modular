# `generate-mitre`

`generate-mitre` is a separate maintenance utility. It reads a MITRE Enterprise ATT&CK STIX bundle and rebuilds the Go table used for technique names, tactics, retirement state, and replacements.

Build or run it separately from `sysmon-modular`:

```bash
go build -o generate-mitre ./cmd/generate-mitre
```

Run the build from `tooling`; use `-o generate-mitre.exe` on Windows.

```text
generate-mitre --input <bundle.json> [--output <file>]
```

`--input <file>`

Selects the Enterprise ATT&CK STIX JSON bundle. This flag is required. The generator reads `attack-pattern` objects with valid `T####` or `T####.###` IDs and `mitre-attack` kill-chain phases. It also follows `revoked-by` relationships to record replacement techniques. A bundle with no Enterprise techniques is rejected.

`--output <file>`

Sets the generated Go file. The default is `internal/mitre/techniques_gen.go`, relative to the current directory. The generator overwrites this file directly and does not create missing parent directories.

The output is formatted as Go source. Its header records the source URL, SHA-256 of the exact input bundle, and the latest `modified` timestamp among included attack patterns. Duplicate technique IDs and malformed STIX objects cause failure.

## Example

From the `tooling` directory:

```bash
curl -L --fail \
  -o /tmp/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

go run ./cmd/generate-mitre \
  --input /tmp/enterprise-attack.json \
  --output internal/mitre/techniques_gen.go
```

To reproduce the currently embedded ATT&CK 19.1 table, select the versioned
bundle instead:

```bash
curl -L --fail \
  -o /tmp/enterprise-attack-19.1.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json
go run ./cmd/generate-mitre \
  --input /tmp/enterprise-attack-19.1.json \
  --output internal/mitre/techniques_gen.go
go test ./cmd/generate-mitre ./internal/mitre ./internal/coverage
```

Review the generated header, including the source checksum and latest
technique timestamp, when moving to a newer bundle.
