# `generate-kql`

**NOTICE: This is an experimental feature, this will likely not alway produce great results yet. :)**

`generate-kql` converts supported Microsoft Defender XDR KQL filters into Sysmon module XML. It has two input modes. Single-file mode writes one module to `--output`. Directory mode scans files recursively and writes one module per selected query below `--output-dir`.

```text
sysmon-modular generate-kql (--kql <file> | --directory <directory>) [flags]
```

Supply exactly one of `--kql` and `--directory`.

## Input and output modes

`--kql <file>`

Reads one KQL query from a file. The command converts it to one XML document and writes that document through `--output`.

`--directory <directory>`

Recursively scans text files. Markdown files may contain several fenced KQL blocks, with nearby headings used to infer Defender or Sentinel context. Other text files are treated as direct queries when their contents look like KQL. Binary and invalid UTF-8 files are skipped.

`--output <file|->`

Sets the XML destination in single-file mode. The default is `-`, which writes to standard output. Directory mode does not use this flag.

`--output-dir <directory>`

Sets the destination root in directory mode. The default is `0_custom_configuration/generated_kql`. Generated files retain the input directory layout and use sanitized source and platform names. Single-file mode does not use this flag.

`--platform <defender|sentinel|all>`

Selects Markdown queries in directory mode. The default is `defender`. Queries marked for both platforms and queries whose platform cannot be inferred remain eligible. The aliases `defender-xdr`, `mde`, and `xdr` also select Defender. This flag does not filter single-file input.

The converter currently accepts queries starting from `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, or `DeviceImageLoadEvents`. Unsupported tables are skipped in directory mode and reported in the summary.

## Conversion policy

### Supported KQL

The exact subset supports literal `==`, `=~`, `in`, `in~`, `contains`,
`contains_any`, `contains_all`, `startswith` and `endswith` predicates on
fields with an event-specific Sysmon equivalent. Literal `let` arrays,
multiple `where` stages and nested `and`/`or` expressions with parentheses
are supported. Boolean precedence and grouping are preserved, with a limit
of 256 expanded branches.

KQL `has`, `has_any` and `has_all` use token matching, which is not equivalent
to Sysmon substring matching. Negation, computed predicates, unresolved lists,
unsupported fields, joins, aggregation and row-changing pipeline operators
also fall outside the exact subset. The command reports why input is rejected
or skipped. Only `where` stages create Sysmon filters; later projection and
display stages do not add conditions.

Every generated module is schema-validated before it is written. Directory
mode reports totals and the reason for each skipped query. Platform selection
does not add support for other event tables.

### Conversion flags

`--allow-lossy`

Allows conversion when the KQL contains a supported core filter but also has behavior that Sysmon cannot represent exactly. Without this flag, lossy queries are rejected in single-file mode and skipped in directory mode. With it, the command writes a fallback and prints the reasons for information loss. Review such output before deployment.

`--dedup`

Loads existing repository modules and marks generated conditions that already exist. For KQL, deduplication annotates conditions rather than removing them. The command fails if it finds no existing modules below `--base-path`.

The comparison includes the event, include/exclude scope, field, condition
operator and normalized value. The condition stays in the generated expression
with an XML comment identifying the existing module; the summary counts these
as `conditions_annotated`.

`--base-path <directory>`

Sets the repository root used by `--dedup` to discover modules in numbered directories. It has no effect when deduplication is off.

## Optional analyzer request

`--analyzer`

Sends each selected query to an external KQL analyzer before local conversion. Analyzer failures become warnings and do not stop conversion. The analyzer checks the original query. The local converter still decides whether it can produce Sysmon XML.

`--analyzer-url <url>`

Sets the HTTP endpoint. The default is `http://localhost:8080/api/analyze`. The command sends a JSON `POST` request with the query and analyzer settings. This flag is only used with `--analyzer`.

`--analyzer-environment <name>`

Sets the request's `environment` value. The default is `m365_with_sentinel`.

`--analyzer-profile <name>`

Sets the request's `parser_profile` value. The default is `current`.

`--analyzer-strict`

Sets `strict_mode` to true in the analyzer request. The default is false.

`--analyzer-nrt`

Asks the analyzer to check near-real-time compatibility by setting `check_nrt_compatibility` to true.

`--analyzer-timeout <duration>`

Sets the timeout for each analyzer request. The default is `15s`. Use Go duration notation such as `500ms`, `30s`, or `2m`.

## Examples

Convert one query to standard output:

```bash
./sysmon-modular generate-kql --kql ./query.kql
```

Convert Defender queries found below a documentation tree and annotate overlap with current modules:

```bash
./sysmon-modular generate-kql \
  --directory ./Hunting-Queries-Detection-Rules \
  --platform defender \
  --output-dir ../0_custom_configuration/generated_kql \
  --base-path .. \
  --dedup
```

Run analyzer checks with a longer request timeout:

```bash
./sysmon-modular generate-kql \
  --kql ./query.kql \
  --analyzer \
  --analyzer-strict \
  --analyzer-timeout 30s \
  --output ./generated.xml
```
