# `list-rules`

`list-rules` prints the Sysmon module files that repository discovery would use. The output has one slash-separated path per line and is suitable for redirection into another tool.

```text
sysmon-modular list-rules [--base-path <directory>]
```

`--base-path <directory>`

Sets the repository root. The command inspects only immediate child directories whose names begin with a digit. It lists `*.xml` files directly inside those directories, sorts the full set by path, and prints paths relative to the base. It does not recurse into nested folders.

## Examples

Review discovered modules:

```bash
./sysmon-modular list-rules --base-path ..
```

Save the list:

```bash
./sysmon-modular list-rules --base-path .. > module-paths.txt
```
