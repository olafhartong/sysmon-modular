# `fix-mitre`

`fix-mitre` reviews ATT&CK technique metadata in XML `name` attributes and repairs values that have an unambiguous correction. It can work interactively, apply every proposed fix, or report a dry run.

```text
sysmon-modular fix-mitre [flags]
```

At least one of `--path`, `--all`, or `--all-xml` is required. Duplicate selections are processed once.

`--path <file>`

Selects one XML file. Repeat the flag for more files.

`--all`

Selects module XML files directly inside numbered directories below `--base-path`.

`--all-xml`

Recursively selects all `.xml` files below `--base-path`, excluding `.git`.

`--base-path <directory>`

Sets the discovery root for `--all` and `--all-xml`.

`--dry-run`

Reports proposed changes but does not write any file. This also disables interactive prompting. Use it before a repository-wide repair to see how many values can be fixed and how many require manual work.

`--yes`

Applies all unambiguous fixes without prompting. Without `--yes` or `--dry-run`, the command prompts when standard input is a terminal. Press Enter or `a` to approve all remaining changes, `y` for one change, `n` to skip one, or `q` to stop.

When standard input is not a terminal, fix mode applies all unambiguous changes without prompting. Files with issues that cannot be corrected automatically are left for manual repair and cause exit code `4`.

Repairs use the embedded Enterprise ATT&CK catalogue: retired IDs with known
replacements are updated, `technique=` is corrected to `technique_id=`, and
stale `technique_name` values are replaced with current names. Incomplete
placeholders such as `technique_id=T,technique_name=` require manual review.
Interactive proposals show the file, line, old value and replacement.

## Examples

Preview repairs across repository modules:

```bash
./sysmon-modular fix-mitre --base-path .. --all --dry-run
```

Apply repairs to two files without prompts:

```bash
./sysmon-modular fix-mitre \
  --path ../first.xml \
  --path ../second.xml \
  --yes
```
