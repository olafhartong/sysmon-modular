#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_path=${1:-"$repo_root/sysmonconfig-mde-augment.xml"}
case "$output_path" in
  /*) ;;
  *) output_path="$PWD/$output_path" ;;
esac

tool_path=
for candidate in \
  "$repo_root/tooling/sysmon-modular" \
  "$repo_root/tooling/sysmon-modular.exe"; do
  if [ -x "$candidate" ]; then
    tool_path=$candidate
    break
  fi
done

run_tool() {
  if [ -n "$tool_path" ]; then
    "$tool_path" "$@"
  elif command -v sysmon-modular >/dev/null 2>&1; then
    sysmon-modular "$@"
  elif command -v go >/dev/null 2>&1; then
    go -C "$repo_root/tooling" run ./cmd/sysmon-modular "$@"
  else
    printf '%s\n' 'sysmon-modular was not found. Download a release binary into tooling/ or install Go.' >&2
    exit 127
  fi
}

run_tool merge \
  --base-path "$repo_root" \
  --template "$repo_root/templates/sysmon_template.xml" \
  --exclude-list "$script_dir/mde_covered_modules.txt" \
  --preserve-comments \
  --sysmon-version 15.21 \
  --unsupported exclude \
  --output "$output_path"

run_tool validate \
  --path "$output_path" \
  --sysmon-version 15.21

printf 'generated %s\n' "$output_path"
