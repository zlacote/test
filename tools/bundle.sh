#!/bin/bash
# Assemble self-contained test scripts in dist/ from probe/*.sh.in templates.
# A line "@@AYANA_RUN_C@@" is replaced by launcher/ayana-run.c.
set -e
cd "$(dirname "$0")/.."
mkdir -p dist
for t in probe/*.sh.in; do
  o="dist/$(basename "${t%.in}")"
  awk -v src=launcher/ayana-run.c '
    $0 == "@@AYANA_RUN_C@@" { while ((getline l < src) > 0) print l; next }
    { print }' "$t" > "$o"
  bash -n "$o"
  echo "built $o"
done
