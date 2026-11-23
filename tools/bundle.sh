#!/bin/bash
# Assemble self-contained scripts in dist/ from probe/*.sh.in templates.
# A line "@@INCLUDE <path>@@" is replaced by the content of <path>
# (relative to the repository root).
set -e
cd "$(dirname "$0")/.."
mkdir -p dist
for t in probe/*.sh.in; do
  o="dist/$(basename "${t%.in}")"
  awk '
    /^@@INCLUDE .*@@$/ {
      f = substr($0, 11, length($0) - 12)
      if ((getline l < f) <= 0) { print "missing include: " f > "/dev/stderr"; exit 1 }
      print l
      while ((getline l < f) > 0) print l
      close(f)
      next
    }
    { print }' "$t" > "$o"
  bash -n "$o"
  echo "built $o"
done
