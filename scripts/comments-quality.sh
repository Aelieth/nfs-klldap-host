#!/usr/bin/env bash
# Comment quality gate: length, sentence integrity, block size.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
scratch="${SCRATCH:-/tmp/grok-goal-comments-audit}"
mkdir -p "$scratch"
out="$scratch/comments-audit.txt"
: >"$out"

srcs="nfs-klldap-config/src nfs-klldap-identity/src nfs-klldap-ui/src"
fail=0

section() {
  echo "=== $1 ===" >>"$out"
}

ok() {
  echo "OK: $1" | tee -a "$out"
}

fail_check() {
  echo "FAIL: $1" | tee -a "$out" >&2
  fail=1
}

# (a) No comment lines longer than 79 chars.
section "length >79"
if long=$(grep -rnE '^(\s*//|//!|# ).{80,}' --include='*.rs' $srcs 2>/dev/null || true); then
  if [[ -n "$long" ]]; then
    echo "$long" >>"$out"
    fail_check "length >79 ($(echo "$long" | wc -l) lines)"
  else
    ok "length >79"
  fi
else
  ok "length >79"
fi
echo >>"$out"

# (b) Sentence integrity patterns.
run_pat_check() {
  local name="$1" pat="$2"
  section "$name"
  local hits
  hits=$(grep -rnE "$pat" --include='*.rs' $srcs 2>/dev/null || true)
  if [[ -n "$hits" ]]; then
    echo "$hits" >>"$out"
    fail_check "$name ($(echo "$hits" | wc -l) lines)"
  else
    ok "$name"
  fi
  echo >>"$out"
}
run_pat_check "stray space before period" '^(\s*//|//!|///).* \.$'
run_pat_check "ellipsis truncation" '^(\s*//|//!|///).*\.\.\.$'
run_pat_check "mangled //!" '^// !'

# (c) Block size and lowercase continuation fragments.
section "doc block quality"
python3 - <<'PY' >>"$out" 2>&1
import re
import sys
from pathlib import Path

root = Path(".")
paths = [
    root / p
    for p in [
        "nfs-klldap-config/src",
        "nfs-klldap-identity/src",
        "nfs-klldap-ui/src",
    ]
]
doc_pat = re.compile(r"^(\s*)(//!|///)(.*)$")
fail = False


def check_file(f: Path) -> list[str]:
    lines = f.read_text().splitlines()
    issues: list[str] = []
    run = 0
    start = 0
    for i, line in enumerate(lines, 1):
        if doc_pat.match(line):
            if run == 0:
                start = i
            run += 1
        else:
            if run > 3:
                issues.append(f"block>3 {f}:{start}-{i - 1} ({run} lines)")
            run = 0
    if run > 3:
        issues.append(f"block>3 {f}:{start}-{len(lines)} ({run} lines)")

    i = 0
    while i < len(lines):
        m = doc_pat.match(lines[i])
        if not m:
            i += 1
            continue
        block: list[tuple[int, str]] = []
        while i < len(lines) and (dm := doc_pat.match(lines[i])):
            block.append((i + 1, dm.group(3).strip()))
            i += 1
        if len(block) > 1:
            prev_text = block[0][1]
            for ln, text in block[1:]:
                if (
                    text
                    and text[0].islower()
                    and not prev_text.rstrip().endswith((".", "!", "?", ":", "*/"))
                ):
                    issues.append(
                        f"lowercase_cont {f}:{ln} {text[:72]}"
                    )
                prev_text = text
    return issues


all_issues: list[str] = []
for base in paths:
    for f in sorted(base.rglob("*.rs")):
        all_issues.extend(check_file(f))

if all_issues:
    fail = True
    print(f"FAIL: doc block quality ({len(all_issues)} issues)")
    for issue in all_issues:
        print(issue)
else:
    print("OK: doc block quality")

sys.exit(1 if fail else 0)
PY
py_exit=$?
if [[ $py_exit -ne 0 ]]; then
  fail_check "doc block quality"
else
  ok "doc block quality"
fi
echo >>"$out"

echo "comments-quality: wrote $out"
exit "$fail"