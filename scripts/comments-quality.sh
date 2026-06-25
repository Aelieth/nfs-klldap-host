#!/usr/bin/env bash
# Dual comment quality gate: line length + sentence integrity.
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

# (b) Sentence integrity.
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

# (c) Optional advisory: >6 consecutive //! or /// (struct docs often use 4-6).
section "consecutive doc lines >6 (advisory)"
python3 - <<'PY' >>"$out" 2>&1 || true
import re
from pathlib import Path
root = Path(".")
paths = [root / p for p in ["nfs-klldap-config/src", "nfs-klldap-identity/src", "nfs-klldap-ui/src"]]
pat = re.compile(r"^(\s*)(//!|///)")
bad = []
for base in paths:
    for f in base.rglob("*.rs"):
        lines = f.read_text().splitlines()
        run = 0
        start = 0
        for i, line in enumerate(lines, 1):
            if pat.match(line):
                if run == 0:
                    start = i
                run += 1
            else:
                if run > 6:
                    bad.append(f"{f}:{start}-{i-1} ({run} lines)")
                run = 0
        if run > 6:
            bad.append(f"{f}:{start}-{len(lines)} ({run} lines)")
if bad:
    print("WARN:", len(bad), "blocks")
    for b in bad[:20]:
        print(b)
else:
    print("OK: no excessive consecutive doc blocks")
PY

echo "comments-quality: wrote $out"
exit "$fail"