#!/usr/bin/env bash
# Comment quality gate: length, block size, sentence integrity (//, ///, //!).
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

section "comment block quality"
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

comment_pat = re.compile(r"^(\s*)(//([^/!].*)|//!(.*)|///(.*))$")
doc_pat = re.compile(r"^(\s*)(//!|///)(.*)$")

# Doc-comment lines that are fragments, not sentences.
DOC_FRAGMENT = re.compile(
    r"^(token\s*->|getent\s*\(|Falls back\b|generate drives\b|Drives the\b|"
    r"Called before\b|Container translation\b|bind-mounted\b|and /settings\b|"
    r"WalkDir\b|Bind-root\b|nfs-utils\b|idmapd\.conf\b|ldap://\b|"
    r"host_path\s*→|std Mutex\b)",
    re.I,
)

fail = False


def comment_text(line: str) -> tuple[str, str] | None:
    m = comment_pat.match(line)
    if not m:
        return None
    if m.group(2).startswith("//!"):
        return ("doc", (m.group(4) or "").strip())
    if m.group(2).startswith("///"):
        return ("doc", (m.group(5) or "").strip())
    return ("line", (m.group(3) or "").strip())


def is_continuation_fragment(prev: str, text: str) -> bool:
    if not text or not text[0].islower():
        return False
    return not prev.rstrip().endswith((".", "!", "?", ":", "*/", ";"))


def doc_incomplete(text: str) -> bool:
    if not text:
        return False
    if DOC_FRAGMENT.search(text):
        return True
    # Lowercase doc opener (not e.g./i.e.) is a fragment.
    if text[0].islower() and not text.startswith(("e.g.", "i.e.", "etc.")):
        return True
    # Arrow shorthand without a verb.
    if "->" in text and not re.search(
        r"\b(is|are|maps?|keyed|returns?|yields?|points?)\b", text, re.I
    ):
        return True
    return False


def check_file(f: Path) -> list[str]:
    lines = f.read_text().splitlines()
    issues: list[str] = []

    run = 0
    start = 0
    for i, line in enumerate(lines, 1):
        if comment_pat.match(line):
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
        parsed = comment_text(lines[i])
        if parsed is None:
            i += 1
            continue
        block: list[tuple[int, str, str]] = []
        while i < len(lines) and (p := comment_text(lines[i])) is not None:
            block.append((i + 1, p[0], p[1]))
            i += 1
        if len(block) > 1:
            prev = block[0][2]
            for ln, kind, text in block[1:]:
                if is_continuation_fragment(prev, text):
                    issues.append(f"lowercase_cont {f}:{ln} {text[:72]}")
                prev = text

    for i, line in enumerate(lines, 1):
        parsed = comment_text(line)
        if parsed is None:
            continue
        kind, text = parsed
        if kind == "doc" and doc_incomplete(text):
            issues.append(f"doc_incomplete {f}:{i} {text[:72]}")

    return issues


all_issues: list[str] = []
for base in paths:
    for f in sorted(base.rglob("*.rs")):
        all_issues.extend(check_file(f))

if all_issues:
    fail = True
    print(f"FAIL: comment block quality ({len(all_issues)} issues)")
    for issue in all_issues:
        print(issue)
else:
    print("OK: comment block quality")

sys.exit(1 if fail else 0)
PY
py_exit=$?
if [[ $py_exit -ne 0 ]]; then
  fail_check "comment block quality"
else
  ok "comment block quality"
fi
echo >>"$out"

echo "comments-quality: wrote $out"
exit "$fail"