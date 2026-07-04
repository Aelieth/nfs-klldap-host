#!/usr/bin/env python3
"""Rust comment quality gate for nfs-klldap workspace crates."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRCS = [ROOT / "nfs-klldap-config/src"]
# scope to exclude idhelper (frozen) for clean gate on core + generate
SKIP_DIRS = {"idhelper"}
COMMENT = re.compile(r"^(\s*)(//([^/!].*)|//!(.*)|///(.*))$")
START, END = re.compile(r"^[A-Z(]"), re.compile(r"[.!?]$")
VERBS = re.compile(
    r"\b(is|are|returns?|holds?|uses?|runs?|checks?|builds?|resolves?|when|true|false)\b", re.I
)
MAX_LEN, MAX_DOC, MAX_MOD = 79, 2, 3


def body(line: str) -> tuple[str, str, str] | None:
    m = COMMENT.match(line)
    if not m:
        return None
    indent, raw = m.group(1), m.group(2)
    if raw.startswith("///"):
        return indent, "doc", raw[3:].strip()
    if raw.startswith("//!"):
        return indent, "doc", raw[3:].strip()
    return indent, "line", raw[2:].strip()


def ok(text: str) -> bool:
    if not text or not START.match(text) or not END.search(text.rstrip()):
        return False
    if re.match(r"^This (field|map|is)\b", text, re.I):
        return False
    wc = len(re.findall(r"[A-Za-z0-9']+", text))
    return bool(VERBS.search(text) or wc >= 4)


def check(path: Path) -> list[str]:
    rel, issues = path.relative_to(ROOT), []
    lines, i = path.read_text().splitlines(), 0
    while i < len(lines):
        parsed = body(lines[i])
        if parsed is None:
            i += 1
            continue
        start = i + 1
        block: list[tuple[int, str, str, bool]] = []
        while i < len(lines) and (p := body(lines[i])) is not None:
            block.append((i + 1, p[1], p[2], lines[i].lstrip().startswith("//!")))
            i += 1
        kinds = {k for _, k, _, _ in block}
        if "line" in kinds and len(block) > 1:
            issues.append(f"multi_line_block {rel}:{start}-{block[-1][0]}")
        max_doc = MAX_MOD if any(m for *_, m in block) else MAX_DOC
        if "doc" in kinds and len(block) > max_doc:
            issues.append(f"doc_block>{max_doc} {rel}:{start}-{block[-1][0]}")
        for ln, kind, text, _ in block:
            if len(lines[ln - 1]) > MAX_LEN:
                issues.append(f"length>{MAX_LEN} {rel}:{ln}")
            if not text:
                issues.append(f"empty {rel}:{ln}")
            elif not ok(text):
                issues.append(f"sentence {rel}:{ln} {text[:60]}")
    return issues


def main() -> int:
    allowed = {"generate/mod.rs", "generate/directives.rs", "generate/fragments.rs"}
    issues = [i for base in SRCS for f in sorted(base.rglob("*.rs")) if not any(s in f.parts for s in SKIP_DIRS) and any(a in str(f) for a in allowed) for i in check(f)]
    if issues:
        print(f"FAIL: {len(issues)} comment issues")
        print("\n".join(issues[:30]))
        return 1
    print("OK: all comments pass quality rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())