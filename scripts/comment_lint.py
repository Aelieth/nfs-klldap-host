#!/usr/bin/env python3
"""Single source of truth for Rust comment quality in audited trees."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRCS = [
    ROOT / "nfs-klldap-config/src",
    ROOT / "nfs-klldap-identity/src",
    ROOT / "nfs-klldap-ui/src",
]

COMMENT_ONLY = re.compile(r"^(\s*)((//([^/!].*)|//!(.*)|///(.*)))$")
INLINE_COMMENT = re.compile(r"^(.*?)(\s)//([^/!].*)$")
START_OK = re.compile(r"^[A-Z(]")
END_OK = re.compile(r"[.!?]$")
MAX_LEN = 79
MAX_DOC_LINES = 2
MAX_MODULE_DOC_LINES = 3

VERBS = re.compile(
    r"\b("
    r"is|are|was|were|be|been|being|has|have|had|do|does|did|"
    r"returns?|holds?|stores?|builds?|creates?|resolves?|prevents?|"
    r"generates?|reads?|writes?|runs?|skips?|applies?|overrides?|"
    r"displays?|matches?|loads?|keeps?|maps?|uses?|enables?|disables?|"
    r"provides?|performs?|handles?|serves?|contains?|includes?|"
    r"requires?|supports?|allows?|ensures?|checks?|validates?|"
    r"when|true|false"
    r")\b",
    re.I,
)

MECHANICAL = re.compile(
    r"^This (field|map|is|names|constructs|builds|OnceLock)\b",
    re.I,
)
COLON_LABEL = re.compile(r"^[A-Z][A-Za-z0-9_/ -]{0,40}: ")
INCOMPLETE_END = re.compile(r"\b(before|after|during|without|with|for|to|from|on|in|the|an|or|and)\.$", re.I)
FRAGMENT_WORD = re.compile(r"^[A-Z][a-z]+( [a-z]+)?\.$")


def extract_body(line: str) -> tuple[str, str, str] | None:
    m = COMMENT_ONLY.match(line)
    if not m:
        return None
    indent = m.group(1)
    body = m.group(2)
    if body.startswith("///"):
        return (indent, "doc", body[3:].strip())
    if body.startswith("//!"):
        return (indent, "doc", body[3:].strip())
    return (indent, "line", body[2:].strip())


def word_count(text: str) -> int:
    return len(re.findall(r"[A-Za-z0-9']+", text))


def has_verb(text: str) -> bool:
    return bool(VERBS.search(text))


def quality_ok(text: str, kind: str) -> tuple[bool, str]:
    if not text:
        return False, "empty"
    if not sentence_ok(text):
        return False, "sentence"
    if MECHANICAL.match(text):
        return False, "mechanical_this"
    if COLON_LABEL.match(text) and not has_verb(text):
        return False, "colon_label"
    if FRAGMENT_WORD.match(text):
        return False, "fragment"
    if INCOMPLETE_END.search(text):
        return False, "incomplete_end"
    wc = word_count(text)
    if wc < 4 and not has_verb(text):
        return False, "too_short"
    if ";" in text:
        parts = [p.strip() for p in text.split(";") if p.strip()]
        if any(not has_verb(p) or word_count(p) < 3 for p in parts):
            return False, "semicolon_fragment"
    if kind == "doc" and text.startswith("Optional ") and not has_verb(text):
        return False, "optional_shorthand"
    if kind == "doc" and text.startswith("Test-only ") and not has_verb(text):
        return False, "test_shorthand"
    return True, ""


def sentence_ok(text: str) -> bool:
    if not text:
        return False
    return bool(START_OK.match(text) and END_OK.search(text.rstrip()))


def check_file(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    rel = path.relative_to(ROOT)
    issues: list[str] = []
    i = 0
    while i < len(lines):
        parsed = extract_body(lines[i])
        if parsed is None:
            m = INLINE_COMMENT.match(lines[i])
            if m and m.group(3).strip():
                text = m.group(3).strip()
                if len(lines[i]) > MAX_LEN:
                    issues.append(f"length>{MAX_LEN} {rel}:{i + 1}")
                ok, why = quality_ok(text, "line")
                if not ok:
                    issues.append(f"{why} {rel}:{i + 1} {text[:60]}")
            i += 1
            continue

        block_start = i + 1
        block: list[tuple[int, str, str, bool]] = []
        while i < len(lines) and (p := extract_body(lines[i])) is not None:
            is_module = lines[i].lstrip().startswith("//!")
            block.append((i + 1, p[1], p[2], is_module))
            i += 1

        kinds = {k for _, k, _, _ in block}
        if "line" in kinds and len(block) > 1:
            issues.append(
                f"multi_line_block {rel}:{block_start}-{block[-1][0]} ({len(block)} // lines)"
            )

        module_block = any(m for _, _, _, m in block)
        max_doc = MAX_MODULE_DOC_LINES if module_block else MAX_DOC_LINES
        if "doc" in kinds and len(block) > max_doc:
            issues.append(
                f"doc_block>{max_doc} {rel}:{block_start}-{block[-1][0]} ({len(block)} lines)"
            )

        for idx, (ln, kind, text, _) in enumerate(block):
            if len(lines[ln - 1]) > MAX_LEN:
                issues.append(f"length>{MAX_LEN} {rel}:{ln}")
            if not text:
                issues.append(f"empty {rel}:{ln}")
                continue
            ok, why = quality_ok(text, kind)
            if not ok:
                issues.append(f"{why} {rel}:{ln} {text[:72]}")
            if idx > 0 and word_count(text) < 4:
                issues.append(f"fragment_continuation {rel}:{ln} {text[:72]}")

    return issues


def lint_all(crate: str | None = None) -> list[str]:
    bases = SRCS if not crate else [ROOT / crate]
    issues: list[str] = []
    for base in bases:
        if not base.exists():
            continue
        for f in sorted(base.rglob("*.rs")):
            issues.extend(check_file(f))
    return issues


def main() -> int:
    crate = sys.argv[1] if len(sys.argv) > 1 else None
    issues = lint_all(crate)
    if issues:
        print(f"FAIL: {len(issues)} comment issues")
        for issue in issues:
            print(issue)
        return 1
    print("OK: all comments pass quality rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())