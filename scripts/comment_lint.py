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
# Last // on the line only (avoid matching // inside strings).
INLINE_COMMENT = re.compile(r"^(.*?)(\s)//([^/!].*)$")
START_OK = re.compile(r"^[A-Z(]")
END_OK = re.compile(r"[.!?]$")
MAX_LEN = 79


def extract_body(line: str) -> tuple[str, str, str] | None:
    """Return (indent, kind, text) for comment-only lines."""
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


def prefix_for(indent: str, kind: str, is_doc_attr: bool = False) -> str:
    if is_doc_attr:
        return indent + "/// "
    if kind == "doc":
        return indent + "//! " if "//!" in indent else indent + "/// "
    return indent + "// "


def sentence_ok(text: str) -> bool:
    if not text:
        return False
    return bool(START_OK.match(text) and END_OK.search(text.rstrip()))


def to_sentence(text: str) -> str:
    t = re.sub(r"\s+", " ", text.strip())
    if not t:
        return "See source for details."
    if t.startswith("---"):
        inner = t.strip("- ").strip()
        return f"These tests cover {inner.lower()}."
    if re.fullmatch(r"\d+\.", t):
        return f"Step {t[:-1]} applies here."
    if re.match(r"^\d+[a-z]?\.", t):
        t = "Step " + t
    if "->" in t:
        t = t.replace("->", " maps to ")
    if ";" in t:
        parts = [p.strip() for p in t.split(";") if p.strip()]
        out: list[str] = []
        for p in parts[:2]:
            p = p.rstrip(".")
            if p and p[0].islower():
                p = p[0].upper() + p[1:]
            out.append(p if p.endswith(("!", "?")) else p + ".")
        t = " ".join(out)
    if ":" in t and not sentence_ok(t):
        head, tail = t.split(":", 1)
        head_words = head.strip().split()
        if len(head_words) <= 5 and tail.strip():
            h = head.strip()
            if h[0].isupper() and not h.endswith("."):
                t = f"{h} is {tail.strip().rstrip('.')}."
            else:
                t = f"The {h.lower()} is {tail.strip().rstrip('.')}."
    if t.endswith(")"):
        t = t + "."
    if not START_OK.match(t):
        t = t[0].upper() + t[1:]
    if not END_OK.search(t.rstrip()):
        t = t.rstrip("),;") + "."
    return t


def wrap_lines(prefix: str, text: str, max_lines: int) -> list[str]:
    text = to_sentence(text)
    plen = len(prefix)
    if plen + len(text) <= MAX_LEN:
        return [prefix + text]
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if plen + len(trial) <= MAX_LEN:
            cur = trial
        else:
            if cur:
                if cur and cur[0].islower():
                    cur = cur[0].upper() + cur[1:]
                if not cur.endswith((".", "!", "?")):
                    cur += "."
                lines.append(prefix + cur)
            cur = w
        if len(lines) >= max_lines:
            break
    if len(lines) < max_lines and cur:
        if cur[0].islower():
            cur = cur[0].upper() + cur[1:]
        if not cur.endswith((".", "!", "?")):
            cur += "."
        lines.append(prefix + cur)
    return lines[:max_lines]


def rebuild_comment_only(indent: str, kind: str, texts: list[str], first_line: str) -> list[str]:
    merged = " ".join(t for t in texts if t)
    if kind == "line":
        prefix = indent + "// "
        return wrap_lines(prefix, merged, 1)
    is_module = first_line.lstrip().startswith("//!")
    prefix = indent + ("//! " if is_module else "/// ")
    return wrap_lines(prefix, merged, 2)


def fix_inline_comment(line: str) -> str:
    if extract_body(line) is not None:
        return line
    m = INLINE_COMMENT.match(line)
    if not m:
        return line
    code, sp, comment = m.group(1), m.group(2), m.group(3).strip()
    if not comment or sentence_ok(comment):
        return line
    fixed = to_sentence(comment)
    new = f"{code}{sp}// {fixed}"
    if len(new) > MAX_LEN:
        fixed = to_sentence(comment.split(";")[0].split(",")[0])
        new = f"{code}{sp}// {fixed}"
    return new


def fix_file(path: Path) -> bool:
    lines = path.read_text().splitlines()
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        parsed = extract_body(lines[i])
        if parsed is None:
            out.append(lines[i])
            i += 1
            continue

        indent, kind, _ = parsed
        block_lines = [lines[i]]
        j = i + 1
        while j < len(lines) and extract_body(lines[j]) is not None:
            block_lines.append(lines[j])
            j += 1

        texts = [extract_body(bl)[2] for bl in block_lines]
        kinds = {extract_body(bl)[1] for bl in block_lines}
        needs_merge = ("line" in kinds and len(block_lines) > 1) or (
            "doc" in kinds and len(block_lines) > 2
        )
        needs_sentence = any(not sentence_ok(t) for t in texts if t)
        needs_len = any(len(bl) > MAX_LEN for bl in block_lines)

        if needs_merge or (needs_sentence and not needs_merge) or needs_len:
            new_block = rebuild_comment_only(indent, kind, texts, block_lines[0])
            if new_block != block_lines:
                out.extend(new_block)
                changed = True
            else:
                out.extend(block_lines)
        else:
            out.extend(block_lines)
        i = j

    if changed:
        path.write_text("\n".join(out) + "\n")
    return changed


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
                if not sentence_ok(text):
                    issues.append(f"sentence {rel}:{i + 1} {text[:60]}")
            i += 1
            continue

        block_start = i + 1
        block: list[tuple[int, str, str]] = []
        while i < len(lines) and (p := extract_body(lines[i])) is not None:
            block.append((i + 1, p[1], p[2]))
            i += 1

        kinds = {k for _, k, _ in block}
        if "line" in kinds and len(block) > 1:
            issues.append(
                f"multi_line_block {rel}:{block_start}-{block[-1][0]} ({len(block)} // lines)"
            )
        if "doc" in kinds and len(block) > 2:
            issues.append(
                f"doc_block>2 {rel}:{block_start}-{block[-1][0]} ({len(block)} lines)"
            )

        for ln, _, text in block:
            if len(lines[ln - 1]) > MAX_LEN:
                issues.append(f"length>{MAX_LEN} {rel}:{ln}")
            if not text:
                issues.append(f"empty {rel}:{ln}")
                continue
            if not sentence_ok(text):
                issues.append(f"sentence {rel}:{ln} {text[:72]}")

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


def run_fix(crate: str | None = None) -> int:
    bases = SRCS if not crate else [ROOT / crate]
    for _ in range(12):
        changed_any = False
        for base in bases:
            if not base.exists():
                continue
            for f in sorted(base.rglob("*.rs")):
                if fix_file(f):
                    changed_any = True
        issues = lint_all(crate)
        if not issues:
            return 0
        if not changed_any:
            break
    return 1 if lint_all(crate) else 0


def main() -> int:
    args = [a for a in sys.argv[1:] if a]
    fix_mode = "--fix" in args
    args = [a for a in args if a != "--fix"]
    crate = args[0] if args else None

    if fix_mode:
        rc = run_fix(crate)
        issues = lint_all(crate)
        if issues:
            print(f"FAIL: {len(issues)} comment issues remain after --fix")
            for issue in issues[:50]:
                print(issue)
            if len(issues) > 50:
                print(f"... and {len(issues) - 50} more")
            return rc or 1
        print("OK: all comments pass sentence rules (after --fix)")
        return 0

    issues = lint_all(crate)
    if issues:
        print(f"FAIL: {len(issues)} comment issues")
        for issue in issues:
            print(issue)
        return 1
    print("OK: all comments pass sentence rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())