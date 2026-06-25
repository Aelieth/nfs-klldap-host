#!/usr/bin/env python3
"""Merge consecutive comment-only lines into <=3 complete sentences (<=79 cols)."""
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


def extract_text(line: str) -> str:
    m = COMMENT_ONLY.match(line)
    if not m:
        return ""
    body = m.group(2)
    if body.startswith("///"):
        return body[3:].strip()
    if body.startswith("//!"):
        return body[3:].strip()
    return body[2:].strip()


def prefix_kind(indent: str, first_line: str) -> str:
    if "///" in first_line:
        return indent + "/// "
    if "//!" in first_line:
        return indent + "//! "
    return indent + "// "


def wrap_comment(prefix: str, text: str, max_len: int = 79) -> list[str]:
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    if not text[0].isupper():
        text = text[0].upper() + text[1:]
    if text[-1] not in ".!?":
        text += "."
    plen = len(prefix)
    if plen + len(text) <= max_len:
        return [prefix + text]
    # Split into two lines near midpoint word boundary.
    target = max_len - plen
    mid = len(text) // 2
    split = text.rfind(" ", 0, mid + 20)
    if split < 20:
        split = text.find(" ", mid)
    if split < 0:
        return [prefix + text[: target]]
    a, b = text[:split].strip(), text[split:].strip()
    if b and b[0].islower():
        b = b[0].upper() + b[1:]
    out = []
    if plen + len(a) <= max_len:
        out.append(prefix + a)
    else:
        out.append(prefix + a[: target])
    if plen + len(b) <= max_len:
        out.append(prefix + b)
    else:
        out.append(prefix + b[: max_len - plen])
    return out[:3]


def needs_merge(block: list[str]) -> bool:
    if len(block) > 3:
        return True
    texts = [extract_text(l) for l in block]
    for i in range(1, len(texts)):
        prev, cur = texts[i - 1], texts[i]
        if cur and cur[0].islower() and not prev.rstrip().endswith((".", "!", "?", ":", ";")):
            return True
    return False


def process_file(path: Path) -> bool:
    lines = path.read_text().splitlines()
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        m = COMMENT_ONLY.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        block = [lines[i]]
        j = i + 1
        while j < len(lines) and COMMENT_ONLY.match(lines[j]):
            block.append(lines[j])
            j += 1
        if needs_merge(block):
            indent = COMMENT_ONLY.match(block[0]).group(1)
            prefix = prefix_kind(indent, block[0])
            merged = " ".join(t for t in (extract_text(l) for l in block) if t)
            out.extend(wrap_comment(prefix, merged))
            changed = True
        else:
            out.extend(block)
        i = j
    if changed:
        path.write_text("\n".join(out) + "\n")
    return changed


def main() -> int:
    n = 0
    for base in SRCS:
        for f in sorted(base.rglob("*.rs")):
            if process_file(f):
                n += 1
                print(f"merged: {f.relative_to(ROOT)}")
    print(f"done: {n} files updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())