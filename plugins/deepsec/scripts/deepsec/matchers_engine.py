"""JSON matcher registry and regex application."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Map brace globs like **/*.{ts,tsx} to a simple suffix check.


def _flags_from_str(flags: str | None) -> int:
    fl = 0
    if not flags:
        return fl
    if "i" in flags:
        fl |= re.IGNORECASE
    if "m" in flags:
        fl |= re.MULTILINE
    if "s" in flags:
        fl |= re.DOTALL
    return fl


def load_matchers(matcher_dirs: list[Path]) -> list[dict[str, Any]]:
    by_slug: dict[str, dict[str, Any]] = {}
    for d in matcher_dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.json")):
            if p.name.startswith("_"):
                continue
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            slug = obj.get("slug")
            if not slug or not obj.get("patterns"):
                continue
            compiled = []
            for pat in obj["patterns"]:
                try:
                    rx = re.compile(pat["regex"], _flags_from_str(pat.get("flags")))
                except re.error:
                    continue
                compiled.append({"regex": rx, "label": pat.get("label") or slug, "raw": pat["regex"]})
            if not compiled:
                continue
            obj = dict(obj)
            obj["_compiled"] = compiled
            by_slug[slug] = obj
    return list(by_slug.values())


def expand_brace_pattern(pattern: str) -> list[str]:
    """Expand a single {a,b} brace group; leave other globs as-is."""
    m = re.search(r"\{([^{}]+)\}", pattern)
    if not m:
        return [pattern]
    alts = m.group(1).split(",")
    prefix = pattern[: m.start()]
    suffix = pattern[m.end() :]
    out: list[str] = []
    for a in alts:
        for e in expand_brace_pattern(prefix + a + suffix):
            out.append(e)
    return out


def path_matches_glob(rel_path: str, pattern: str) -> bool:
    """Minimal gitignore-style matcher for ** and * and brace groups."""
    rel = rel_path.replace("\\", "/")
    for pat in expand_brace_pattern(pattern):
        if _match_one(rel, pat):
            return True
    return False


def _match_one(rel: str, pattern: str) -> bool:
    # Convert glob to regex
    i = 0
    out = []
    while i < len(pattern):
        c = pattern[i]
        if c == "*" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            # **
            if i + 2 < len(pattern) and pattern[i + 2] == "/":
                out.append("(?:.*/)?")
                i += 3
            else:
                out.append(".*")
                i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == ".":
            out.append("\\.")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    rx = re.compile("^" + "".join(out) + "$")
    return bool(rx.match(rel))


def matcher_applies(matcher: dict[str, Any], rel_path: str) -> bool:
    patterns = matcher.get("filePatterns") or ["**/*"]
    return any(path_matches_glob(rel_path, p) for p in patterns)


def run_matcher(matcher: dict[str, Any], content: str) -> list[dict[str, Any]]:
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    matches: list[dict[str, Any]] = []
    slug = matcher["slug"]
    for pat in matcher.get("_compiled") or []:
        hit_lines: list[int] = []
        snippets: list[str] = []
        rx: re.Pattern = pat["regex"]
        for i, line in enumerate(lines):
            if rx.search(line):
                hit_lines.append(i + 1)
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                snippets.append("\n".join(lines[start:end]))
        if hit_lines:
            matches.append(
                {
                    "vulnSlug": slug,
                    "lineNumbers": hit_lines,
                    "snippet": snippets[0] if snippets else "",
                    "matchedPattern": pat["label"],
                }
            )
    return matches


def default_matcher_dir(plugin_root: Path | None = None) -> Path:
    if plugin_root is not None:
        return plugin_root / "scripts" / "matchers"
    # scripts/deepsec/ -> scripts/matchers
    return Path(__file__).resolve().parent.parent / "matchers"
