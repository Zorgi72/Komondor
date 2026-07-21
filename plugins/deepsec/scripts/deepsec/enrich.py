"""Git committer enrichment (graceful without git)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .state import DeepSecPaths, iter_file_records, save_file_record, utc_now


def git_available(root: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.returncode == 0 and "true" in (r.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        return False


def recent_committers(root: Path, file_path: str, limit: int = 5) -> list[dict[str, str]]:
    try:
        r = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "log",
                f"-n{limit}",
                "--pretty=format:%an|%ae|%aI",
                "--",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    out = []
    seen = set()
    for line in (r.stdout or "").splitlines():
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        name, email, date = parts
        key = (name, email)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "email": email, "date": date})
    return out


def detect_github_url(root: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    url = (r.stdout or "").strip()
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@"):
        # git@github.com:owner/repo
        url = url.replace(":", "/", 1).replace("git@", "https://", 1)
    if "github.com" in url:
        return url.rstrip("/") + "/blob/HEAD"
    return None


def enrich_project(paths: DeepSecPaths, root: Path, *, force: bool = False) -> dict[str, Any]:
    if not git_available(root):
        return {"enriched": 0, "skipped": "no git repository", "git": False}
    n = 0
    for rec in iter_file_records(paths):
        if not rec.get("findings"):
            continue
        if rec.get("gitInfo") and not force:
            continue
        committers = recent_committers(root, rec["filePath"])
        rec["gitInfo"] = {
            "recentCommitters": committers,
            "enrichedAt": utc_now(),
        }
        save_file_record(paths, rec)
        n += 1
    return {"enriched": n, "git": True}


def git_diff_files(root: Path, base: str = "HEAD") -> list[Path]:
    if not git_available(root):
        raise RuntimeError("git is required for --diff mode (not a git repository)")
    # unstaged + staged + commits vs base when base != working tree
    r = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", base],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if r.returncode != 0:
        # try base...HEAD
        r = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", f"{base}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    if r.returncode != 0:
        raise RuntimeError(f"git diff failed: {r.stderr.strip() or r.stdout}")
    files = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        p = root / line
        if p.is_file():
            files.append(p)
    return files
