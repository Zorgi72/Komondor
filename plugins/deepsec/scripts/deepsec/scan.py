"""Filesystem walk + matcher scan + FileRecord upsert."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .matchers_engine import load_matchers, matcher_applies, run_matcher
from .state import (
    IGNORE_DIR_NAMES,
    DeepSecPaths,
    complete_run,
    create_run_meta,
    empty_file_record,
    load_file_record,
    load_project_config,
    merge_candidates,
    save_file_record,
    sha256_text,
    utc_now,
)


def should_skip_dir(name: str) -> bool:
    return name in IGNORE_DIR_NAMES or name.startswith(".")


def iter_source_files(root: Path, ignore_globs: list[str] | None = None) -> list[Path]:
    root = root.resolve()
    files: list[Path] = []
    ignore_globs = ignore_globs or []
    for dirpath, dirnames, filenames in os_walk_filtered(root):
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                continue
            if any(_simple_ignore(rel, g) for g in ignore_globs):
                continue
            # skip obvious binaries by extension
            if p.suffix.lower() in {
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".webp",
                ".ico",
                ".pdf",
                ".zip",
                ".gz",
                ".tar",
                ".woff",
                ".woff2",
                ".ttf",
                ".eot",
                ".mp4",
                ".mp3",
                ".so",
                ".dylib",
                ".dll",
                ".exe",
                ".o",
                ".a",
                ".class",
                ".pyc",
            }:
                continue
            files.append(p)
    return files


def os_walk_filtered(root: Path):
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        # also skip .grok/deepsec data under project
        yield dirpath, dirnames, filenames


def _simple_ignore(rel: str, glob: str) -> bool:
    from .matchers_engine import path_matches_glob

    g = glob.strip()
    if not g:
        return False
    if g.endswith("/"):
        return rel.startswith(g) or f"/{g}" in f"/{rel}/"
    return path_matches_glob(rel, g) or rel.startswith(g.rstrip("*"))


def read_text_safe(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None  # binary
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None


def scan_project(
    *,
    root: Path,
    paths: DeepSecPaths,
    matcher_dirs: list[Path],
    run_mode: str = "full",
    file_list: list[Path] | None = None,
    source_label: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    paths.ensure_layout()
    cfg = load_project_config(paths)
    ignore = list(cfg.get("ignorePaths") or [])
    matchers = load_matchers(matcher_dirs)
    if not matchers:
        raise RuntimeError(f"no matchers loaded from {matcher_dirs}")

    run = create_run_meta(
        paths,
        run_type="scan",
        root_path=str(root),
        extra={
            "scannerConfig": {
                "matcherSlugs": [m["slug"] for m in matchers],
                "mode": "files" if file_list is not None else "full",
                "source": source_label,
                "fileCount": len(file_list) if file_list is not None else None,
            }
        },
    )

    if file_list is not None:
        targets = [p.resolve() for p in file_list if p.exists() and p.is_file()]
    else:
        targets = iter_source_files(root, ignore)

    files_scanned = 0
    candidates_found = 0
    records_written = 0
    root = root.resolve()

    for path in targets:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        content = read_text_safe(path)
        if content is None:
            if file_list is not None:
                # still write empty record for explicit list
                rec = load_file_record(paths, rel) or empty_file_record(rel, paths.project_id)
                rec["lastScannedAt"] = utc_now()
                rec["lastScannedRunId"] = run["runId"]
                rec["fileHash"] = None
                save_file_record(paths, rec)
                records_written += 1
            continue

        new_cands: list[dict[str, Any]] = []
        for m in matchers:
            if not matcher_applies(m, rel):
                continue
            new_cands.extend(run_matcher(m, content))

        files_scanned += 1
        if on_progress and files_scanned % 50 == 0:
            on_progress(f"scanned {files_scanned} files…")

        if not new_cands and file_list is None:
            continue  # full scan only stores hits

        rec = load_file_record(paths, rel) or empty_file_record(rel, paths.project_id)
        before = len(rec.get("candidates") or [])
        rec["candidates"] = merge_candidates(rec.get("candidates") or [], new_cands)
        rec["lastScannedAt"] = utc_now()
        rec["lastScannedRunId"] = run["runId"]
        rec["fileHash"] = sha256_text(content)
        if "status" not in rec or rec["status"] is None:
            rec["status"] = "pending"
        # do not reset analyzed → pending
        if rec.get("status") not in ("analyzed", "processing", "pending", "error"):
            rec["status"] = "pending"
        if rec.get("status") not in ("analyzed", "processing") and not rec.get("findings"):
            rec["status"] = "pending"
        save_file_record(paths, rec)
        records_written += 1
        candidates_found += max(0, len(rec["candidates"]) - before) if before else len(new_cands)

    stats = {
        "filesScanned": files_scanned,
        "candidatesFound": candidates_found,
        "recordsWritten": records_written,
        "matcherCount": len(matchers),
    }
    complete_run(paths, run, "done", stats)
    return {"run": run, "stats": stats}
