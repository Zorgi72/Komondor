#!/usr/bin/env python3
"""DeepSec CLI — pure Python entry point for Grok Build plugin.

Usage:
  python3 deepsec_cli.py <command> [options]

Commands: help, init, scan, process, revalidate, triage, enrich,
          export, status, resume, report
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure package import when run as script
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from deepsec.enrich import detect_github_url, enrich_project, git_diff_files  # noqa: E402
from deepsec.export_fmt import export_json, export_md, export_md_dir, status_summary, write_report  # noqa: E402
from deepsec.matchers_engine import default_matcher_dir  # noqa: E402
from deepsec.process import (  # noqa: E402
    DEFAULT_CORE_PROMPT,
    apply_revalidation,
    apply_triage,
    build_process_prompt,
    claim_batch,
    pending_records,
    run_process_heuristic,
    run_process_with_response,
)
from deepsec.scan import scan_project  # noqa: E402
from deepsec.state import (  # noqa: E402
    DeepSecPaths,
    acquire_process_lock,
    atomic_write_json,
    atomic_write_text,
    complete_run,
    create_run_meta,
    default_project_id,
    load_file_record,
    reclaim_stale_file_locks,
    release_process_lock,
    resolve_canonical_root,
    resolve_workspace,
    utc_now,
)

PLUGIN_ROOT = SCRIPTS.parent
INFO_TEMPLATE = """# Project security context

## What this service does

(Describe the product and trust boundaries.)

## Tech stack

(Languages, frameworks, data stores.)

## Auth model

(How users/services authenticate and authorize.)

## Sensitive data

(What must not leak.)

## Known hotspots

(Areas worth extra scrutiny.)
"""

SETUP_TEMPLATE = """# DeepSec setup for this project

1. Fill in INFO.md with accurate architecture context.
2. Run scan: `python3 scripts/deepsec_cli.py scan --root <repo>`
3. Run process (AI or heuristic): `… process --heuristic` or use Grok `/deepsec process`.
4. Export findings: `… export --format md-dir --out ./findings`.
"""

HELP = """DeepSec — AI-assisted vulnerability pipeline for Grok Build

Commands:
  init                 Scaffold .grok/deepsec workspace
  scan [path]          Regex matcher scan (no AI)
  process              Investigate pending files (AI / --heuristic / --inject-response)
  process --diff       Scan+process git-changed files only
  revalidate           TP/FP/fixed/uncertain verdicts on findings
  triage               P0/P1/P2/skip classification
  enrich               Attach git committer metadata
  export               Export findings (md|json|md-dir)
  status               Pipeline status summary
  resume               Reclaim locks and continue process
  report               Write reports/report.md + report.json
  help                 This message

State: .grok/deepsec/data/<projectId>/
Docs:  plugin README + docs/deepsec-port-design.md in the fork
"""


def cmd_help(_: argparse.Namespace) -> int:
    print(HELP)
    return 0


def _paths_from_args(args: argparse.Namespace, root: Path) -> DeepSecPaths:
    workspace = resolve_workspace(
        cwd=Path(args.cwd) if getattr(args, "cwd", None) else Path.cwd(),
        data_dir=Path(args.data_dir) if getattr(args, "data_dir", None) else None,
    )
    pid = getattr(args, "project_id", None) or default_project_id(root)
    return DeepSecPaths(workspace, pid)


def _resolve_root(args: argparse.Namespace, paths: DeepSecPaths | None = None) -> tuple[Path, DeepSecPaths]:
    """Resolve project root pinned to project.json rootPath when present."""
    cli_root = Path(args.root).resolve() if getattr(args, "root", None) else None
    # Need project_id before full pin; use cli_root or cwd for id default
    probe_root = cli_root or Path.cwd().resolve()
    if paths is None:
        paths = _paths_from_args(args, probe_root)
    try:
        root = resolve_canonical_root(paths, cli_root)
    except ValueError as e:
        raise SystemExit(f"error: {e}") from e
    # Re-bind paths with stable project id from probe (project_id flag wins)
    paths = _paths_from_args(args, root)
    return root, paths


def cmd_init(args: argparse.Namespace) -> int:
    import shutil

    cli_root = Path(args.root or Path.cwd()).resolve()
    workspace = resolve_workspace(
        cwd=cli_root,
        data_dir=Path(args.data_dir) if args.data_dir else cli_root / ".grok" / "deepsec",
    )
    pid = args.project_id or default_project_id(cli_root)
    paths = DeepSecPaths(workspace, pid)
    paths.ensure_layout()

    force = bool(getattr(args, "force", False))
    existing: dict | None = None
    if paths.project_json.exists():
        try:
            existing = json.loads(paths.project_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = None

    if existing and existing.get("rootPath"):
        stored = Path(existing["rootPath"]).resolve()
        if stored != cli_root and not force:
            print(
                f"error: project already initialized with rootPath {stored}\n"
                f"  Refusing to retarget to {cli_root} without --force "
                f"(would create duplicate FileRecords with different relative paths).\n"
                f"  Use: deepsec_cli.py init --root {stored}\n"
                f"  Or retarget (clears files/ + runs/): deepsec_cli.py init --force --root {cli_root}",
                file=sys.stderr,
            )
            return 2
        if stored != cli_root and force:
            # Retarget: clear scan/process state so relative paths stay unique
            for sub in (paths.files, paths.runs):
                if sub.is_dir():
                    shutil.rmtree(sub)
            paths.files.mkdir(parents=True, exist_ok=True)
            paths.runs.mkdir(parents=True, exist_ok=True)
            print(
                f"note: --force retarget {stored} → {cli_root}; cleared files/ and runs/",
                file=sys.stderr,
            )

    root = cli_root
    if existing and existing.get("rootPath") and not force:
        # Preserve stored rootPath (and createdAt); only fill missing githubUrl
        root = Path(existing["rootPath"]).resolve()
        project = dict(existing)
        project["projectId"] = pid
        project["rootPath"] = str(root)
        if not project.get("githubUrl"):
            project["githubUrl"] = detect_github_url(root)
    else:
        project = {
            "projectId": pid,
            "rootPath": str(root),
            "createdAt": (existing or {}).get("createdAt") or utc_now(),
            "githubUrl": detect_github_url(root),
        }

    atomic_write_json(paths.project_json, project)
    if not paths.info_md.exists() or force:
        atomic_write_text(paths.info_md, INFO_TEMPLATE)
    if not paths.setup_md.exists() or force:
        atomic_write_text(paths.setup_md, SETUP_TEMPLATE)
    ws_cfg = workspace / "config.json"
    if not ws_cfg.exists():
        atomic_write_json(ws_cfg, {"defaultProjectId": pid, "version": 1})
    gi = workspace / ".gitignore"
    if not gi.exists():
        atomic_write_text(
            gi,
            "data/*/files/\ndata/*/runs/\ndata/*/reports/\ndata/*/.process.lock\n",
        )
    print(f"Initialized DeepSec workspace at {workspace}")
    print(f"  projectId: {pid}")
    print(f"  root:      {root}")
    print(f"  INFO.md:   {paths.info_md}")
    print("Next: edit INFO.md, then run: deepsec_cli.py scan --root", root)
    return 0


def _ensure_inited(paths: DeepSecPaths) -> None:
    if not paths.data.is_dir() or not paths.project_json.is_file():
        raise SystemExit(
            f"DeepSec not initialized at {paths.workspace}. Run: deepsec_cli.py init --root <path>"
        )


def cmd_scan(args: argparse.Namespace) -> int:
    # --root is the project root (pinned to project.json once init'd).
    # Optional positional path scopes the walk without changing path relativity.
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    if not paths.project_json.is_file():
        args.root = str(cli_root)
        args.force = False
        cmd_init(args)
        paths = _paths_from_args(args, cli_root)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)

    scope = Path(args.path).resolve() if getattr(args, "path", None) else root
    if getattr(args, "path", None):
        if not scope.exists():
            print(
                f"error: scan path does not exist: {scope}\n"
                f"  Project root: {root}\n"
                f"  Hint: pass an existing file or directory under the project root.",
                file=sys.stderr,
            )
            return 2
        try:
            scope.relative_to(root)
        except ValueError:
            print(f"error: scan path {scope} is outside project root {root}", file=sys.stderr)
            return 2

    matcher_dirs = [default_matcher_dir(PLUGIN_ROOT)]
    extra = paths.workspace / "matchers"
    if extra.is_dir():
        matcher_dirs.append(extra)

    def progress(msg: str) -> None:
        print(msg, file=sys.stderr)

    # When scoped, pass explicit file list relative to project root
    file_list = None
    source_label = None
    if scope != root:
        from deepsec.scan import iter_source_files

        if scope.is_file():
            file_list = [scope]
            source_label = f"path:{scope.relative_to(root).as_posix()}"
        else:
            file_list = iter_source_files(scope)
            source_label = f"path:{scope.relative_to(root).as_posix()}"

    result = scan_project(
        root=root,
        paths=paths,
        matcher_dirs=matcher_dirs,
        file_list=file_list,
        source_label=source_label,
        on_progress=progress,
    )
    s = result["stats"]
    print(
        f"scan complete: files={s['filesScanned']} candidates={s['candidatesFound']} "
        f"records={s['recordsWritten']} matchers={s['matcherCount']} run={result['run']['runId']}"
    )
    if s.get("skippedPermission"):
        print(
            f"note: {s['skippedPermission']} file(s) skipped due to permissions (see stderr warnings)",
            file=sys.stderr,
        )
    return 0


def cmd_process(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)

    if args.diff is not None:
        base = args.diff if args.diff != "" and args.diff is not True else "HEAD"
        if args.diff is True or args.diff == "":
            base = "HEAD"
        try:
            files = git_diff_files(root, str(base))
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        matcher_dirs = [default_matcher_dir(PLUGIN_ROOT)]
        scan_project(
            root=root,
            paths=paths,
            matcher_dirs=matcher_dirs,
            file_list=files,
            source_label=f"git-diff:{base}",
        )
        print(f"diff scan: {len(files)} files from git diff {base}")

    if not acquire_process_lock(paths, "process-cli"):
        print("error: another process holds the DeepSec lock; try resume later", file=sys.stderr)
        return 3
    try:
        if args.inject_response:
            text = Path(args.inject_response).read_text(encoding="utf-8")
            result = run_process_with_response(
                paths, root=root, response_text=text, limit=args.limit, model="injected"
            )
        elif args.heuristic or args.prompt_only:
            if args.prompt_only:
                reclaim_stale_file_locks(paths)
                pending = pending_records(paths)
                if args.limit:
                    pending = pending[: args.limit]
                info = paths.info_md.read_text(encoding="utf-8") if paths.info_md.is_file() else ""
                # claim for prompt package without completing
                run = create_run_meta(paths, run_type="process", root_path=str(root))
                claimed = claim_batch(paths, pending, run["runId"], args.limit)
                prompt = build_process_prompt(
                    info_md=info, records=claimed, root=root, core_prompt=DEFAULT_CORE_PROMPT
                )
                out = paths.runs / f"{run['runId']}.prompt.md"
                atomic_write_text(out, prompt)
                # leave claimed for apply-response; or release if user only wants prompt
                if args.release_claims:
                    for r in claimed:
                        rec = load_file_record(paths, r["filePath"])
                        if rec:
                            rec["status"] = "pending"
                            rec["lockedByRunId"] = None
                            rec["lockedAt"] = None
                            from deepsec.state import save_file_record

                            save_file_record(paths, rec)
                    complete_run(paths, run, "done", {"promptOnly": True})
                print(str(out))
                print(f"claimed {len(claimed)} files for investigation (run {run['runId']})")
                return 0
            result = run_process_heuristic(paths, root=root, limit=args.limit)
        else:
            # default offline-safe: heuristic with message
            print(
                "note: no --inject-response; using --heuristic candidate synthesis "
                "(Grok skill path should inject real agent JSON)",
                file=sys.stderr,
            )
            result = run_process_heuristic(paths, root=root, limit=args.limit)
        s = result.get("stats") or {}
        print(f"process complete: {s} run={result['run']['runId']}")
        return 0
    finally:
        release_process_lock(paths)


def cmd_revalidate(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)
    text = Path(args.inject_response).read_text(encoding="utf-8") if args.inject_response else None
    result = apply_revalidation(
        paths,
        root=root,
        response_text=text,
        force=args.force,
        limit=args.limit,
        heuristic=text is None or args.heuristic,
    )
    print(f"revalidate complete: {result['stats']}")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)
    text = Path(args.inject_response).read_text(encoding="utf-8") if args.inject_response else None
    result = apply_triage(
        paths,
        root=root,
        response_text=text,
        force=args.force,
        limit=args.limit,
        heuristic=text is None or args.heuristic,
        min_severity=args.min_severity,
    )
    print(f"triage complete: {result['stats']}")
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)
    result = enrich_project(paths, root, force=args.force)
    print(f"enrich complete: {result}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)
    fmt = (args.format or "json").lower()
    out = Path(args.out) if args.out else None
    if fmt == "json":
        out = out or Path("deepsec-findings.json")
        p = export_json(paths, out)
    elif fmt == "md":
        out = out or Path("deepsec-findings.md")
        p = export_md(paths, out)
    elif fmt in ("md-dir", "mddir", "md_dir"):
        out = out or Path("deepsec-findings")
        p = export_md_dir(paths, out)
    else:
        print(f"error: unknown format {fmt}", file=sys.stderr)
        return 2
    print(f"exported {fmt} → {p}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    if paths.project_json.is_file():
        try:
            root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        paths = _paths_from_args(args, root)
    else:
        root = cli_root
    if not paths.data.is_dir():
        print(f"DeepSec not initialized under {paths.workspace}")
        print("Run: deepsec_cli.py init")
        return 0
    s = status_summary(paths)
    print(f"project:    {s['projectId']}")
    print(f"data:       {s['dataDir']}")
    print(f"files:      {s['filesTotal']}  {s['files']}")
    print(f"candidates: {s['candidatesTotal']}")
    print(f"findings:   {s['findingsTotal']}  {s['findingsBySeverity']}")
    if paths.lock_file.exists():
        print(f"lock:       HELD ({paths.lock_file})")
    else:
        print("lock:       free")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    # ensure process uses pinned root
    args.root = str(root)
    paths = _paths_from_args(args, root)
    n = reclaim_stale_file_locks(paths)
    print(f"reclaimed {n} stale file locks")
    args.heuristic = True
    args.inject_response = None
    args.diff = None
    args.prompt_only = False
    args.release_claims = False
    return cmd_process(args)


def cmd_report(args: argparse.Namespace) -> int:
    cli_root = Path(args.root or Path.cwd()).resolve()
    paths = _paths_from_args(args, cli_root)
    _ensure_inited(paths)
    try:
        root = resolve_canonical_root(paths, Path(args.root).resolve() if args.root else cli_root)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = _paths_from_args(args, root)
    outs = write_report(paths)
    print(f"report: {outs['md']}")
    print(f"report: {outs['json']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deepsec", description="DeepSec for Grok Build")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=None, help="Project source root")
    common.add_argument("--project-id", default=None)
    common.add_argument("--data-dir", default=None, help="Override .grok/deepsec path")
    common.add_argument("--cwd", default=None)
    # also accept globals on the root parser (before subcommand)
    p.add_argument("--root", default=None)
    p.add_argument("--project-id", default=None)
    p.add_argument("--data-dir", default=None)
    p.add_argument("--cwd", default=None)
    sub = p.add_subparsers(dest="command")

    sub.add_parser("help", aliases=["--help-text"], parents=[common])

    s = sub.add_parser("init", parents=[common])
    s.add_argument("--force", action="store_true")

    s = sub.add_parser("scan", parents=[common])
    s.add_argument("path", nargs="?", default=None)

    s = sub.add_parser("process", parents=[common])
    s.add_argument("--diff", nargs="?", const=True, default=None)
    s.add_argument("--limit", type=int, default=None)
    s.add_argument("--inject-response", default=None)
    s.add_argument("--heuristic", action="store_true")
    s.add_argument("--prompt-only", action="store_true")
    s.add_argument("--release-claims", action="store_true")

    s = sub.add_parser("revalidate", parents=[common])
    s.add_argument("--force", action="store_true")
    s.add_argument("--limit", type=int, default=None)
    s.add_argument("--inject-response", default=None)
    s.add_argument("--heuristic", action="store_true")

    s = sub.add_parser("triage", parents=[common])
    s.add_argument("--force", action="store_true")
    s.add_argument("--limit", type=int, default=None)
    s.add_argument("--min-severity", default=None)
    s.add_argument("--inject-response", default=None)
    s.add_argument("--heuristic", action="store_true")

    s = sub.add_parser("enrich", parents=[common])
    s.add_argument("--force", action="store_true")

    s = sub.add_parser("export", parents=[common])
    s.add_argument("--format", default="json")
    s.add_argument("--out", default=None)

    s = sub.add_parser("status", parents=[common])

    s = sub.add_parser("resume", parents=[common])
    s.add_argument("--limit", type=int, default=None)

    s = sub.add_parser("report", parents=[common])

    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(HELP)
        return 0
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command or args.command in ("help", "--help-text"):
        return cmd_help(args)
    dispatch = {
        "init": cmd_init,
        "scan": cmd_scan,
        "process": cmd_process,
        "revalidate": cmd_revalidate,
        "triage": cmd_triage,
        "enrich": cmd_enrich,
        "export": cmd_export,
        "status": cmd_status,
        "resume": cmd_resume,
        "report": cmd_report,
    }
    # Defaults for optional attrs not on every subcommand
    for attr, default in (
        ("force", False),
        ("limit", None),
        ("inject_response", None),
        ("heuristic", False),
        ("diff", None),
        ("prompt_only", False),
        ("release_claims", False),
        ("format", "json"),
        ("out", None),
        ("min_severity", None),
        ("path", None),
    ):
        if not hasattr(args, attr):
            setattr(args, attr, default)
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
