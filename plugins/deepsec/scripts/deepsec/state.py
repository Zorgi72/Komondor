"""On-disk state: FileRecord, RunMeta, project layout, atomic writes, locks."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STALE_LOCK_SECONDS = 3600  # 1 hour, mirrors upstream

IGNORE_DIR_NAMES = {
    ".git",
    "node_modules",
    ".grok",
    "target",
    "dist",
    "build",
    ".next",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "coverage",
    ".deepsec",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_relpath(path: str) -> str:
    p = path.replace("\\", "/").lstrip("/")
    parts = [x for x in p.split("/") if x and x != "."]
    if ".." in parts:
        raise ValueError(f"unsafe path: {path}")
    return "/".join(parts)


class DeepSecPaths:
    def __init__(self, workspace: Path, project_id: str):
        self.workspace = workspace.resolve()
        self.project_id = project_id
        self.data = self.workspace / "data" / project_id
        self.files = self.data / "files"
        self.runs = self.data / "runs"
        self.reports = self.data / "reports"
        self.project_json = self.data / "project.json"
        self.info_md = self.data / "INFO.md"
        self.setup_md = self.data / "SETUP.md"
        self.config_json = self.data / "config.json"
        self.workspace_config = self.workspace / "config.json"
        self.lock_file = self.data / ".process.lock"

    def ensure_layout(self) -> None:
        self.files.mkdir(parents=True, exist_ok=True)
        self.runs.mkdir(parents=True, exist_ok=True)
        self.reports.mkdir(parents=True, exist_ok=True)

    def file_record_path(self, file_path: str) -> Path:
        rel = safe_relpath(file_path)
        return self.files / f"{rel}.json"


def resolve_workspace(cwd: Path | None = None, data_dir: Path | None = None) -> Path:
    if data_dir is not None:
        return data_dir.resolve()
    base = (cwd or Path.cwd()).resolve()
    # Prefer existing .grok/deepsec walking up
    for p in [base, *base.parents]:
        candidate = p / ".grok" / "deepsec"
        if candidate.is_dir():
            return candidate
        if (p / ".git").exists() or (p / ".grok").is_dir():
            return p / ".grok" / "deepsec"
    return base / ".grok" / "deepsec"


def default_project_id(root: Path) -> str:
    name = root.resolve().name
    cleaned = "".join(c if c.isalnum() or c in "-_" else "-" for c in name).strip("-")
    return cleaned or "project"


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:16]}"


def empty_file_record(file_path: str, project_id: str) -> dict[str, Any]:
    return {
        "filePath": safe_relpath(file_path),
        "projectId": project_id,
        "candidates": [],
        "findings": [],
        "analysisHistory": [],
        "status": "pending",
        "lastScannedAt": None,
        "lastScannedRunId": None,
        "fileHash": None,
        "lockedByRunId": None,
        "lockedAt": None,
        "gitInfo": None,
    }


def load_file_record(paths: DeepSecPaths, file_path: str) -> dict[str, Any] | None:
    p = paths.file_record_path(file_path)
    if not p.is_file():
        return None
    return read_json(p)


def save_file_record(paths: DeepSecPaths, record: dict[str, Any]) -> None:
    atomic_write_json(paths.file_record_path(record["filePath"]), record)


def iter_file_records(paths: DeepSecPaths) -> list[dict[str, Any]]:
    if not paths.files.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for p in sorted(paths.files.rglob("*.json")):
        try:
            out.append(read_json(p))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def create_run_meta(
    paths: DeepSecPaths,
    *,
    run_type: str,
    root_path: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run: dict[str, Any] = {
        "runId": new_run_id(),
        "projectId": paths.project_id,
        "rootPath": str(Path(root_path).resolve()),
        "createdAt": utc_now(),
        "completedAt": None,
        "type": run_type,
        "phase": "running",
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "stats": {},
    }
    if extra:
        run.update(extra)
    atomic_write_json(paths.runs / f"{run['runId']}.json", run)
    return run


def complete_run(paths: DeepSecPaths, run: dict[str, Any], phase: str, stats: dict[str, Any] | None = None) -> None:
    run["phase"] = phase
    run["completedAt"] = utc_now()
    if stats:
        run["stats"] = {**run.get("stats", {}), **stats}
    atomic_write_json(paths.runs / f"{run['runId']}.json", run)


def load_run(paths: DeepSecPaths, run_id: str) -> dict[str, Any] | None:
    p = paths.runs / f"{run_id}.json"
    if not p.is_file():
        return None
    return read_json(p)


def list_runs(paths: DeepSecPaths) -> list[dict[str, Any]]:
    if not paths.runs.is_dir():
        return []
    runs = []
    for p in sorted(paths.runs.glob("*.json")):
        try:
            runs.append(read_json(p))
        except (OSError, json.JSONDecodeError):
            continue
    return runs


def acquire_process_lock(paths: DeepSecPaths, run_id: str) -> bool:
    """Exclusive lock via O_EXCL create. Returns False if held by live owner."""
    paths.data.mkdir(parents=True, exist_ok=True)
    payload = {
        "runId": run_id,
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "acquiredAt": utc_now(),
        "acquiredAtUnix": time.time(),
    }
    try:
        fd = os.open(str(paths.lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            os.write(fd, json.dumps(payload).encode())
        finally:
            os.close(fd)
        return True
    except FileExistsError:
        if reclaim_stale_lock(paths):
            return acquire_process_lock(paths, run_id)
        return False


def release_process_lock(paths: DeepSecPaths, run_id: str | None = None) -> None:
    if not paths.lock_file.exists():
        return
    try:
        data = read_json(paths.lock_file)
        if run_id and data.get("runId") != run_id:
            return
    except (OSError, json.JSONDecodeError):
        pass
    try:
        paths.lock_file.unlink()
    except OSError:
        pass


def reclaim_stale_lock(paths: DeepSecPaths) -> bool:
    if not paths.lock_file.exists():
        return False
    try:
        data = read_json(paths.lock_file)
    except (OSError, json.JSONDecodeError):
        paths.lock_file.unlink(missing_ok=True)
        return True
    run_id = data.get("runId")
    if run_id:
        run = load_run(paths, run_id)
        if run and run.get("phase") in ("done", "error"):
            paths.lock_file.unlink(missing_ok=True)
            return True
    pid = data.get("pid")
    host = data.get("hostname")
    if host == socket.gethostname() and isinstance(pid, int):
        try:
            os.kill(pid, 0)
        except OSError:
            paths.lock_file.unlink(missing_ok=True)
            return True
    acquired = data.get("acquiredAtUnix")
    if isinstance(acquired, (int, float)) and time.time() - acquired > STALE_LOCK_SECONDS:
        paths.lock_file.unlink(missing_ok=True)
        return True
    return False


def reclaim_stale_file_locks(paths: DeepSecPaths) -> int:
    """Clear processing locks whose run is dead/stale; set status back to pending."""
    n = 0
    for rec in iter_file_records(paths):
        if rec.get("status") != "processing" and not rec.get("lockedByRunId"):
            continue
        run_id = rec.get("lockedByRunId")
        reclaim = False
        if not run_id:
            reclaim = True
        else:
            run = load_run(paths, run_id)
            if not run or run.get("phase") in ("done", "error"):
                reclaim = True
            elif run.get("hostname") == socket.gethostname() and isinstance(run.get("pid"), int):
                try:
                    os.kill(run["pid"], 0)
                except OSError:
                    reclaim = True
            locked_at = rec.get("lockedAt")
            # ISO times: also reclaim if lockedAt older than STALE
            if not reclaim and isinstance(locked_at, str):
                try:
                    # rough: if run still running but file lock older than stale
                    run_created = run.get("createdAt") if run else None
                    if run and run.get("phase") == "running":
                        # use lock file age via run pid already checked
                        pass
                except Exception:
                    pass
        if reclaim:
            rec["status"] = "pending" if rec.get("status") == "processing" else rec.get("status", "pending")
            if rec.get("status") == "processing":
                rec["status"] = "pending"
            rec["lockedByRunId"] = None
            rec["lockedAt"] = None
            save_file_record(paths, rec)
            n += 1
    return n


def candidate_key(c: dict[str, Any]) -> str:
    lines = ",".join(str(x) for x in c.get("lineNumbers") or [])
    return f"{c.get('vulnSlug')}::{c.get('matchedPattern')}::{lines}"


def finding_key(f: dict[str, Any]) -> str:
    title = " ".join(str(f.get("title") or "").lower().split())
    return f"{f.get('vulnSlug')}::{title}"


def merge_candidates(existing: list[dict], new: list[dict]) -> list[dict]:
    by = {candidate_key(c): c for c in existing}
    for c in new:
        by[candidate_key(c)] = c
    return list(by.values())


def merge_findings(existing: list[dict], new: list[dict]) -> list[dict]:
    by = {finding_key(f): dict(f) for f in existing}
    for f in new:
        k = finding_key(f)
        if k in by:
            # preserve annotations
            merged = dict(by[k])
            for field in ("triage", "revalidation"):
                if field in merged and field not in f:
                    pass
                elif field in f:
                    merged[field] = f[field]
            for field, val in f.items():
                if field in ("triage", "revalidation") and field in merged and merged[field]:
                    continue
                if val is not None:
                    merged[field] = val
            by[k] = merged
        else:
            by[k] = dict(f)
    return list(by.values())


def load_workspace_config(workspace: Path) -> dict[str, Any]:
    p = workspace / "config.json"
    if p.is_file():
        try:
            return read_json(p)
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def load_project_config(paths: DeepSecPaths) -> dict[str, Any]:
    if paths.config_json.is_file():
        try:
            return read_json(paths.config_json)
        except (OSError, json.JSONDecodeError):
            return {}
    return {}
