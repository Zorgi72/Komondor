"""Process / revalidate / triage: claim, parse agent JSON, merge findings."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .state import (
    DeepSecPaths,
    complete_run,
    create_run_meta,
    finding_key,
    iter_file_records,
    load_file_record,
    merge_findings,
    reclaim_stale_file_locks,
    save_file_record,
    utc_now,
)


def extract_json_payload(text: str) -> Any:
    """Extract JSON array/object from model text (fenced or raw)."""
    text = text.strip()
    # fenced
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.I)
    if m:
        candidate = m.group(1).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    # raw array/object
    for start_char, end_char in (("[", "]"), ("{", "}")):
        start = text.find(start_char)
        end = text.rfind(end_char)
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError("wasn't a parseable JSON findings array")


def normalize_process_results(payload: Any, batch_paths: list[str]) -> list[dict[str, Any]]:
    """Map agent payload to [{filePath, findings}] for each batch path."""
    if isinstance(payload, dict) and "results" in payload:
        payload = payload["results"]
    if isinstance(payload, dict) and "filePath" in payload:
        payload = [payload]
    if not isinstance(payload, list):
        raise ValueError("process response must be a JSON array")

    by_path: dict[str, list[dict]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        fp = item.get("filePath") or item.get("path")
        if not fp:
            continue
        fp = str(fp).replace("\\", "/").lstrip("./")
        findings = item.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        cleaned = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            cleaned.append(
                {
                    "severity": str(f.get("severity") or "MEDIUM").upper(),
                    "vulnSlug": f.get("vulnSlug") or f.get("slug") or "other-unknown",
                    "title": f.get("title") or "Untitled finding",
                    "description": f.get("description") or "",
                    "lineNumbers": f.get("lineNumbers") or f.get("lines") or [],
                    "recommendation": f.get("recommendation") or "",
                    "confidence": f.get("confidence") or "medium",
                }
            )
        by_path[fp] = cleaned

    out = []
    for bp in batch_paths:
        key = bp.replace("\\", "/").lstrip("./")
        # fuzzy match basename
        findings = by_path.get(key)
        if findings is None:
            for k, v in by_path.items():
                if k.endswith(key) or key.endswith(k):
                    findings = v
                    break
        out.append({"filePath": key, "findings": findings if findings is not None else []})
    return out


def pending_records(paths: DeepSecPaths, *, include_error: bool = True) -> list[dict[str, Any]]:
    reclaim_stale_file_locks(paths)
    out = []
    for r in iter_file_records(paths):
        st = r.get("status")
        if st == "pending" or (include_error and st == "error"):
            out.append(r)
        elif st == "processing" and not r.get("lockedByRunId"):
            out.append(r)
    # priority paths first
    return out


def claim_batch(
    paths: DeepSecPaths,
    records: list[dict[str, Any]],
    run_id: str,
    limit: int | None,
) -> list[dict[str, Any]]:
    claimed = []
    for rec in records:
        if limit is not None and len(claimed) >= limit:
            break
        rec = load_file_record(paths, rec["filePath"]) or rec
        if rec.get("status") == "analyzed" and rec.get("lockedByRunId") is None:
            continue
        rec["status"] = "processing"
        rec["lockedByRunId"] = run_id
        rec["lockedAt"] = utc_now()
        save_file_record(paths, rec)
        claimed.append(rec)
    return claimed


def apply_process_results(
    paths: DeepSecPaths,
    *,
    run: dict[str, Any],
    results: list[dict[str, Any]],
    agent_type: str = "grok",
    model: str = "injected",
) -> dict[str, Any]:
    findings_count = 0
    for item in results:
        fp = item["filePath"]
        rec = load_file_record(paths, fp)
        if rec is None:
            continue
        new_findings = item.get("findings") or []
        rec["findings"] = merge_findings(rec.get("findings") or [], new_findings)
        findings_count += len(new_findings)
        rec["analysisHistory"] = list(rec.get("analysisHistory") or []) + [
            {
                "runId": run["runId"],
                "investigatedAt": utc_now(),
                "durationMs": 0,
                "agentType": agent_type,
                "model": model,
                "findingCount": len(new_findings),
                "phase": "process",
            }
        ]
        rec["status"] = "analyzed"
        rec["lockedByRunId"] = None
        rec["lockedAt"] = None
        save_file_record(paths, rec)
    return {"findingsCount": findings_count}


def mark_batch_error(paths: DeepSecPaths, file_paths: list[str], run_id: str, reason: str) -> None:
    for fp in file_paths:
        rec = load_file_record(paths, fp)
        if not rec:
            continue
        rec["status"] = "error"
        rec["lockedByRunId"] = None
        rec["lockedAt"] = None
        rec["lastError"] = reason
        save_file_record(paths, rec)


def build_process_prompt(
    *,
    info_md: str,
    records: list[dict[str, Any]],
    root: Path,
    core_prompt: str,
) -> str:
    parts = [core_prompt.strip(), "", "## Project context (INFO.md)", info_md.strip() or "(empty)", "", "## Target files"]
    for rec in records:
        fp = rec["filePath"]
        abs_path = root / fp
        body = ""
        try:
            body = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = "(unreadable)"
        cands = rec.get("candidates") or []
        cand_lines = "\n".join(
            f"- {c.get('vulnSlug')} @ {c.get('lineNumbers')}: {c.get('matchedPattern')}" for c in cands
        )
        parts.append(f"### {fp}\n**Candidates:**\n{cand_lines or '(none)'}\n\n```\n{body}\n```\n")
    parts.append(
        """## Output format

Return ONLY a JSON array (optionally in a ```json fence):
[
  {
    "filePath": "relative/path",
    "findings": [
      {
        "severity": "CRITICAL|HIGH|MEDIUM|LOW|HIGH_BUG|BUG",
        "vulnSlug": "sql-injection",
        "title": "one sentence",
        "description": "full explanation",
        "lineNumbers": [1, 2],
        "recommendation": "fix advice",
        "confidence": "high|medium|low"
      }
    ]
  }
]
If a file has no real issues, return findings: [].
"""
    )
    return "\n".join(parts)


def run_process_with_response(
    paths: DeepSecPaths,
    *,
    root: Path,
    response_text: str,
    limit: int | None = None,
    invocation_mode: str = "scan",
    source: str | None = None,
    agent_type: str = "grok",
    model: str = "injected",
) -> dict[str, Any]:
    paths.ensure_layout()
    run = create_run_meta(
        paths,
        run_type="process",
        root_path=str(root),
        extra={
            "processorConfig": {
                "agentType": agent_type,
                "model": model,
                "modelConfig": {},
                "invocationMode": invocation_mode,
                "source": source,
            }
        },
    )
    pending = pending_records(paths)
    claimed = claim_batch(paths, pending, run["runId"], limit)
    if not claimed:
        complete_run(paths, run, "done", {"filesProcessed": 0, "findingsCount": 0})
        return {"run": run, "stats": {"filesProcessed": 0, "findingsCount": 0}, "message": "nothing pending"}

    batch_paths = [r["filePath"] for r in claimed]
    try:
        payload = extract_json_payload(response_text)
        results = normalize_process_results(payload, batch_paths)
        stats = apply_process_results(paths, run=run, results=results, agent_type=agent_type, model=model)
        stats["filesProcessed"] = len(claimed)
        complete_run(paths, run, "done", stats)
        return {"run": run, "stats": stats}
    except Exception as e:
        mark_batch_error(paths, batch_paths, run["runId"], str(e))
        complete_run(paths, run, "error", {"error": str(e), "filesProcessed": 0})
        raise


def synthesize_findings_from_candidates(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic heuristic process for offline demos/tests (not a model)."""
    results = []
    for rec in records:
        findings = []
        for c in rec.get("candidates") or []:
            slug = c.get("vulnSlug") or "other"
            findings.append(
                {
                    "severity": _slug_severity(slug),
                    "vulnSlug": slug,
                    "title": f"Possible {slug} at lines {c.get('lineNumbers')}",
                    "description": f"Matcher hit: {c.get('matchedPattern')}\n\n```\n{c.get('snippet','')}\n```",
                    "lineNumbers": c.get("lineNumbers") or [],
                    "recommendation": f"Review and fix potential {slug}.",
                    "confidence": "medium",
                }
            )
        # dedupe by finding key within file
        by = {}
        for f in findings:
            by[finding_key(f)] = f
        results.append({"filePath": rec["filePath"], "findings": list(by.values())})
    return results


def _slug_severity(slug: str) -> str:
    high = {"rce", "sql-injection", "auth-bypass", "ssrf", "secrets-exposure", "path-traversal"}
    med = {"xss", "open-redirect", "insecure-crypto", "dangerous-html", "missing-auth"}
    if slug in high:
        return "HIGH"
    if slug in med:
        return "MEDIUM"
    return "LOW"


def run_process_heuristic(paths: DeepSecPaths, *, root: Path, limit: int | None = None) -> dict[str, Any]:
    """Offline process using candidate→finding synthesis (same merge path as inject)."""
    paths.ensure_layout()
    pending = pending_records(paths)
    if limit is not None:
        pending = pending[:limit]
    # Build synthetic response through the real inject path
    # Claim happens inside run_process_with_response — but that claims again from pending.
    # So just synthesize response for current pending and inject.
    results = synthesize_findings_from_candidates(pending[: limit or len(pending)])
    text = json.dumps(results, indent=2)
    return run_process_with_response(
        paths, root=root, response_text=text, limit=limit, agent_type="heuristic", model="candidate-synth"
    )


def apply_revalidation(
    paths: DeepSecPaths,
    *,
    root: Path,
    response_text: str | None = None,
    force: bool = False,
    limit: int | None = None,
    heuristic: bool = False,
) -> dict[str, Any]:
    paths.ensure_layout()
    run = create_run_meta(paths, run_type="revalidate", root_path=str(root), extra={})
    targets: list[tuple[dict, dict]] = []  # (record, finding)
    for rec in iter_file_records(paths):
        for f in rec.get("findings") or []:
            if f.get("revalidation") and not force:
                continue
            targets.append((rec, f))
    if limit is not None:
        targets = targets[:limit]

    if not targets:
        complete_run(paths, run, "done", {"findingsRevalidated": 0})
        return {"run": run, "stats": {"findingsRevalidated": 0}}

    verdicts: dict[str, dict] = {}
    if heuristic or response_text is None:
        for rec, f in targets:
            k = f"{rec['filePath']}::{finding_key(f)}"
            verdicts[k] = {
                "verdict": "true-positive",
                "reasoning": "Heuristic revalidation: candidate-backed finding retained as true-positive.",
                "revalidatedAt": utc_now(),
                "runId": run["runId"],
                "model": "heuristic",
            }
    else:
        payload = extract_json_payload(response_text)
        if not isinstance(payload, list):
            raise ValueError("revalidate response must be a JSON array")
        for item in payload:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("filePath") or "")
            title = item.get("title") or ""
            slug = item.get("vulnSlug") or ""
            k = f"{fp}::{slug}::{' '.join(title.lower().split())}"
            verdicts[k] = {
                "verdict": item.get("verdict") or "uncertain",
                "reasoning": item.get("reasoning") or "",
                "adjustedSeverity": item.get("adjustedSeverity"),
                "revalidatedAt": utc_now(),
                "runId": run["runId"],
                "model": item.get("model") or "injected",
            }

    n = 0
    # rewrite records
    touched: dict[str, dict] = {}
    for rec, f in targets:
        fp = rec["filePath"]
        if fp not in touched:
            touched[fp] = load_file_record(paths, fp) or rec
        rec2 = touched[fp]
        k1 = f"{fp}::{finding_key(f)}"
        k2 = f"{fp}::{f.get('vulnSlug')}::{' '.join(str(f.get('title') or '').lower().split())}"
        v = verdicts.get(k1) or verdicts.get(k2)
        if not v and heuristic:
            v = {
                "verdict": "true-positive",
                "reasoning": "default",
                "revalidatedAt": utc_now(),
                "runId": run["runId"],
                "model": "heuristic",
            }
        if not v:
            continue
        for i, existing in enumerate(rec2.get("findings") or []):
            if finding_key(existing) == finding_key(f):
                existing = dict(existing)
                existing["revalidation"] = v
                rec2["findings"][i] = existing
                n += 1
                break
        rec2["analysisHistory"] = list(rec2.get("analysisHistory") or []) + [
            {
                "runId": run["runId"],
                "investigatedAt": utc_now(),
                "agentType": "revalidate",
                "model": v.get("model"),
                "findingCount": 1,
                "phase": "revalidate",
            }
        ]
    for rec2 in touched.values():
        save_file_record(paths, rec2)

    stats = {"findingsRevalidated": n}
    complete_run(paths, run, "done", stats)
    return {"run": run, "stats": stats}


def apply_triage(
    paths: DeepSecPaths,
    *,
    root: Path,
    response_text: str | None = None,
    force: bool = False,
    limit: int | None = None,
    heuristic: bool = False,
    min_severity: str | None = None,
) -> dict[str, Any]:
    paths.ensure_layout()
    run = create_run_meta(paths, run_type="process", root_path=str(root), extra={"processorConfig": {"agentType": "triage"}})
    # Use type field extension via stats; keep type as process for schema compat — store triage in stats
    run["type"] = "process"
    run["processorConfig"] = {"agentType": "triage", "model": "heuristic" if heuristic else "injected"}
    sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "HIGH_BUG": 3, "BUG": 1}
    min_rank = sev_order.get((min_severity or "").upper(), 0)

    targets: list[tuple[dict, dict]] = []
    for rec in iter_file_records(paths):
        for f in rec.get("findings") or []:
            if f.get("triage") and not force:
                continue
            if min_rank and sev_order.get(str(f.get("severity") or "").upper(), 0) < min_rank:
                continue
            targets.append((rec, f))
    if limit is not None:
        targets = targets[:limit]
    if not targets:
        complete_run(paths, run, "done", {"findingsTriaged": 0})
        return {"run": run, "stats": {"findingsTriaged": 0}}

    triages: dict[str, dict] = {}
    if heuristic or response_text is None:
        for rec, f in targets:
            sev = str(f.get("severity") or "MEDIUM").upper()
            if sev == "CRITICAL":
                pri, exp, impact = "P0", "moderate", "critical"
            elif sev == "HIGH":
                pri, exp, impact = "P1", "moderate", "high"
            elif sev in ("MEDIUM", "HIGH_BUG"):
                pri, exp, impact = "P2", "difficult", "medium"
            else:
                pri, exp, impact = "skip", "difficult", "low"
            triages[f"{rec['filePath']}::{finding_key(f)}"] = {
                "priority": pri,
                "exploitability": exp,
                "impact": impact,
                "reasoning": f"Heuristic triage from severity {sev}.",
                "triagedAt": utc_now(),
                "model": "heuristic",
            }
    else:
        payload = extract_json_payload(response_text)
        if not isinstance(payload, list):
            raise ValueError("triage response must be a JSON array")
        for item in payload:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("filePath") or "")
            title = item.get("title") or ""
            slug = item.get("vulnSlug") or ""
            triages[f"{fp}::{slug}::{' '.join(title.lower().split())}"] = {
                "priority": item.get("priority") or "P2",
                "exploitability": item.get("exploitability") or "moderate",
                "impact": item.get("impact") or "medium",
                "reasoning": item.get("reasoning") or "",
                "triagedAt": utc_now(),
                "model": item.get("model") or "injected",
            }

    n = 0
    touched: dict[str, dict] = {}
    for rec, f in targets:
        fp = rec["filePath"]
        if fp not in touched:
            touched[fp] = load_file_record(paths, fp) or rec
        rec2 = touched[fp]
        k = f"{fp}::{finding_key(f)}"
        t = triages.get(k)
        if not t:
            # try alt key
            for kk, vv in triages.items():
                if kk.endswith(finding_key(f)) or finding_key(f) in kk:
                    t = vv
                    break
        if not t:
            continue
        for i, existing in enumerate(rec2.get("findings") or []):
            if finding_key(existing) == finding_key(f):
                existing = dict(existing)
                existing["triage"] = t
                rec2["findings"][i] = existing
                n += 1
                break
    for rec2 in touched.values():
        save_file_record(paths, rec2)
    stats = {"findingsTriaged": n}
    complete_run(paths, run, "done", stats)
    return {"run": run, "stats": stats}


DEFAULT_CORE_PROMPT = """You are a world-class security researcher. An automated scanner flagged candidate files.
Static analysis only — do not exploit. Report only genuine, exploitable issues.
Severities: CRITICAL, HIGH, MEDIUM, LOW, HIGH_BUG, BUG.
Return JSON findings per file as specified at the end of this prompt.
"""
