"""Export and report formatters (read-only)."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .state import DeepSecPaths, atomic_write_text, iter_file_records, utc_now


def collect_findings(paths: DeepSecPaths) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rec in iter_file_records(paths):
        for f in rec.get("findings") or []:
            item = dict(f)
            item["filePath"] = rec["filePath"]
            item["projectId"] = rec.get("projectId")
            out.append(item)
    return out


def export_json(paths: DeepSecPaths, out_path: Path) -> Path:
    findings = collect_findings(paths)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path


def export_md(paths: DeepSecPaths, out_path: Path) -> Path:
    findings = collect_findings(paths)
    lines = [f"# DeepSec findings — {paths.project_id}", "", f"Generated: {utc_now()}", f"Total: {len(findings)}", ""]
    for f in sorted(findings, key=lambda x: (x.get("severity") or "", x.get("filePath") or "")):
        lines.append(f"## [{f.get('severity')}] {f.get('title')}")
        lines.append(f"- **File:** `{f.get('filePath')}`")
        lines.append(f"- **Slug:** `{f.get('vulnSlug')}`")
        if f.get("lineNumbers"):
            lines.append(f"- **Lines:** {f.get('lineNumbers')}")
        if f.get("revalidation"):
            lines.append(f"- **Revalidation:** {f['revalidation'].get('verdict')}")
        if f.get("triage"):
            lines.append(f"- **Triage:** {f['triage'].get('priority')}")
        lines.append("")
        lines.append(str(f.get("description") or ""))
        lines.append("")
        if f.get("recommendation"):
            lines.append(f"**Recommendation:** {f['recommendation']}")
            lines.append("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", s).strip("-").lower()
    return s[:80] or "finding"


def export_md_dir(paths: DeepSecPaths, out_dir: Path) -> Path:
    findings = collect_findings(paths)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, f in enumerate(findings):
        sev = str(f.get("severity") or "UNKNOWN").upper()
        d = out_dir / sev
        d.mkdir(parents=True, exist_ok=True)
        name = f"{_slugify(str(f.get('vulnSlug')))}--{_slugify(str(f.get('title')))}--{i}.md"
        body = "\n".join(
            [
                f"# {f.get('title')}",
                "",
                f"- Severity: {sev}",
                f"- File: `{f.get('filePath')}`",
                f"- Slug: `{f.get('vulnSlug')}`",
                f"- Lines: {f.get('lineNumbers')}",
                f"- Confidence: {f.get('confidence')}",
                "",
                str(f.get("description") or ""),
                "",
                f"## Recommendation\n\n{f.get('recommendation') or ''}",
                "",
            ]
        )
        (d / name).write_text(body, encoding="utf-8")
    return out_dir


def write_report(paths: DeepSecPaths) -> dict[str, Path]:
    findings = collect_findings(paths)
    records = iter_file_records(paths)
    by_status = Counter(r.get("status") or "unknown" for r in records)
    by_sev = Counter(str(f.get("severity") or "UNKNOWN") for f in findings)
    by_verdict = Counter(
        (f.get("revalidation") or {}).get("verdict") or "none" for f in findings if f.get("revalidation")
    )
    summary = {
        "projectId": paths.project_id,
        "generatedAt": utc_now(),
        "files": dict(by_status),
        "findingsTotal": len(findings),
        "findingsBySeverity": dict(by_sev),
        "revalidation": dict(by_verdict),
        "findings": findings,
    }
    md_lines = [
        f"# DeepSec report — {paths.project_id}",
        "",
        f"Generated: {summary['generatedAt']}",
        "",
        "## File status",
        "",
        *[f"- {k}: {v}" for k, v in sorted(by_status.items())],
        "",
        "## Findings by severity",
        "",
        *[f"- {k}: {v}" for k, v in sorted(by_sev.items())],
        "",
        f"**Total findings:** {len(findings)}",
        "",
    ]
    if by_verdict:
        md_lines += ["## Revalidation", "", *[f"- {k}: {v}" for k, v in sorted(by_verdict.items())], ""]
    paths.reports.mkdir(parents=True, exist_ok=True)
    md_path = paths.reports / "report.md"
    json_path = paths.reports / "report.json"
    atomic_write_text(md_path, "\n".join(md_lines))
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"md": md_path, "json": json_path}


def status_summary(paths: DeepSecPaths) -> dict[str, Any]:
    records = iter_file_records(paths)
    findings = collect_findings(paths)
    by_status = Counter(r.get("status") or "unknown" for r in records)
    cand_total = sum(len(r.get("candidates") or []) for r in records)
    by_sev = Counter(str(f.get("severity") or "UNKNOWN") for f in findings)
    return {
        "projectId": paths.project_id,
        "dataDir": str(paths.data),
        "files": dict(by_status),
        "filesTotal": len(records),
        "candidatesTotal": cand_total,
        "findingsTotal": len(findings),
        "findingsBySeverity": dict(by_sev),
    }
