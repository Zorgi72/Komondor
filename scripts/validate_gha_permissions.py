#!/usr/bin/env python3
"""Fail if workflow YAML uses invalid top-level permissions keys.

GitHub silently produces "No jobs were run" for unknown permission names
like administration / members.
"""
from __future__ import annotations

import sys
from pathlib import Path

# https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions
VALID = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}


def parse_permissions_block(text: str) -> list[str]:
    keys: list[str] = []
    in_perm = False
    for line in text.splitlines():
        if line.startswith("permissions:"):
            in_perm = True
            continue
        if in_perm:
            if not line.startswith(" ") and not line.startswith("\t") and line.strip():
                break
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" in stripped:
                keys.append(stripped.split(":", 1)[0].strip())
    return keys


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    wf_dir = root / ".github" / "workflows"
    bad = 0
    for path in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
        keys = parse_permissions_block(path.read_text(encoding="utf-8"))
        invalid = [k for k in keys if k not in VALID]
        if invalid:
            print(f"FAIL {path.relative_to(root)}: invalid permissions {invalid}")
            bad += 1
        else:
            print(f"OK   {path.relative_to(root)}: {keys or '(none)'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
