#!/usr/bin/env python3
"""Tests for scripts/validate_gha_permissions.py (shipped validator)."""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_gha_permissions.py"


def test_repo_workflows_pass():
    r = subprocess.run([sys.executable, str(VALIDATOR)], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "grant-kodus-access.yml" in r.stdout
    assert "OK" in r.stdout


def test_rejects_administration_and_members():
    """Drive real parse_permissions_block + VALID check on a bad sample."""
    # Import the shipped module by path
    import importlib.util
    spec = importlib.util.spec_from_file_location("validate_gha_permissions", VALIDATOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bad = """
name: x
on: push
permissions:
  contents: write
  administration: write
  members: write
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
    keys = mod.parse_permissions_block(bad)
    invalid = [k for k in keys if k not in mod.VALID]
    assert "administration" in invalid
    assert "members" in invalid
    good = """
permissions:
  contents: write
  pull-requests: write
"""
    keys2 = mod.parse_permissions_block(good)
    assert all(k in mod.VALID for k in keys2)


if __name__ == "__main__":
    test_repo_workflows_pass()
    test_rejects_administration_and_members()
    print("test_validate_gha_permissions: ALL_OK")
