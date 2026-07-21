#!/usr/bin/env python3
"""Unit/integration tests for shipped DeepSec engine (no mocks of core logic)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # scripts/
PLUGIN = ROOT.parent
FIXTURE = PLUGIN / "fixtures" / "vulnerable-app"
CLI = ROOT / "deepsec_cli.py"

sys.path.insert(0, str(ROOT))

from deepsec.matchers_engine import load_matchers, run_matcher, matcher_applies, default_matcher_dir  # noqa: E402
from deepsec.process import extract_json_payload, normalize_process_results, merge_findings  # noqa: E402
from deepsec.state import merge_candidates, candidate_key, finding_key  # noqa: E402


def run_cli(args: list[str], cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=e,
    )


class MatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matchers = {m["slug"]: m for m in load_matchers([default_matcher_dir(PLUGIN)])}

    def test_core_matchers_loaded(self):
        for slug in (
            "sql-injection",
            "xss",
            "ssrf",
            "path-traversal",
            "rce",
            "secrets-exposure",
            "insecure-crypto",
            "open-redirect",
            "auth-bypass",
        ):
            self.assertIn(slug, self.matchers, f"missing {slug}")

    def test_fixture_sql_injection(self):
        content = (FIXTURE / "src/lib/db.ts").read_text()
        hits = run_matcher(self.matchers["sql-injection"], content)
        self.assertGreater(len(hits), 0)

    def test_fixture_xss(self):
        content = (FIXTURE / "src/components/comment.tsx").read_text()
        hits = run_matcher(self.matchers["xss"], content)
        self.assertGreater(len(hits), 0)

    def test_fixture_ssrf(self):
        content = (FIXTURE / "src/lib/fetch-proxy.ts").read_text()
        hits = run_matcher(self.matchers["ssrf"], content)
        self.assertGreater(len(hits), 0)

    def test_fixture_rce(self):
        content = (FIXTURE / "src/utils/exec-helper.ts").read_text()
        hits = run_matcher(self.matchers["rce"], content)
        self.assertGreater(len(hits), 0)

    def test_fixture_secrets(self):
        content = (FIXTURE / "src/config.ts").read_text()
        hits = run_matcher(self.matchers["secrets-exposure"], content)
        self.assertGreater(len(hits), 0)

    def test_fixture_crypto(self):
        content = (FIXTURE / "src/lib/crypto.ts").read_text()
        hits = run_matcher(self.matchers["insecure-crypto"], content)
        self.assertGreater(len(hits), 0)
        labels = " ".join(h["matchedPattern"] for h in hits)
        self.assertTrue("MD5" in labels or "md5" in labels.lower() or "Math.random" in labels)

    def test_merge_candidates_idempotent(self):
        a = [{"vulnSlug": "xss", "matchedPattern": "p", "lineNumbers": [1], "snippet": "x"}]
        b = [{"vulnSlug": "xss", "matchedPattern": "p", "lineNumbers": [1], "snippet": "y"}]
        m = merge_candidates(a, b)
        self.assertEqual(len(m), 1)


class ParserTests(unittest.TestCase):
    def test_extract_fenced_json(self):
        text = 'Here:\n```json\n[{"filePath":"a.ts","findings":[]}]\n```\n'
        p = extract_json_payload(text)
        self.assertIsInstance(p, list)
        self.assertEqual(p[0]["filePath"], "a.ts")

    def test_normalize_results(self):
        payload = [
            {
                "filePath": "src/a.ts",
                "findings": [
                    {
                        "severity": "high",
                        "vulnSlug": "xss",
                        "title": "XSS",
                        "description": "d",
                        "lineNumbers": [3],
                    }
                ],
            }
        ]
        out = normalize_process_results(payload, ["src/a.ts", "src/b.ts"])
        self.assertEqual(len(out), 2)
        self.assertEqual(len(out[0]["findings"]), 1)
        self.assertEqual(out[0]["findings"][0]["severity"], "HIGH")
        self.assertEqual(out[1]["findings"], [])


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="deepsec-test-"))
        self.root = self.tmp / "app"
        shutil.copytree(FIXTURE, self.root)
        self.data = self.tmp / "dsdata"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_pipeline_fixture(self):
        r = run_cli(
            ["init", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "vuln"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

        r = run_cli(
            ["scan", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "vuln"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("candidates=", r.stdout)

        r = run_cli(
            [
                "process",
                "--heuristic",
                "--root",
                str(self.root),
                "--data-dir",
                str(self.data),
                "--project-id",
                "vuln",
            ],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

        r = run_cli(
            ["status", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "vuln"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("findings:", r.stdout)

        out_json = self.tmp / "out.json"
        r = run_cli(
            [
                "export",
                "--format",
                "json",
                "--out",
                str(out_json),
                "--root",
                str(self.root),
                "--data-dir",
                str(self.data),
                "--project-id",
                "vuln",
            ],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        findings = json.loads(out_json.read_text())
        self.assertGreater(len(findings), 0, "expected non-empty findings on vulnerable-app")
        slugs = {f.get("vulnSlug") for f in findings}
        # at least some classic vulns
        self.assertTrue(slugs & {"sql-injection", "xss", "ssrf", "rce", "secrets-exposure", "path-traversal", "open-redirect", "insecure-crypto", "auth-bypass", "missing-auth"})

        out_md = self.tmp / "out.md"
        r = run_cli(
            [
                "export",
                "--format",
                "md",
                "--out",
                str(out_md),
                "--data-dir",
                str(self.data),
                "--project-id",
                "vuln",
                "--root",
                str(self.root),
            ],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue(out_md.is_file())

        out_dir = self.tmp / "md-dir"
        r = run_cli(
            [
                "export",
                "--format",
                "md-dir",
                "--out",
                str(out_dir),
                "--data-dir",
                str(self.data),
                "--project-id",
                "vuln",
                "--root",
                str(self.root),
            ],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue(any(out_dir.rglob("*.md")))

        r = run_cli(
            ["revalidate", "--heuristic", "--data-dir", str(self.data), "--project-id", "vuln", "--root", str(self.root)],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_cli(
            ["triage", "--heuristic", "--data-dir", str(self.data), "--project-id", "vuln", "--root", str(self.root)],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_cli(
            ["enrich", "--data-dir", str(self.data), "--project-id", "vuln", "--root", str(self.root)],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_cli(
            ["report", "--data-dir", str(self.data), "--project-id", "vuln", "--root", str(self.root)],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue((self.data / "data/vuln/reports/report.md").is_file())

        # idempotent second process (nothing pending)
        r = run_cli(
            ["process", "--heuristic", "--data-dir", str(self.data), "--project-id", "vuln", "--root", str(self.root)],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)

    def test_empty_dir(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        r = run_cli(
            ["init", "--root", str(empty), "--data-dir", str(self.data / "e"), "--project-id", "empty"],
            cwd=empty,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["scan", "--root", str(empty), "--data-dir", str(self.data / "e"), "--project-id", "empty"],
            cwd=empty,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("candidates=0", r.stdout)

    def test_resume_after_partial(self):
        r = run_cli(
            ["init", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "r1"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["scan", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "r1"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        # process only 1 file
        r = run_cli(
            [
                "process",
                "--heuristic",
                "--limit",
                "1",
                "--root",
                str(self.root),
                "--data-dir",
                str(self.data),
                "--project-id",
                "r1",
            ],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["resume", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "r1"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        r = run_cli(
            ["status", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "r1"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("findings:", r.stdout)
        # After resume, pending queue should be drained (all analyzed).
        self.assertIn("analyzed", r.stdout)
        self.assertNotRegex(r.stdout, r"'pending': [1-9]")

    def test_inject_response_path(self):
        r = run_cli(
            ["init", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "inj"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["scan", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "inj"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        # Build response for the first pending record in the same order the engine claims.
        files_dir = self.data / "data/inj/files"
        recs = []
        for p in sorted(files_dir.rglob("*.json")):
            recs.append(json.loads(p.read_text()))
        self.assertGreater(len(recs), 0)
        pending = [r for r in recs if r.get("status") == "pending"]
        self.assertGreater(len(pending), 0)
        target = pending[0]
        payload = [
            {
                "filePath": target["filePath"],
                "findings": [
                    {
                        "severity": "HIGH",
                        "vulnSlug": "sql-injection",
                        "title": "Injected finding",
                        "description": "from inject-response",
                        "lineNumbers": [1],
                        "recommendation": "fix it",
                        "confidence": "high",
                    }
                ],
            }
        ]
        inj = self.tmp / "inj.json"
        inj.write_text(json.dumps(payload))
        r = run_cli(
            [
                "process",
                "--inject-response",
                str(inj),
                "--limit",
                "1",
                "--root",
                str(self.root),
                "--data-dir",
                str(self.data),
                "--project-id",
                "inj",
            ],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        # verify merged into the claimed file
        updated = json.loads((files_dir / f"{target['filePath']}.json").read_text())
        titles = [f["title"] for f in updated.get("findings") or []]
        self.assertIn("Injected finding", titles)
        self.assertEqual(updated.get("status"), "analyzed")


class InitRootPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="deepsec-init-"))
        self.app = self.tmp / "app"
        self.src = self.app / "src"
        self.src.mkdir(parents=True)
        (self.src / "db.ts").write_text("const q = `SELECT * FROM t WHERE id = ${id}`;\n")
        self.data = self.tmp / "ds"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_init_preserves_rootpath_without_force(self):
        r = run_cli(
            ["init", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_cli(
            ["scan", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        # Re-init with subdirectory root without --force must fail (not retarget)
        r = run_cli(
            ["init", "--root", str(self.src), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("without --force", r.stderr)
        # project.json rootPath unchanged
        proj = json.loads((self.data / "data/p/project.json").read_text())
        self.assertEqual(Path(proj["rootPath"]).resolve(), self.app.resolve())
        # scan still works with original root; only src/db.ts records
        r = run_cli(
            ["scan", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0)
        rels = [
            json.loads(p.read_text())["filePath"]
            for p in (self.data / "data/p/files").rglob("*.json")
        ]
        self.assertTrue(any(x == "src/db.ts" or x.endswith("src/db.ts") for x in rels), rels)
        self.assertFalse(any(x == "db.ts" for x in rels), rels)

    def test_init_force_retarget_clears_files(self):
        r = run_cli(
            ["init", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["scan", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue(any((self.data / "data/p/files").rglob("*.json")))
        # Force retarget to src/
        r = run_cli(
            [
                "init",
                "--force",
                "--root",
                str(self.src),
                "--data-dir",
                str(self.data),
                "--project-id",
                "p",
            ],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertIn("cleared files", (r.stderr + r.stdout).lower())
        proj = json.loads((self.data / "data/p/project.json").read_text())
        self.assertEqual(Path(proj["rootPath"]).resolve(), self.src.resolve())
        # Old records gone
        self.assertFalse(any((self.data / "data/p/files").rglob("*.json")))
        # New scan under new root uses db.ts (not src/db.ts)
        r = run_cli(
            ["scan", "--root", str(self.src), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.src,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        rels = [
            json.loads(p.read_text())["filePath"]
            for p in (self.data / "data/p/files").rglob("*.json")
        ]
        self.assertIn("db.ts", rels)
        self.assertFalse(any("src/" in x for x in rels), rels)

    def test_init_same_root_idempotent(self):
        r = run_cli(
            ["init", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["init", "--root", str(self.app), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.app,
        )
        self.assertEqual(r.returncode, 0, r.stderr)


class EdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="deepsec-edge-"))
        self.root = self.tmp / "app"
        self.root.mkdir()
        (self.root / "ok.ts").write_text("const x = `SELECT * FROM t WHERE id = ${id}`;\n")
        self.data = self.tmp / "ds"

    def tearDown(self):
        # restore perms so cleanup works
        for p in self.root.rglob("*"):
            try:
                os.chmod(p, 0o644)
            except OSError:
                pass
        try:
            os.chmod(self.root, 0o755)
        except OSError:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_permission_denied_warns_on_stderr(self):
        secret = self.root / "secret.ts"
        secret.write_text("const y = `SELECT ${z}`;\n")
        os.chmod(secret, 0o000)
        r = run_cli(
            ["init", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_cli(
            ["scan", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "p"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        # Must surface clear permission warning (not silent skip)
        combined = r.stderr + r.stdout
        self.assertIn("permission", combined.lower(), combined)
        self.assertIn("secret.ts", combined)
        # Readable file still scanned
        self.assertIn("candidates=", r.stdout)

    def test_missing_scope_path_errors(self):
        r = run_cli(
            ["init", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "m"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        missing = self.root / "does-not-exist"
        r = run_cli(
            [
                "scan",
                str(missing),
                "--root",
                str(self.root),
                "--data-dir",
                str(self.data),
                "--project-id",
                "m",
            ],
            cwd=self.root,
        )
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("does not exist", r.stderr.lower() + r.stdout.lower())

    def test_mismatched_root_rejects_duplicate_paths(self):
        # Seed a nested layout
        src = self.root / "src"
        src.mkdir()
        (src / "db.ts").write_text("const q = `SELECT * FROM u WHERE id = ${id}`;\n")
        r = run_cli(
            ["init", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "dup"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0)
        r = run_cli(
            ["scan", "--root", str(self.root), "--data-dir", str(self.data), "--project-id", "dup"],
            cwd=self.root,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        # Second scan with --root pointing at subdirectory must be rejected
        r = run_cli(
            ["scan", "--root", str(src), "--data-dir", str(self.data), "--project-id", "dup"],
            cwd=self.root,
        )
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("does not match project rootPath", r.stderr)
        # Only records under original root (src/db.ts), not db.ts
        files_dir = self.data / "data/dup/files"
        recs = list(files_dir.rglob("*.json"))
        rels = [json.loads(p.read_text())["filePath"] for p in recs]
        self.assertTrue(any(x.endswith("src/db.ts") or x == "src/db.ts" for x in rels), rels)
        self.assertFalse(any(x == "db.ts" for x in rels), rels)


if __name__ == "__main__":
    unittest.main(verbosity=2)
