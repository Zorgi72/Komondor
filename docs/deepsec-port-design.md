# DeepSec Port Design — Grok Build Fork

**Status:** Phase 1 design (authoritative for implementation)  
**Inputs:** `docs/deepsec-full-analysis.md`, `docs/analysis/01`–`06`  
**Constraints:** Zero Node for end users; state under `.grok/deepsec/`; fully resumable/idempotent; Grok sandbox-safe.

---

## 1. Command surface

All commands are available as:

1. **Umbrella skill** `/deepsec <subcommand> [args…]`  
2. **Flat skills** `/deepsec-init`, `/deepsec-scan`, …  
3. **Headless** `python3 $PLUGIN_ROOT/scripts/deepsec_cli.py <subcommand> …` (deterministic stages always; AI stages support `--inject-response` for tests)

| Command | Behavior |
|---------|----------|
| `/deepsec` | Help + compact status if workspace exists |
| `/deepsec init` | Scaffold `.grok/deepsec/`, project id, INFO.md, SETUP.md, project.json |
| `/deepsec scan [path]` | Regex scan root (cwd or path); write candidates |
| `/deepsec process [--diff]` | AI investigate pending files (or git-diff set); merge findings |
| `/deepsec revalidate` | Attach TP/FP/fixed/uncertain to findings |
| `/deepsec triage` | Attach P0/P1/P2/skip to findings |
| `/deepsec enrich` | Attach git committer metadata when git available |
| `/deepsec export [--format md\|json\|md-dir] [--out path]` | Read-only export |
| `/deepsec status` | Counts by status, runs, findings severity |
| `/deepsec resume` | Continue interrupted process/revalidate (reclaim locks, process pending/error) |
| `/deepsec report` | Write `reports/report.md` + `report.json` |

### CLI flags (shared)

| Flag | Stages | Meaning |
|------|--------|---------|
| `--root PATH` | most | Project source root |
| `--project-id ID` | most | Override project id (default: basename of root) |
| `--data-dir PATH` | most | Override `.grok/deepsec` location |
| `--limit N` | process, revalidate, triage | Cap work units |
| `--force` | revalidate, triage, enrich | Re-do even if already done |
| `--diff [BASE]` | process | Files from `git diff --name-only BASE` (default `HEAD`) |
| `--inject-response FILE` | process, revalidate, triage | Use recorded JSON (no live model) |
| `--format` / `--out` | export | md \| json \| md-dir |

---

## 2. On-disk state

```
.grok/deepsec/
├── config.json                 # optional workspace config
├── data/<projectId>/
│   ├── project.json
│   ├── INFO.md
│   ├── SETUP.md
│   ├── files/<rel/path>.json   # FileRecord
│   ├── runs/<runId>.json       # RunMeta
│   ├── reports/
│   │   ├── report.md
│   │   └── report.json
│   └── .process.lock           # file lock with runId + pid + hostname
```

### FileRecord (essential fields)

```json
{
  "filePath": "src/api/users.ts",
  "projectId": "myapp",
  "candidates": [
    {
      "vulnSlug": "sql-injection",
      "lineNumbers": [12],
      "snippet": "...",
      "matchedPattern": "template literal SELECT with interpolation"
    }
  ],
  "findings": [],
  "analysisHistory": [],
  "status": "pending",
  "lastScannedAt": "…",
  "lastScannedRunId": "…",
  "fileHash": "sha256…",
  "lockedByRunId": null,
  "gitInfo": null
}
```

### Status lifecycle

`pending` → `processing` (lock held) → `analyzed` | `error`  
Re-scan does **not** reset `analyzed` → `pending`.  
`process`/`resume` select `pending` and `error` (and reclaim stale `processing`).

### Atomic writes

Write temp file next to target → `os.replace`. Never partial JSON on crash.

---

## 3. Matcher system

- Packs under `plugins/deepsec/scripts/matchers/*.json`:

```json
{
  "slug": "sql-injection",
  "description": "Raw SQL string concatenation or interpolation",
  "filePatterns": ["**/*.{ts,tsx,js,jsx}"],
  "patterns": [
    {"regex": "`\\s*SELECT\\s+[^`]{0,400}\\$\\{", "label": "template literal SELECT with interpolation"}
  ]
}
```

- Engine: Python `re` + pathlib walk; ignore `node_modules`, `.git`, `target`, `.grok/deepsec`, etc.
- Merge candidates with key `(vulnSlug, matchedPattern, ",".join(map(str, lineNumbers)))`.
- Extensibility: drop extra JSON in `.grok/deepsec/matchers/` (project overrides by slug).

---

## 4. Process / AI integration

### Skill path (interactive / headless with model)

1. CLI: create RunMeta, claim batch of pending FileRecords (`status=processing`, set lock).
2. CLI: emit prompt package (INFO.md + file contents + candidates) to stdout or `runs/<id>.prompt.md`.
3. Agent investigates using Grok tools; produces JSON findings array.
4. CLI: `process --apply-response <json>` merges findings, appends history, clears lock, `status=analyzed`.

### Deterministic / test path

`process --inject-response recorded.json` uses the **same** parser and merger as production (no reimplementation in tests).

### Parser

- Extract fenced ```json``` or raw array.
- Expected shape: `[{ "filePath", "findings": [ Finding… ] }, …]`
- Missing files in batch → empty findings (analyzed with 0 findings).
- Malformed → mark batch files `error`, keep candidates, allow resume.

### Finding merge

Dedupe by `vulnSlug::normalizedTitle`; preserve existing revalidation/triage when re-merging same signature.

---

## 5. Revalidate / triage / enrich

| Stage | Input | Output field |
|-------|-------|--------------|
| revalidate | findings without `revalidation` | `verdict`, `reasoning`, timestamps |
| triage | findings without `triage` | `priority`, `exploitability`, `impact`, `reasoning` |
| enrich | files with findings, git present | `gitInfo.recentCommitters` |

Graceful: no git → enrich no-ops with message; still exit 0.

---

## 6. Export / report / status / resume

### export

- `json` → single array of findings with `filePath` attached  
- `md` → one markdown document  
- `md-dir` → `{out}/{SEVERITY}/{slug-title}.md`

### report

Aggregate severity counts, TP rates, top files → `reports/report.md` + `.json`.

### status

Human-readable table: files by status, candidate count, finding count by severity, last runs.

### resume

1. Reclaim stale locks  
2. Map last incomplete RunMeta  
3. Re-enter process (or revalidate) for pending/error  

---

## 7. Graceful degradation

| Situation | Behavior |
|-----------|----------|
| No `.grok/deepsec` | Commands (except init/help) print actionable “run /deepsec init” |
| Empty tree | scan → 0 files, status clean |
| Binary files | skip (decode errors) |
| Unreadable path | warn, continue |
| Missing git | enrich skip; `--diff` error with fix |
| Concurrent run | lock fail → clear message |
| Huge repo | default ignore dirs; optional `--limit` on process |

---

## 8. Plugin packaging

```
plugins/deepsec/
├── plugin.json
├── README.md
├── skills/
│   ├── deepsec/SKILL.md
│   ├── deepsec-init/SKILL.md
│   ├── deepsec-scan/SKILL.md
│   ├── deepsec-process/SKILL.md
│   ├── deepsec-revalidate/SKILL.md
│   ├── deepsec-triage/SKILL.md
│   ├── deepsec-enrich/SKILL.md
│   ├── deepsec-export/SKILL.md
│   ├── deepsec-status/SKILL.md
│   ├── deepsec-resume/SKILL.md
│   └── deepsec-report/SKILL.md
├── scripts/
│   ├── deepsec_cli.py
│   ├── deepsec/            # package
│   │   ├── __init__.py
│   │   ├── state.py
│   │   ├── scan.py
│   │   ├── merge.py
│   │   ├── process.py
│   │   ├── export_fmt.py
│   │   ├── enrich.py
│   │   └── matchers_engine.py
│   ├── matchers/*.json
│   └── tests/test_deepsec.py
├── references/
│   ├── process-prompt.md
│   ├── revalidate-prompt.md
│   ├── triage-prompt.md
│   └── INFO-template.md
└── fixtures/vulnerable-app/   # vendored minimal copy for docs/tests
```

Install: copy/symlink to `~/.grok/plugins/deepsec` (user-trusted) and/or project `.grok/plugins/deepsec`.

---

## 9. Security

- Scan/process file reads are local only.
- AI stages use same tools/network policy as the parent Grok session.
- No product telemetry; no SpaceXAI phone-home from DeepSec code.
- Do not upload FileRecords or source off-machine except via user-driven agent tools.

---

## 10. Verification (Phase 3)

Mandatory checklist in goal OBJECTIVE; results in `docs/verification-report.md`.  
Unit tests drive shipped `deepsec` Python package (matchers, merge, export, resume).  
Fixture E2E: scan vulnerable-app → inject process response → export non-empty findings.
