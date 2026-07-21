# DeepSec → Grok Build: Full Analysis Synthesis

**Phase 0 deliverable.** Synthesizes the six specialist reports under `docs/analysis/`.  
**Sources:** vercel-labs/deepsec (clone used during analysis), Grok-Fork plugin/skills model, live `~/.grok` conventions.

**Upstream pin (refactor baseline):** deepsec **2.2.4** @ `97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04` (2026-07-19).  
See [`plugins/deepsec/UPSTREAM.md`](../plugins/deepsec/UPSTREAM.md) and `plugins/deepsec/SOURCE_REV`.

| Doc | Focus |
|-----|--------|
| [01-pipeline-and-architecture.md](analysis/01-pipeline-and-architecture.md) | Stages, FileRecord lifecycle, locks, resume |
| [02-matcher-system.md](analysis/02-matcher-system.md) | Matcher interface, inventory, merge, MVP set |
| [03-agent-prompts-and-context.md](analysis/03-agent-prompts-and-context.md) | INFO.md, process/revalidate/triage prompts |
| [04-data-layout-and-config.md](analysis/04-data-layout-and-config.md) | Schemas, export formats, config |
| [05-edge-cases-security-and-limitations.md](analysis/05-edge-cases-security-and-limitations.md) | Edge modes, sandbox, FP, cost |
| [06-grok-build-mapping.md](analysis/06-grok-build-mapping.md) | Exact Grok plugin/skill/slash mapping |

---

## 1. What DeepSec is

DeepSec is an **append-only, file-centric** security harness:

```
scan (regex, free) → process (AI, $$) → revalidate (AI) → triage (AI) → enrich (git) → export/report
```

- Unit of work = **source file** → one **FileRecord** JSON on disk.
- Stages **merge** rather than overwrite (candidates, findings, history, annotations).
- **~110–200** built-in regex matchers produce **candidates**; AI turns pending files into **findings**.
- State lives under `data/<projectId>/` (upstream) → ported to **`.grok/deepsec/`**.

---

## 2. Pipeline contracts (non-negotiable for the port)

### Stages

| Stage | AI? | Mutates | Resume key |
|-------|-----|---------|------------|
| `init` | No | Scaffold only | Idempotent dirs/files |
| `scan` | No | `candidates`, `lastScanned*`, `fileHash` | Re-scan merges candidates; does not wipe findings |
| `process` | Yes | `findings`, `analysisHistory`, `status` | Skip `analyzed`; reclaim stale locks; claim via `lockedByRunId` |
| `revalidate` | Yes | `finding.revalidation` | Skip findings that already have verdict unless `--force` |
| `triage` | Yes | `finding.triage` | Skip already-triaged unless force |
| `enrich` | No* | `gitInfo` | Skip if already enriched (unless force) |
| `export` / `report` / `status` | No | Read-only (report may overwrite `reports/`) | N/A |
| `resume` | — | Continues interrupted stage | Reads RunMeta phase + pending/error files |

\*enrich uses local `git log` only (no ownership plugin required for OSS port).

### Merge / idempotency keys

- **Candidates:** `(vulnSlug, matchedPattern, lineNumbers joined)`
- **Findings:** `vulnSlug::normalizedTitle`
- **History:** always append `AnalysisEntry`
- **Locks:** project `.process.lock` + per-file `lockedByRunId`; reclaim on run `phase:error|done`, same-host dead PID, or stale timeout

### Diff mode

`process --diff` (or explicit file list): scan listed files into FileRecords (even zero candidates), then process with `invocationMode: "direct"`. Hard-requires git for `--diff`.

---

## 3. On-disk layout (Grok port)

```
.grok/deepsec/                          # project workspace
├── config.json                         # optional: ignorePaths, priorityPaths, promptAppend
├── data/<projectId>/
│   ├── project.json
│   ├── INFO.md                         # curated context → AI prompts
│   ├── SETUP.md
│   ├── tech.json                       # optional
│   ├── files/**/*.json                 # FileRecords
│   ├── runs/*.json                     # RunMeta
│   ├── reports/                        # report.md / report.json
│   └── .process.lock                   # exclusive claim
~/.grok/deepsec/                        # optional user defaults / global registry
plugins/deepsec/                        # shipped plugin (skills + scripts + matchers)
```

Schemas: FileRecord, Finding, CandidateMatch, RunMeta, ProjectConfig — see analysis 04. Behavioral fidelity > byte-identical paths to upstream `data/`.

---

## 4. Matchers

- Interface: `slug`, `description`, `filePatterns[]`, `patterns[{regex,label}]`, optional `noiseTier` / gates.
- Scan: glob → read text → run matchers → merge candidates → write FileRecords for files with hits (full scan).
- **MVP for fixtures/vulnerable-app:** sql-injection, xss, ssrf, path-traversal, open-redirect, rce, secrets-exposure, insecure-crypto, auth-bypass, dangerous-html (plus more for quality).
- Port strategy: **JSON matcher packs + Python (or Rust) regex walker** — **zero Node** for end users.

---

## 5. AI stages (process / revalidate / triage)

- **INFO.md** injected into every process/revalidate/triage batch (project-aware findings).
- Process prompt: investigate candidate files → JSON array of `{filePath, findings[]}`.
- Revalidate: TP / FP / fixed / uncertain (+ git history when available).
- Triage: P0 / P1 / P2 / skip without re-reading full code.
- **Parser/merger must work offline** with injected agent responses (tests, no-model environments).
- Grok mapping: skills spawn sub-agents (or in-session investigation); pure merge/claim stays in scripts.

---

## 6. Grok extension mapping

| DeepSec | Grok Build |
|---------|------------|
| `deepsec` CLI | Plugin `plugins/deepsec` + `scripts/deepsec_cli.py` |
| Subcommands | Skills: `deepsec`, `deepsec-init`, `deepsec-scan`, … (umbrella + flat) |
| Slash UX | `/deepsec …` and `/deepsec-scan` etc. |
| AI backends | Host Grok agent / subagents (no Codex/Claude SDKs) |
| Sandbox | Grok sandbox profiles; write only under `.grok/deepsec/` |
| Headless | `grok -p "/deepsec …"` or direct `python3 …/deepsec_cli.py` |

**Zero Node:** skills + Python stdlib + JSON matchers only.

---

## 7. Edge cases & security (must handle)

- No git → enrich degrades; `--diff` errors clearly; githubUrl optional
- Empty / binary-only dirs → empty scan, exit 0, clear status
- Huge monorepo → ignore dirs, `--limit`, priorityPaths
- Interrupt → locks reclaimable; resume continues pending/error
- Concurrent runs → lock mutex; no corrupt JSON (atomic write)
- Permissions → skip unreadable files with message; never corrupt state
- Security → no extra network exfil beyond base agent; matchers local only

---

## 8. Out of scope for v1 port

- Vercel Sandbox OIDC, AI Gateway, org ownership oracles, notifiers
- Byte-identical TypeScript monorepo
- Guaranteeing model FP rate (pathways + merge correctness required)

---

## 9. Implementation order (from mapping)

1. Data layer + init  
2. Matcher engine + scan  
3. Process claim/merge + inject-response path  
4. Revalidate / triage / enrich  
5. Export / report / status / resume  
6. Plugin packaging + skills  
7. Docs + fixture E2E + verification report  
8. Ship (commit, README, push, tag)

---

## 10. Success bar

Every listed `/deepsec` command works; fixture pipeline yields real candidates/findings; resume/edge modes never corrupt state; plugin visible as native Grok feature; **zero end-user Node**.
