# 06 — DeepSec → Grok Build Extension Mapping

Concrete mapping of [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec) concepts onto Grok Build’s extension model (plugins, skills, agents, headless, sandbox). Sources inspected:

| Source | Path |
|--------|------|
| DeepSec clone | `/tmp/grok-goal-f8e64663ee8a/implementer/deepsec` |
| Grok-Fork | `/home/elliot/Grok-Fork` |
| Live Grok home | `/home/elliot/.grok` (bundled skills/plugins, user-guide 04/08/09/14/16/18) |
| Plugin manifest | `crates/codegen/xai-grok-agent/src/plugins/manifest.rs` |
| Skills discovery | `crates/codegen/xai-grok-tools/src/implementations/skills/` |
| Example plugin | `~/.grok/marketplace-cache/.../external_plugins/neon/` |
| Bundled skill pattern | `~/.grok/bundled/skills/implement/`, `execute-plan/` |

**Goal:** ship DeepSec as a **zero-Node** Grok plugin: pure scan/state logic in Python (or small Rust helpers), AI stages as Grok skills + subagents, on-disk state compatible with DeepSec’s `FileRecord` / `RunMeta` shapes so exports stay interoperable.

---

## 1. Plugin layout (`plugin.json` + `skills/`)

### Canonical install layout (fork implementation path)

Implement DeepSec as a first-class plugin under the fork, then publish / install via marketplace or path:

```
# Repo-vendored during development (highest clarity for implementers):
/home/elliot/Grok-Fork/plugins/deepsec/
├── plugin.json
├── README.md
├── skills/
│   ├── deepsec/                 # umbrella / help
│   │   └── SKILL.md
│   ├── deepsec-init/
│   │   └── SKILL.md
│   ├── deepsec-scan/
│   │   └── SKILL.md
│   ├── deepsec-process/
│   │   └── SKILL.md
│   ├── deepsec-revalidate/
│   │   └── SKILL.md
│   ├── deepsec-triage/
│   │   └── SKILL.md
│   ├── deepsec-enrich/
│   │   └── SKILL.md
│   ├── deepsec-export/
│   │   └── SKILL.md
│   ├── deepsec-status/
│   │   └── SKILL.md
│   ├── deepsec-resume/
│   │   └── SKILL.md
│   └── deepsec-report/
│       └── SKILL.md
├── agents/                      # optional agent defs (plugin agents/)
│   ├── deepsec-investigator.md
│   ├── deepsec-revalidator.md
│   └── deepsec-triager.md
├── scripts/                     # pure logic — NO Node
│   ├── deepsec_cli.py           # argparse entry: scan|status|export|…
│   ├── scan.py                  # glob + matcher engine
│   ├── state.py                 # FileRecord / RunMeta R/W, locks
│   ├── matchers/                # JSON/YAML matcher packs (port of ~110 TS matchers)
│   │   ├── registry.json
│   │   └── **/*.json
│   ├── merge.py                 # additive merge of candidates/findings
│   ├── enrich_git.py            # git committer enrichment
│   ├── export_fmt.py            # JSON / md-dir / report writers
│   └── schemas/                 # JSON Schema for FileRecord, RunMeta, Finding
├── references/                  # prompt templates + data-layout docs for the model
│   ├── process-prompt.md        # port of packages/processor/src/prompt/core.ts
│   ├── revalidate-prompt.md
│   ├── triage-prompt.md
│   ├── severity.md
│   └── data-layout.md           # mirror of deepsec docs/data-layout.md
└── hooks/                       # optional; not required for MVP
    └── hooks.json
```

### `plugin.json` (exact shape expected by `manifest.rs`)

```json
{
  "name": "deepsec",
  "version": "0.1.0",
  "description": "AI-powered vulnerability scanner pipeline (scan → process → revalidate → triage → export) for Grok Build.",
  "author": { "name": "xAI / Grok Build" },
  "license": "Apache-2.0",
  "keywords": ["security", "sast", "vulnerability", "scan"],
  "skills": "skills",
  "agents": "agents"
}
```

Notes from `PluginManifest` (`crates/codegen/xai-grok-agent/src/plugins/manifest.rs`):

- `name` must be kebab-case, 1–64 chars, lowercase alphanumeric + hyphens.
- `skills` / `agents` may be omitted; convention dirs `skills/` and `agents/` are discovered automatically.
- Fallback manifests: `.grok-plugin/plugin.json`, `.claude-plugin/plugin.json`.
- Plugin data dir at runtime: `~/.grok/plugin-data/<plugin_id>/` (`LoadedPlugin::data_dir`).
- Env for hooks (if any): `GROK_PLUGIN_ROOT`, `GROK_PLUGIN_DATA` (+ Claude aliases).

### Install locations (so `/skills`, `/plugins`, autocomplete see it)

| Mode | Path | How enabled |
|------|------|-------------|
| Dev / fork work | `Grok-Fork/plugins/deepsec/` | `zyth plugin install ./plugins/deepsec --trust` or `--plugin-dir` |
| User install | `~/.grok/plugins/deepsec/` | `zyth plugin install <source> --trust` |
| Project team | `<repo>/.grok/plugins/deepsec/` | commit + trust grant; or list in `[plugins].enabled` |
| Config path | any dir | `[plugins] paths = ["…/deepsec"]` + `enabled = ["deepsec"]` |
| Marketplace | source with `plugin-index.json` | `zyth plugin marketplace add …` then install |
| Bundled (optional later) | ship under binary extract → `~/.grok/bundled/` | only if productizing as stock skill |

Skills discovery (`discovery.rs` + user-guide 08):

- Plugin skills load from `plugin.skill_dirs` → each `skills/*/SKILL.md`.
- Appear in slash autocomplete as bare name when unique, else qualified `deepsec:deepsec-scan`.
- `user-invocable: true` (default) → listed in `/` menu and skill tool.
- `argument-hint` drives the gray autocomplete hint string.

### Naming strategy for slash surface

DeepSec’s CLI is `deepsec <subcommand>`. Grok skills cannot natively nest multi-level `/deepsec scan` as separate builtins; two supported patterns:

| Pattern | Slash form | Recommendation |
|---------|------------|----------------|
| **A. Prefixed flat skills** | `/deepsec-scan`, `/deepsec-process`, … | **Primary.** Each skill is its own `skills/deepsec-scan/SKILL.md` with `name: deepsec-scan`. |
| **B. Umbrella + args** | `/deepsec scan …` | `skills/deepsec/SKILL.md` with `name: deepsec`, body dispatches on first arg. |
| **C. Both** | Umbrella + flat aliases | **Ship both:** umbrella for discoverability (`/deepsec`), flat for autocomplete + headless. |

This document uses **C**. Flat skill `name` values are the slash stems; umbrella `deepsec` routes:

```
/deepsec              → help / status overview
/deepsec init …       → invoke deepsec-init body
/deepsec scan …       → deepsec-scan
…
```

---

## 2. Slash commands → skills (exact mapping)

Each row is one `SKILL.md` under `plugins/deepsec/skills/<dir>/`.

Frontmatter fields map to `SkillInfo` in `types.rs` / parser in `discovery.rs`:

| Frontmatter | Meaning |
|-------------|---------|
| `name` | Slash stem + skill tool id |
| `user-invocable` | `true` → shows in `/` and invocable; default true |
| `argument-hint` | Autocomplete hint after the command name |
| `disable-model-invocation` | `true` for destructive / expensive pipeline steps if we want user-only |
| `when-to-use` | Auto-trigger phrases |
| `allowed-tools` | Optional tool allowlist for the skill turn |

### 2.1 `/deepsec` (umbrella)

```yaml
---
name: deepsec
description: >-
  DeepSec security pipeline for this repo: init, scan, process, revalidate,
  triage, enrich, export, status, resume, report. Use when the user mentions
  deepsec, vulnerability scan, SAST, or /deepsec.
when-to-use: deepsec, vulnerability scan, security scan, /deepsec
argument-hint: "[init|scan|process|revalidate|triage|enrich|export|status|resume|report] [args…]"
user-invocable: true
---
```

**Body:** Print pipeline overview; if args present, hand off to the matching sub-skill instructions (or re-read that skill’s `SKILL.md` via `read_file` from `$GROK_PLUGIN_ROOT` / skill path). Prefer running pure-logic subcommands via:

```bash
python3 "${PLUGIN_ROOT}/scripts/deepsec_cli.py" <subcommand> …
```

### 2.2 `/deepsec init` → skill `deepsec-init`

Maps DeepSec `init` / `init-project` (`packages/deepsec/src/commands/init.ts`).

```yaml
---
name: deepsec-init
description: >-
  Scaffold project DeepSec state under .grok/deepsec/ (config, INFO.md,
  project.json). Use for first-time setup or registering another root.
when-to-use: deepsec init, set up deepsec, initialize security scan workspace
argument-hint: "[--id <project-id>] [--root <path>] [--force]"
user-invocable: true
disable-model-invocation: false
---
```

**Actions (skill body):**

1. Resolve project id (basename of root unless `--id`).
2. Create `.grok/deepsec/` workspace (see §4).
3. Write `config.toml` or `config.json`, `data/<id>/project.json`, `INFO.md` template, `SETUP.md`.
4. Optionally append project rules / AGENTS snippet pointing agents at INFO.md.
5. Print next steps: fill INFO.md, then `/deepsec-scan`.

**Pure logic:** `scripts/deepsec_cli.py init` (mkdir + templates). Agent may improve INFO.md after scaffold (like DeepSec’s “paste into coding agent” prompt).

### 2.3 `scan` → skill `deepsec-scan`

Maps `deepsec scan` — free, no AI; regex matchers → candidates.

```yaml
---
name: deepsec-scan
description: >-
  Run DeepSec regex matchers across the project root and write FileRecords
  under .grok/deepsec/data/<id>/files/. No model calls.
when-to-use: deepsec scan, run matchers, find candidate vulnerability sites
argument-hint: "[--project-id <id>] [--root <path>] [--matchers <slugs>]"
user-invocable: true
# Prefer user + model both allowed; scan is cheap.
---
```

**Actions:**

```bash
python3 "$PLUGIN_ROOT/scripts/deepsec_cli.py" scan \
  --project-id <id> [--root <path>] [--matchers a,b]
```

Skill verifies exit code, summarizes `status` counts, suggests `/deepsec-process --limit 20`.

### 2.4 `process` → skill `deepsec-process`

Maps `deepsec process` — expensive AI investigation of pending files.

```yaml
---
name: deepsec-process
description: >-
  Investigate DeepSec candidates with Grok subagents; write findings into
  FileRecords. Supports concurrency, batch-size, limit, filters, resume.
when-to-use: deepsec process, investigate candidates, AI security review of scan hits
argument-hint: "[--project-id <id>] [--limit N] [--concurrency N] [--batch-size N] [--filter prefix] [--run-id id] [--only-slugs csv] [--reinvestigate [N]]"
user-invocable: true
disable-model-invocation: true   # expensive; user-triggered only
---
```

**Actions:** Orchestrator skill (pattern from `implement` / `execute-plan`):

1. `deepsec_cli.py status --json` → pending files.
2. Claim batches via `deepsec_cli.py claim --run-id … --limit …` (sets `lockedByRunId`, `status=processing`).
3. For each batch, `spawn_subagent` with `deepsec-investigator` agent / persona prompt from `references/process-prompt.md` + per-file candidates + INFO.md.
4. Parse structured findings JSON from subagent; `deepsec_cli.py commit-findings …` (append `analysisHistory`, merge `findings`, clear lock).
5. On failure: leave pending/error; user can `/deepsec-resume`.

### 2.5 `revalidate` → skill `deepsec-revalidate`

Maps `deepsec revalidate` — TP/FP/fixed/uncertain on existing findings.

```yaml
---
name: deepsec-revalidate
description: >-
  Re-check existing DeepSec findings for false positives, fixes, and severity.
when-to-use: deepsec revalidate, reduce false positives, verify findings
argument-hint: "[--project-id <id>] [--min-severity SEV] [--force] [--limit N] [--concurrency N] [--only-slugs csv]"
user-invocable: true
disable-model-invocation: true
---
```

**Subagents:** `deepsec-revalidator` (read-only capability preferred). Writes `finding.revalidation` via `deepsec_cli.py commit-revalidation`.

### 2.6 `triage` → skill `deepsec-triage`

Maps `deepsec triage` — P0/P1/P2/skip without deep code reread (cheap model path).

```yaml
---
name: deepsec-triage
description: >-
  Classify DeepSec findings into P0/P1/P2/skip with exploitability and impact.
when-to-use: deepsec triage, prioritize findings, P0 P1 P2
argument-hint: "[--project-id <id>] [--severity SEV] [--limit N] [--force]"
user-invocable: true
disable-model-invocation: true
---
```

**Subagents:** lightweight `deepsec-triager`; may run as single-turn skill without spawn for small sets.

### 2.7 `enrich` → skill `deepsec-enrich`

Maps `deepsec enrich` — git committers (+ optional ownership later).

```yaml
---
name: deepsec-enrich
description: >-
  Attach git committer history (and optional ownership) to FileRecords that
  have findings.
when-to-use: deepsec enrich, who owns this finding, git blame enrich
argument-hint: "[--project-id <id>] [--filter prefix] [--min-severity SEV] [--force]"
user-invocable: true
---
```

**Pure logic only:** `deepsec_cli.py enrich` using `git log` / `git blame` (no AI). Ownership plugins deferred (hooks or Python provider interface later).

### 2.8 `export` → skill `deepsec-export`

Maps `deepsec export`.

```yaml
---
name: deepsec-export
description: >-
  Export DeepSec findings as JSON or a directory of markdown files.
when-to-use: deepsec export, dump findings, export vulnerabilities
argument-hint: "[--format json|md-dir] [--out path] [--project-id id] [--min-severity SEV] [--only-true-positive] [filters…]"
user-invocable: true
---
```

**Pure logic:** `deepsec_cli.py export …` (stdout or files). Skill may also present a short human summary.

### 2.9 `status` → skill `deepsec-status`

Maps `deepsec status`.

```yaml
---
name: deepsec-status
description: >-
  Show DeepSec project mirror state: scanned, pending, processing, analyzed,
  findings by severity, open runs.
when-to-use: deepsec status, scan progress, how many findings
argument-hint: "[--project-id <id>] [--json]"
user-invocable: true
---
```

**Pure logic:** `deepsec_cli.py status`.

### 2.10 `resume` → skill `deepsec-resume`

DeepSec has no separate `resume` binary — resume is “re-run process/revalidate with same flags / `--run-id`”. Grok surfaces an explicit skill for UX parity with `/implement --resume` patterns.

```yaml
---
name: deepsec-resume
description: >-
  Resume an interrupted DeepSec process or revalidate run: reclaim stale locks,
  re-queue error/pending files, continue from --run-id.
when-to-use: deepsec resume, continue interrupted scan process, reclaim locks
argument-hint: "[process|revalidate] [--run-id <id>] [--project-id <id>]"
user-invocable: true
disable-model-invocation: true
---
```

**Actions:** `deepsec_cli.py reclaim-locks` then re-enter `deepsec-process` or `deepsec-revalidate` with stored run config from `runs/<runId>.json`.

### 2.11 `report` → skill `deepsec-report`

Maps `deepsec report` (+ optional `metrics`).

```yaml
---
name: deepsec-report
description: >-
  Generate markdown + JSON DeepSec report under data/<id>/reports/.
when-to-use: deepsec report, security report, findings summary
argument-hint: "[--project-id <id>] [--run-id <id>]"
user-invocable: true
---
```

**Pure logic:** `deepsec_cli.py report`. Skill may open/read the md and narrate highlights.

### Command matrix (DeepSec CLI → Grok)

| DeepSec CLI | Grok skill `name` | `user-invocable` | `argument-hint` (abbrev) | Logic home |
|-------------|-------------------|------------------|--------------------------|------------|
| `deepsec` (help) | `deepsec` | true | `[init\|scan\|…]` | skill body |
| `deepsec init` | `deepsec-init` | true | `[--id] [--root] [--force]` | `scripts/` + agent INFO fill |
| `deepsec init-project` | fold into `deepsec-init` | true | same | `scripts/` |
| `deepsec scan` | `deepsec-scan` | true | `[--project-id] [--matchers]` | **Python only** |
| `deepsec process` | `deepsec-process` | true | `[--limit] [--concurrency]…` | scripts claim/commit + **subagents** |
| `deepsec revalidate` | `deepsec-revalidate` | true | `[--min-severity] [--force]…` | scripts + **subagents** |
| `deepsec triage` | `deepsec-triage` | true | `[--severity] [--limit]` | scripts + **subagents** / single turn |
| `deepsec enrich` | `deepsec-enrich` | true | `[--filter] [--min-severity]` | **Python + git** |
| `deepsec export` | `deepsec-export` | true | `[--format] [--out]…` | **Python only** |
| `deepsec status` | `deepsec-status` | true | `[--project-id] [--json]` | **Python only** |
| (implicit re-run) | `deepsec-resume` | true | `[process\|revalidate] [--run-id]` | scripts + skill re-entry |
| `deepsec report` / `metrics` | `deepsec-report` | true | `[--project-id] [--run-id]` | **Python only** |
| `deepsec sandbox*` | **out of scope v1** | — | — | use Grok `--sandbox` instead |

---

## 3. Where pure logic lives

### Principle

| Stage | DeepSec today | Grok Build mapping | Why |
|-------|---------------|--------------------|-----|
| Matcher scan | TS `packages/scanner` | **`scripts/scan.py` + JSON matcher packs** | Deterministic, free, must be fast/reliable; agent-only scanning is flaky and expensive |
| State / locks / merge | TS `@deepsec/core` | **`scripts/state.py`** | Atomic claim/commit, schema validation — not LLM |
| Init templates | TS `init.ts` | **`scripts/` templates** | File layout consistency |
| Enrich git | TS enrich | **`scripts/enrich_git.py`** | `git` CLI |
| Export / report / status | TS | **`scripts/`** | Pure transform |
| Process / revalidate / triage AI | Codex/Claude/Pi SDKs | **Grok session + `spawn_subagent`** | Grok *is* the agent backend; no external agent SDKs |
| Prompt assembly | TS `prompt/assemble.ts` | **`references/*.md` + skill body** | Skill loads INFO.md, candidates, highlights |
| Matchers authoring | TS plugins | **JSON matchers + optional skill to draft new ones** | Zero Node |
| Notifiers / ownership / executor | DeepSec plugin slots | **Defer v1**; later hooks / MCP / Python providers | Not required for core pipeline |

### Prefer skill scripts over agent-only

Pattern matches bundled skills:

- `~/.grok/bundled/skills/implement/scripts/memory.py`
- `~/.grok/bundled/skills/execute-plan/scripts/validate-plan.py`
- `~/.grok/bundled/skills/docx|pptx/scripts/*.py`

DeepSec skill bodies **must** call scripts for any state mutation:

```text
# SKILL.md excerpt
PLUGIN_ROOT = dirname(SKILL.md)/../..   # plugins/deepsec
CLI = python3 ${PLUGIN_ROOT}/scripts/deepsec_cli.py

1. Run: ${CLI} status --project-id … --json
2. Parse JSON; do not invent FileRecord fields.
3. Only then spawn subagents / summarize.
```

### Optional small Rust helper (later)

If Python scan is too slow on huge monorepos, add:

```
crates/codegen/xai-deepsec-scan/   # optional workspace crate
```

or a standalone `deepsec-scan` binary next to the plugin. **Not required for MVP.** Prefer Python first for portability in skill `run_terminal_cmd` without linking into the agent binary.

### What stays agent-only (by design)

- Interpreting candidate context → real findings (process).
- TP/FP/fixed reasoning with git history (revalidate).
- Priority classification (triage).
- Authoring / refining INFO.md and custom matchers from findings.

---

## 4. State paths: `.grok/deepsec/` vs `~/.grok/deepsec/`

### DeepSec original

- Workspace: repo `./.deepsec/` (config, `package.json`, pnpm).
- Data root: `./data/<projectId>/` relative to CWD when running CLI (or `DEEPSEC_DATA_ROOT`), typically inside `.deepsec/data/` after init.
- Layout (`docs/data-layout.md`):

```
data/<projectId>/
├── project.json
├── INFO.md
├── config.json
├── files/**/*.json      # FileRecord
├── runs/<runId>.json    # RunMeta
└── reports/
```

### Grok Build mapping (exact)

| Kind | Path | Purpose |
|------|------|---------|
| **Project workspace (canonical)** | `<repo>/.grok/deepsec/` | Versionable config + project registry; **team-shared** via git |
| **Project data** | `<repo>/.grok/deepsec/data/<projectId>/` | FileRecords, runs, reports (gitignore by default) |
| **Project config** | `<repo>/.grok/deepsec/config.toml` | projects[], default matchers, ignorePaths, priorityPaths |
| **User global defaults** | `~/.grok/deepsec/config.toml` | User-wide defaults (model effort, concurrency caps) — optional |
| **Plugin install tree** | `~/.grok/plugins/deepsec/` or marketplace cache | Read-only skills/scripts |
| **Plugin writable data** | `~/.grok/plugin-data/<plugin_id>/` | Caches, downloaded matcher packs, metrics — **not** per-repo findings |
| **Scratch** | `${TMPDIR:-/tmp}/grok-$(id -u)/deepsec-…` | Batch prompts, temp JSON (same pattern as implement skill) |

**Do not** store FileRecords only under `~/.grok/plugin-data/…`: findings must live next to the repo so CI and teammates share them, matching DeepSec’s “data travels with the workspace” model.

### Gitignore recommendation (written by `deepsec-init`)

```
# <repo>/.grok/deepsec/.gitignore
data/*/files/
data/*/runs/
data/*/reports/
*.lock
```

Keep `data/*/INFO.md`, `project.json`, and optional `config.json` committable.

### Resolution algorithm (`scripts/state.py`)

```
1. If env DEEPSEC_DATA_ROOT set → use it (compat with upstream DeepSec).
2. Else walk cwd→root for .grok/deepsec/config.toml → data dir = that/data.
3. Else if .deepsec/data exists (upstream layout) → read-only compat import path.
4. Else error: run /deepsec-init.
```

Project id: single project auto-selected; multi-project requires `--project-id`.

---

## 5. Sub-agents for process / revalidate / triage

### Plugin agents (optional but recommended)

Under `plugins/deepsec/agents/`:

| File | Role | Tools posture |
|------|------|----------------|
| `deepsec-investigator.md` | process | read + shell (git/read only); **no** exploit execution; write only via instructed JSON output file |
| `deepsec-revalidator.md` | revalidate | read + git history; verdict JSON |
| `deepsec-triager.md` | triage | findings JSON only; no full tree walk |

Agent definitions follow Grok agent `.md` format (same as `~/.grok/bundled/agents/explore.md`). Skills may also use `subagent_type: "general-purpose"` + prompt-injected persona text (pattern used by `/implement`) if custom agents are not yet registered.

### Spawn pattern (`deepsec-process`)

```
for batch in batches:
  spawn_subagent(
    subagent_type = "general-purpose",   # or deepsec-investigator when wired
    description   = "[deepsec-process] batch <n>",
    background    = true if concurrency > 1,
    capability_mode = "execute",         # read + shell for git/code read
    # isolation: none — must see real repo + .grok/deepsec state
    prompt = process-prompt.md
             + INFO.md
             + candidate FileRecords
             + "Write findings JSON to <scratch>/batch-<n>.json"
  )
wait / gather
deepsec_cli.py commit-findings --batch-file …
```

Rules (from DeepSec design + Grok subagent guide):

- **One file unit of work** still preferred; batch-size default 5 like DeepSec.
- **No worktree isolation** for investigators (they must annotate shared state via CLI, not edit product code).
- **Static analysis only** — process prompt forbids exploitation (port `CORE_PROMPT` from `packages/processor/src/prompt/core.ts`).
- **Concurrency:** orchestrator skill launches up to `--concurrency` background subagents; claim locks in Python so workers never double-write.
- **Resume:** incomplete locks with dead `pid` reclaimed by `reclaim-locks` (port `pid`/`hostname` fields from DeepSec `RunMeta`).

### Personas (optional overlay)

Can also ship:

```
plugins/deepsec/personas/  # if product supports plugin personas later
```

Until then, keep persona text inside agent md / skill prompts. Bundled `security-auditor` persona is related but **not** a substitute for DeepSec’s structured Finding schema.

---

## 6. Headless: `grok -p "/deepsec …"`

From user-guide 14-headless-mode:

```bash
# Umbrella
grok -p "/deepsec status" --yolo
grok -p "/deepsec scan --project-id my-app" --yolo

# Flat skills (more reliable for scripting)
grok -p "/deepsec-scan --project-id my-app" --yolo
grok -p "/deepsec-process --project-id my-app --limit 50 --concurrency 3" --yolo
grok -p "/deepsec-export --format json --out findings.json" --yolo

# Machine-readable
grok -p "/deepsec-status --json" --output-format json --yolo

# Sandbox the whole run (OS landlock/seatbelt — not Vercel Sandbox)
grok --sandbox workspace -p "/deepsec-scan" --yolo
```

Notes:

- `-p` / `--single` triggers headless; skill slash is expanded like TUI.
- Expensive skills have `disable-model-invocation: true` so they only run when the **user prompt** explicitly includes the slash form — still works headless because the prompt contains `/deepsec-process …`.
- For CI, prefer **direct Python** when no LLM is needed:

```bash
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py scan --project-id my-app
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py status --json
```

Use `grok -p` only for process/revalidate/triage.

Alias: live installs may expose binary as `grok` or `zyth`; document both.

---

## 7. Packaging so `/skills`, `/plugins`, autocomplete see deepsec

### Discovery chain

1. **Plugin enabled** → `PluginRegistry` loads `skills/` → each SKILL.md becomes `SkillInfo` with `scope=Plugin`, `plugin_name=deepsec`.
2. Slash autocomplete merges plugin skills with user/repo/bundled skills (`user_invocable=true` only).
3. `/skills` modal and `zyth inspect` list them with source `plugin: deepsec`.
4. `/plugins` modal shows component inventory (skill names from directory basenames).

### Required packaging steps (implementation)

| Step | Fork path / command |
|------|---------------------|
| Author plugin tree | `Grok-Fork/plugins/deepsec/` as in §1 |
| Validate manifest | `zyth plugin validate plugins/deepsec` |
| Local install | `zyth plugin install ./plugins/deepsec --trust` |
| Enable | ensure not in `[plugins].disabled`; project plugins need `[plugins].enabled = ["deepsec"]` if disabled-by-default |
| Verify | `zyth plugin details deepsec`; `zyth inspect` shows skills; type `/deepsec` in TUI |
| Dev loop without install | `zyth agent --plugin-dir /home/elliot/Grok-Fork/plugins/deepsec …` or config `paths` |
| Marketplace (later) | add repo to marketplace source + `plugin-index.json` entry `{ "name": "deepsec", "source": "…", "sha": "…" }` |

### Autocomplete `argument-hint`

Each skill’s frontmatter `argument-hint` is what the gray text shows after `/deepsec-scan ` — keep them accurate (mirrors commander options).

### Collision policy

- Bare `/status` will **not** steal Grok’s builtins; our names are `deepsec-*` / `deepsec`.
- If a user skill is also named `deepsec`, higher priority scope wins; plugin form remains `deepsec:deepsec` / qualified names.

### Optional: also install thin repo skills

`deepsec-init` may write:

```
<repo>/.grok/skills/deepsec-scan/SKILL.md  # optional shim redirecting to plugin
```

Prefer **not** duplicating — plugin install alone is enough if enabled.

---

## 8. Zero Node dependency strategy

### Why

Upstream DeepSec is a Node 22+ monorepo (`packages/core|scanner|processor|deepsec`), pnpm, Commander, TS matchers, Codex/Claude/Pi SDKs. Grok Build skills already standardize on **Python helpers + markdown prompts**. Pulling Node for scan would break sandbox-minimal and CI images that only have `grok` + Python.

### Strategy

| Upstream package | Zero-Node replacement |
|------------------|------------------------|
| `packages/scanner` (~110 matchers) | Port matchers to **JSON** (`slug`, `filePatterns`, `regexes[]`, `noiseTier`, `requires.tech`) + `scan.py` engine using Python `pathlib` + `re` + optional `ripgrep` subprocess for speed |
| `packages/core` schemas | `scripts/schemas/*.json` + pydantic or hand validation in `state.py` |
| `packages/core` paths/run locks | `state.py` (same relative layout under `.grok/deepsec/data`) |
| `packages/processor` agents | Grok `spawn_subagent` + `references/process-prompt.md` |
| `packages/processor` prompt assemble | Skill stitches INFO.md + tech highlights markdown files |
| `packages/deepsec` CLI | `scripts/deepsec_cli.py` argparse |
| `deepsec.config.ts` | `.grok/deepsec/config.toml` (or JSON) — no TS runtime |
| Vercel Sandbox executor | Grok `--sandbox workspace\|strict` |
| AI Gateway / multi SDK | Grok auth + model flags (`-m`, `/effort`) |

### Matcher port approach

1. One-time extract from DeepSec TS matchers → `matchers/registry.json` (codegen script can run **once** in the fork build, not at user runtime).
2. Runtime: pure Python loads JSON only.
3. Custom matchers: user drops JSON under `.grok/deepsec/matchers/*.json` (replaces TS plugin matchers).

### Runtime dependencies (user machine)

- `python3` (3.10+)
- `git` (enrich + revalidate history)
- `grok`/`zyth` (AI stages)
- optional: `rg` for faster file listing (Grok already vendors rg under `~/.grok/vendor/`)

**No** `node`, `npm`, `pnpm`, `npx`.

### Compat import

```bash
python3 …/deepsec_cli.py import-deepsec --from ./.deepsec/data
```

Copies FileRecords into `.grok/deepsec/data/` for users migrating from upstream.

---

## 9. DeepSec plugin slots → Grok extensions (secondary)

| DeepSec slot | Grok Build home |
|--------------|-----------------|
| `matchers` | `.grok/deepsec/matchers/*.json` + bundled packs under plugin `scripts/matchers/` |
| `notifiers` | Later: `hooks/hooks.json` on run complete, or skill step calling Slack/GitHub CLI |
| `ownership` / `people` | Later: Python provider module path in config |
| `executor` | Grok sandbox profiles + optional remote via MCP |
| `agents` (codex/claude/pi) | **Eliminated** — Grok is the only agent |
| `commands` (commander) | Plugin skills |

---

## 10. Concrete fork file checklist (eventual implementation)

```
/home/elliot/Grok-Fork/
├── plugins/deepsec/                          # NEW plugin root
│   ├── plugin.json
│   ├── skills/deepsec*/SKILL.md              # 11 skills (§2)
│   ├── agents/*.md
│   ├── scripts/*.py
│   ├── scripts/matchers/**
│   └── references/**
├── docs/analysis/
│   ├── 06-grok-build-mapping.md              # this file
│   └── (related analysis docs as needed)
└── crates/codegen/                           # optional later:
    └── xai-deepsec-scan/                     # Rust accelerator
```

No changes required to `manifest.rs` / skills discovery for MVP — convention layout is enough.

Wire-up validation commands:

```bash
zyth plugin validate /home/elliot/Grok-Fork/plugins/deepsec
zyth plugin install /home/elliot/Grok-Fork/plugins/deepsec --trust
zyth inspect --json | jq '.skills[] | select(.plugin_name=="deepsec")'
```

---

## 11. Recommended implementation order

1. **Scaffold plugin skeleton** — `plugin.json`, empty skills with frontmatter only, `scripts/deepsec_cli.py --help`; install + confirm autocomplete lists `/deepsec-*`.
2. **State layer** — `state.py` implementing FileRecord/RunMeta paths under `.grok/deepsec/data/`; `init` + `status` skills green.
3. **Scanner MVP** — port 10–20 high-value matchers to JSON; `scan` skill writes candidates; e2e on DeepSec `fixtures/vulnerable-app`.
4. **Full matcher pack** — bulk-port remaining matchers; tech gate (`requires`) parity.
5. **Process orchestrator** — `deepsec-process` skill + prompt port + claim/commit; single-concurrency first, then batches.
6. **Revalidate + triage** — second/third prompts + skills; subagent templates.
7. **Enrich / export / report** — pure Python; headless CI examples.
8. **Resume + lock reclaim** — pid/hostname stale detection; `deepsec-resume`.
9. **Polish** — umbrella `/deepsec` router, INFO.md agent fill, import-from-`.deepsec`, marketplace packaging, optional Rust scan accel.
10. **Docs** — user-facing guide under `docs/` or plugin README; link from analysis index.

---

## 5-line summary

DeepSec becomes a Grok **plugin** (`plugins/deepsec/plugin.json` + `skills/` + Python `scripts/`), not a Node CLI. Each CLI subcommand maps to a **user-invocable skill** (`deepsec-scan`, `deepsec-process`, …) with explicit `argument-hint`s; AI stages use **Grok subagents**, deterministic stages use **scripts only**. Project state lives in **`.grok/deepsec/data/<id>/`** (DeepSec-compatible FileRecords); plugin install data stays in **`~/.grok/plugin-data/`**. Headless is **`grok -p "/deepsec-scan …"`** (or direct `python3 …/deepsec_cli.py` for free stages). **Zero Node:** JSON matchers + Python + Grok replace the entire TS monorepo and external agent SDKs.
