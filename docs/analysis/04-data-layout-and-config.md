# 04 — DeepSec data layout and configuration

Analysis of on-disk schemas and config from the deepsec implementer tree
(`/tmp/grok-goal-f8e64663ee8a/implementer/deepsec`). Sources of truth:

| Source | Role |
|---|---|
| `docs/data-layout.md`, `docs/configuration.md`, `docs/plugins.md` | Product docs |
| `packages/core/src/types.ts`, `schemas.ts`, `config.ts`, `paths.ts`, `run.ts` | Type + Zod schemas + paths + I/O |
| `packages/deepsec/src/load-config.ts`, `commands/export.ts`, `commands/report.ts` | Config load + export/report |
| `packages/deepsec/src/sandbox/merge-records.ts`, `data-commit.ts` | Concurrent merge + commit scrub |
| `packages/scanner/src/index.ts`, `packages/processor/src/index.ts` | Scan/process write semantics |
| `packages/deepsec/src/commands/init.ts` | `.deepsec` workspace scaffold |
| `samples/webapp/{deepsec.config.ts,config.json}` | Worked examples |

---

## 1. On-disk layout (deepsec)

`data/` is deepsec's on-disk state. Default root: `./data` (cwd-relative),
overridable by `DeepsecConfig.dataDir` or env `DEEPSEC_DATA_ROOT`. Each
project owns a subdirectory; content is **append-oriented / merge-safe**
across runs (see §5).

```
data/<projectId>/
├── project.json              # ProjectConfig (rootPath, githubUrl, …)
├── INFO.md                   # free-form repo context for AI prompts
├── SETUP.md                  # agent prompt for filling INFO.md (scaffold)
├── config.json               # priorityPaths, promptAppend, ignorePaths (optional)
├── tech.json                 # detected tech tags (written by scan)
├── files/                    # one JSON per scanned source file (FileRecord)
│   └── path/to/source.ts.json
├── runs/                     # one JSON per run (RunMeta)
│   └── 20260429215021-<hex>.json
├── reports/                  # generated markdown + JSON (+ optional CSV path helpers)
│   ├── report.md
│   ├── report.json
│   └── report-<runId>.{md,json}   # when filtered by --run-id
└── .process.lock/            # ephemeral claim mutex (mkdir lock)
```

Path helpers (`packages/core/src/paths.ts`):

| Helper | Path |
|---|---|
| `dataDir(projectId)` | `{dataRoot}/{projectId}` |
| `projectConfigPath` | `…/project.json` |
| `fileRecordPath` | `…/files/{filePath}.json` (mirrors source tree) |
| `runMetaPath` | `…/runs/{runId}.json` |
| `reportMdPath` / `reportJsonPath` / `reportCsvPath` | `…/reports/report[-{runId}].{md,json,csv}` |

`assertSafeSegment` rejects `..`, absolute paths, null bytes, and path
separators in `projectId` / `runId`. `assertSafeFilePath` allows `/`
segments but rejects `..`, `\`, absolute paths.

### Workspace scaffold (`.deepsec`)

`npx deepsec init` creates a self-contained workspace (default dir
`.deepsec/`) next to the scanned codebase:

```
.deepsec/
├── package.json              # private workspace; deps: deepsec
├── pnpm-workspace.yaml       # packages: [] (severs ancestor monorepo)
├── deepsec.config.ts         # multi-root project list
├── AGENTS.md
├── README.md
├── .gitignore                # ignores data/** findings, node_modules, .env*
├── .env.local                # credentials (gitignored)
├── matchers/                 # optional custom matchers (user-added)
└── data/<projectId>/
    ├── project.json
    ├── INFO.md               # template → hand-curated (often committed)
    └── SETUP.md
```

`init-project <root>` appends another `projects[]` entry and creates
another `data/<id>/` tree. Paths in config resolve relative to the config
file / parent of the workspace.

---

## 2. Field tables

Schemas below mirror `packages/core/src/types.ts` + Zod in `schemas.ts`.
Optional fields used for backward compatibility are marked `?`.

### 2.1 `ProjectConfig` — `project.json`

| Field | Type | Purpose |
|---|---|---|
| `projectId` | `string` | Matches directory name under `data/`. |
| `rootPath` | `string` | Absolute path to the codebase; updated each scan with latest `--root`. |
| `createdAt` | `string` (ISO) | Project init time. |
| `githubUrl` | `string?` | `https://github.com/owner/repo/blob/branch` for export links; auto from `git remote` if unset. |

**JSON example:**

```json
{
  "projectId": "my-app",
  "rootPath": "/home/dev/code/my-app",
  "createdAt": "2026-04-29T21:50:21.000Z",
  "githubUrl": "https://github.com/acme/my-app/blob/main"
}
```

### 2.2 `CandidateMatch` — elements of `FileRecord.candidates`

| Field | Type | Purpose |
|---|---|---|
| `vulnSlug` | `string` | Matcher slug that fired. |
| `lineNumbers` | `number[]` | 1-indexed source lines. |
| `snippet` | `string` | Short excerpt around the first match (may be redacted on data-commit for secret slugs). |
| `matchedPattern` | `string` | Human-readable label of the regex (matcher `label`). |

**JSON example:**

```json
{
  "vulnSlug": "sql-injection",
  "lineNumbers": [42, 43],
  "snippet": "db.query(`SELECT * FROM users WHERE id = ${id}`)",
  "matchedPattern": "string-interpolated SQL"
}
```

### 2.3 `Finding`

| Field | Type | Purpose |
|---|---|---|
| `severity` | `"CRITICAL" \| "HIGH" \| "MEDIUM" \| "HIGH_BUG" \| "BUG" \| "LOW"` | Severity bucket. |
| `vulnSlug` | `string` | Matcher slug or `other-<topic>`. |
| `title` | `string` | One-sentence summary. |
| `description` | `string` | Full explanation. |
| `lineNumbers` | `number[]` | 1-indexed lines. |
| `recommendation` | `string` | Suggested fix. |
| `confidence` | `"high" \| "medium" \| "low"` | Agent self-rated confidence. |
| `triage` | `Triage?` | Set by `deepsec triage`. |
| `revalidation` | `Revalidation?` | Set by `deepsec revalidate` (or manual `accepted-risk`). |
| `producedByRunId` | `string?` | Run that first surfaced this finding; set once at append, never updated. |

#### Nested: `Triage`

| Field | Type | Purpose |
|---|---|---|
| `priority` | `"P0" \| "P1" \| "P2" \| "skip"` | Action bucket. |
| `exploitability` | `"trivial" \| "moderate" \| "difficult"` | Effort to weaponize. |
| `impact` | `"critical" \| "high" \| "medium" \| "low"` | Blast radius. |
| `reasoning` | `string` | Why this priority. |
| `triagedAt` | `string` (ISO) | Timestamp. |
| `model` | `string` | Model used. |

#### Nested: `Revalidation`

| Field | Type | Purpose |
|---|---|---|
| `verdict` | `"true-positive" \| "false-positive" \| "fixed" \| "uncertain" \| "accepted-risk" \| "duplicate"` | Re-check result. `accepted-risk` is manual only; `duplicate` points at primary via `duplicateOf`. |
| `reasoning` | `string` | Why this verdict (git evidence if `fixed`). |
| `adjustedSeverity` | `Severity?` | Re-rated severity if changed. |
| `duplicateOf` | `string?` | Title of primary finding when `verdict === "duplicate"`. |
| `revalidatedAt` | `string` (ISO) | Timestamp. |
| `runId` | `string` | Revalidate run id. |
| `model` | `string` | Model used. |

**JSON example:**

```json
{
  "severity": "HIGH",
  "vulnSlug": "sql-injection",
  "title": "Unparameterized SQL in user lookup",
  "description": "User-controlled `id` is interpolated into a SQL string.",
  "lineNumbers": [42],
  "recommendation": "Use a parameterized query or query builder.",
  "confidence": "high",
  "producedByRunId": "20260429215021-19ac",
  "triage": {
    "priority": "P1",
    "exploitability": "moderate",
    "impact": "high",
    "reasoning": "Authenticated endpoint but company-scoped.",
    "triagedAt": "2026-04-30T01:00:00.000Z",
    "model": "claude-opus-4-8"
  },
  "revalidation": {
    "verdict": "true-positive",
    "reasoning": "Still present on HEAD; no fix commit.",
    "revalidatedAt": "2026-04-30T02:00:00.000Z",
    "runId": "20260430020000-abcd",
    "model": "claude-opus-4-8"
  }
}
```

### 2.4 `AnalysisEntry` (append-only log on `FileRecord`)

| Field | Type | Purpose |
|---|---|---|
| `runId` | `string` | Producing run. |
| `investigatedAt` | `string` (ISO) | Timestamp. |
| `durationMs` | `number` | Wall-clock (per-file share of batch). |
| `durationApiMs` | `number?` | API time only. |
| `agentType` | `string` | e.g. `claude-agent-sdk`, `codex`. |
| `model` | `string` | Model identifier. |
| `modelConfig` | `Record<string, unknown>` | Provider settings echo. |
| `agentSessionId` | `string?` | Session/thread id for replay. |
| `findingCount` | `number` | Net-new findings from this entry. |
| `numTurns` | `number?` | Conversation turns (may be split across batch). |
| `phase` | `"process" \| "revalidate"?` | Missing → treat as `process`. |
| `costUsd` | `number?` | Per-file share of batch cost. |
| `usage` | `{ inputTokens, outputTokens, cacheReadInputTokens, cacheCreationInputTokens }?` | Per-file token share. |
| `refusal` | `RefusalReport?` | Partial/full refusal. |
| `codexStderr` | `string?` | Forensic stderr when 0 output tokens. |
| `reinvestigateMarker` | `number?` | Wave marker from `--reinvestigate <N>`. |

#### Nested: `RefusalReport`

| Field | Type | Purpose |
|---|---|---|
| `refused` | `boolean` | True if agent skipped/declined any part. |
| `reason` | `string?` | Free-form reason. |
| `skipped` | `Array<{ filePath?: string; reason: string }>?` | Per-file skips. |
| `raw` | `string?` | Trimmed raw follow-up response. |

### 2.5 `FileRecord` — `files/<path>.json`

Core per-file accumulator. Stages **add**; they do not wholesale replace
history. On-disk path mirrors source under `rootPath` + `.json` suffix
(`src/api/auth.ts` → `files/src/api/auth.ts.json`).

| Field | Type | Purpose |
|---|---|---|
| `filePath` | `string` | Path relative to `rootPath`. |
| `projectId` | `string` | Owning project. |
| `candidates` | `CandidateMatch[]` | Regex matcher hits; merged across scans. |
| `lastScannedAt` | `string` (ISO) | Most recent scan timestamp. |
| `lastScannedRunId` | `string` | runId of last scan that touched this file. |
| `fileHash` | `string` (sha-256) | Source content hash at last scan. |
| `findings` | `Finding[]` | Accumulated AI findings (deduped by signature on re-process). |
| `analysisHistory` | `AnalysisEntry[]` | Append-only log of every AI investigation. |
| `gitInfo` | `object?` | Committers + ownership from `enrich`. |
| `status` | `"pending" \| "processing" \| "analyzed" \| "error"` | Lifecycle state. |
| `lockedByRunId` | `string?` | Run holding the file during process. |
| `lockedAt` | `string?` (ISO) | When lock was taken (stale-lock reclaim). |

#### Nested: `gitInfo`

| Field | Type | Purpose |
|---|---|---|
| `recentCommitters` | `Array<{ name, email, date }>` | Top recent contributors. |
| `enrichedAt` | `string` (ISO) | Last enrich time. |
| `ownership` | `OwnershipData?` | Plugin ownership oracle payload. |

#### Nested: `OwnershipData` (summary)

| Field | Type | Purpose |
|---|---|---|
| `contributors` | `OwnershipContributor[]` | email, name, github_username, score, context, last_contrib |
| `escalationTeams` | `OwnershipEscalationTeam[]` | teams, manager, current_oncall, slack channels |
| `approvers` | `OwnershipApprover[]` | owner, owner_type, pattern, is_primary, is_direct |
| `fetchedAt` | `string` (ISO) | Fetch time |

**Status lifecycle:**

```
pending  →  processing (lockedByRunId set)  →  analyzed
                                           ↘  error (retryable)
```

Re-scan does **not** reset `analyzed` → `pending` (preserves prior analysis).

**JSON example (abbreviated):**

```json
{
  "filePath": "src/api/users.ts",
  "projectId": "my-app",
  "candidates": [
    {
      "vulnSlug": "sql-injection",
      "lineNumbers": [42],
      "snippet": "db.query(`SELECT * …`)",
      "matchedPattern": "string-interpolated SQL"
    }
  ],
  "lastScannedAt": "2026-04-29T21:50:21.000Z",
  "lastScannedRunId": "20260429215021-19ac",
  "fileHash": "e3b0c44298fc1c149afbf4c8996fb924…",
  "findings": [],
  "analysisHistory": [],
  "status": "pending"
}
```

### 2.6 `RunMeta` — `runs/<runId>.json`

| Field | Type | Purpose |
|---|---|---|
| `runId` | `string` | `<YYYYMMDDHHmmss>-<hex>`; sortable. (Docs say rand4; implementation uses 16 hex chars / 64 bits.) |
| `projectId` | `string` | Owning project. |
| `rootPath` | `string` | Resolved root for the run. |
| `createdAt` | `string` (ISO) | Start. |
| `completedAt` | `string?` (ISO) | End (absent while running). |
| `type` | `"scan" \| "process" \| "revalidate"` | Stage. |
| `phase` | `"running" \| "done" \| "error"` | Terminal status. |
| `pid` | `number?` | OS pid of run owner (crash reclaim). |
| `hostname` | `string?` | Host for pid liveness scope. |
| `scannerConfig` | `object?` | Scan-only config. |
| `processorConfig` | `object?` | Process/revalidate config. |
| `stats` | `object` | Counters (see below). |

#### `scannerConfig`

| Field | Type | Purpose |
|---|---|---|
| `matcherSlugs` | `string[]` | Matchers that ran. |
| `mode` | `"full" \| "files"?` | Whole-repo vs explicit file list. |
| `source` | `string?` | e.g. `git-diff:origin/main`, `files:cli`. |
| `fileCount` | `number?` | Size of explicit list when `mode === "files"`. |

#### `processorConfig`

| Field | Type | Purpose |
|---|---|---|
| `agentType` | `string` | Backend id. |
| `model` | `string` | Model id. |
| `modelConfig` | `Record<string, unknown>` | Provider settings. |
| `invocationMode` | `"scan" \| "direct"?` | Queue vs explicit file list. |
| `source` | `string?` | Origin label for direct mode. |

#### `stats` (all optional counters)

| Field | Type |
|---|---|
| `filesScanned` | `number?` |
| `candidatesFound` | `number?` |
| `filesProcessed` | `number?` |
| `findingsCount` | `number?` |
| `totalCostUsd` | `number?` |
| `totalInputTokens` | `number?` |
| `totalOutputTokens` | `number?` |
| `totalDurationMs` | `number?` |
| `findingsRevalidated` | `number?` |
| `truePositives` | `number?` |
| `falsePositives` | `number?` |
| `fixed` | `number?` |
| `uncertain` | `number?` |
| `duplicates` | `number?` |

**JSON example:**

```json
{
  "runId": "20260429215021-a1b2c3d4e5f67890",
  "projectId": "my-app",
  "rootPath": "/home/dev/code/my-app",
  "createdAt": "2026-04-29T21:50:21.000Z",
  "completedAt": "2026-04-29T21:55:00.000Z",
  "type": "process",
  "phase": "done",
  "pid": 12345,
  "hostname": "devbox",
  "processorConfig": {
    "agentType": "claude-agent-sdk",
    "model": "claude-opus-4-8",
    "modelConfig": {},
    "invocationMode": "scan"
  },
  "stats": {
    "filesProcessed": 12,
    "findingsCount": 4,
    "totalCostUsd": 3.42
  }
}
```

---

## 3. Export and report formats

Two command families write consumer-facing output.

### 3.1 `deepsec export` — formats: `json`, `md-dir`

CLI (`packages/deepsec/src/commands/export.ts`):

| Flag | Notes |
|---|---|
| `--format json` | Default. Single JSON array of `ExportedFinding`. stdout or `--out file`. |
| `--format md-dir` | Requires `--out <dir>`. One markdown file per finding. |
| Filters | `--min-severity`, `--only-severity`, `--discovered-today`, `--since`, `--only-true-positive`, `--include-resolved`, `--only-slugs`, `--skip-slugs`, `--require-owner`, `--only-agent`, `--only-marker`, multi `--project-id` |

**Default filter:** hide verdicts `fixed`, `false-positive`, `accepted-risk`, `duplicate` unless `--include-resolved`.

#### `json` — `ExportedFinding[]`

Each element:

```json
{
  "title": "[HIGH] Unparameterized SQL in user lookup",
  "description": "**File:** [`src/api/users.ts`](https://github.com/…)\n…",
  "severity": "HIGH",
  "labels": [
    "security",
    "project:my-app",
    "severity:HIGH",
    "slug:sql-injection",
    "confidence:high",
    "revalidation:true-positive"
  ],
  "assignee": "oncall@acme.com",
  "metadata": {
    "projectId": "my-app",
    "filePath": "src/api/users.ts",
    "lineNumbers": [42],
    "severity": "HIGH",
    "vulnSlug": "sql-injection",
    "confidence": "high",
    "discoveredAt": "2026-04-29T22:00:00.000Z",
    "runId": "20260429220000-…",
    "revalidation": { "verdict": "true-positive", "reasoning": "…" },
    "githubUrl": "https://github.com/acme/my-app/blob/main/src/api/users.ts#L42",
    "owners": {
      "assignee": "oncall@acme.com",
      "assigneeSource": "oncall",
      "teams": [{ "name": "Platform", "slug": "platform" }],
      "oncall": [],
      "managers": [],
      "contributors": [],
      "recentCommitters": []
    }
  }
}
```

Sort order: severity (CRITICAL first) → projectId → filePath.

#### `md-dir` structure

```
<out>/
├── CRITICAL/
│   └── <project>-<slug>-<sha1-10>.md
├── HIGH/
│   └── …
├── MEDIUM/
├── HIGH_BUG/
├── BUG/
└── LOW/
```

- Filename: `{safeProject}-{safeSlug}-{sha1(projectId\\0filePath\\0lines\\0slug)[0:10]}.md`
- Body: `# {title}\n\n{description}\n` (description is the rich markdown built for export)
- **Stale sweep:** severity subdirs are owned namespaces; files not in the current export set are deleted; empty severity dirs removed.

### 3.2 `deepsec report` — markdown + JSON under `reports/`

Not the same as `export --format json`. Report is a project-level
aggregate of **analyzed** files (optional `--run-id` filter).

| Artifact | Path | Behavior |
|---|---|---|
| Markdown | `data/<id>/reports/report.md` or `report-<runId>.md` | Full narrative by severity (CRITICAL…BUG); includes committers, revalidation notes |
| JSON | `data/<id>/reports/report.json` or `report-<runId>.json` | Summary + per-file findings + analysisHistory |

**Report JSON shape:**

```json
{
  "projectId": "my-app",
  "generatedAt": "2026-04-30T03:00:00.000Z",
  "runId": null,
  "summary": {
    "filesAnalyzed": 40,
    "totalFindings": 12,
    "critical": 1,
    "high": 4,
    "medium": 5,
    "highBug": 1,
    "bug": 1
  },
  "files": [
    {
      "filePath": "src/api/users.ts",
      "findings": [/* Finding[] */],
      "analysisHistory": [/* AnalysisEntry[] */]
    }
  ]
}
```

Re-running `report` **overwrites** these files (not incremental).
Path helpers also define `reportCsvPath` for future/adjacent use.

### 3.3 Format summary

| Consumer need | Command | Format |
|---|---|---|
| Issue-tracker pipeline | `export --format json` | Array of `ExportedFinding` |
| Reviewer file tree | `export --format md-dir --out ./findings` | Severity folders + one `.md` per finding |
| Human project report | `report` | `reports/report.md` + `reports/report.json` |

---

## 4. `deepsec.config.ts` and multi-root projects

### 4.1 Load rules (`load-config.ts`)

- Walks up from cwd looking for: `deepsec.config.ts` | `.mjs` | `.js` | `.cjs`
- TS/CJS via jiti; ESM via dynamic import
- Must `export default` an object with `projects: ProjectDeclaration[]`
- On load: `setLoadedConfig` builds `PluginRegistry` from `plugins[]`
- Soft-fail if imports don't resolve (allows `init-project` before install)

### 4.2 Top-level `DeepsecConfig`

| Field | Type | Purpose |
|---|---|---|
| `projects` | `ProjectDeclaration[]` | Codebases deepsec knows about (multi-root). |
| `plugins` | `DeepsecPlugin[]?` | Loaded in order; last-write-wins for single-slot providers. |
| `matchers` | `{ only?: string[]; exclude?: string[] }?` | Filter built-in + plugin matchers for `scan`. `only` ignores `exclude`. CLI `--matchers` overrides. |
| `defaultAgent` | `string?` | Default `--agent` (`codex`, `claude`, `pi`). |
| `dataDir` | `string?` | Override data root (default `./data`). Env `DEEPSEC_DATA_ROOT` equivalent at path layer. |

### 4.3 `ProjectDeclaration`

| Field | Type | Required | Purpose |
|---|---|---|---|
| `id` | `string` | yes | `--project-id` and `data/<id>/` name. |
| `root` | `string` | yes | Absolute or relative path to codebase. |
| `githubUrl` | `string` | no | Export links; else git remote. |
| `infoMarkdown` | `string` | no | Repo context; **overrides** `data/<id>/INFO.md` when set. |
| `promptAppend` | `string` | no | Appended to system prompt (also on `config.json`; file wins if both). |
| `priorityPaths` | `string[]` | no | Path prefixes processed first (also on `config.json`; file wins). |

### 4.4 Multi-root example

```ts
import { defineConfig } from "deepsec/config";
import orgPlugin from "@acme/plugin-internal";

export default defineConfig({
  projects: [
    { id: "web-app", root: "../web-app", priorityPaths: ["src/api/"] },
    {
      id: "billing-svc",
      root: "../billing-svc",
      githubUrl: "https://github.com/acme/billing/blob/main",
      promptAppend: "Multi-tenant isolation is P0.",
    },
  ],
  plugins: [orgPlugin()],
  matchers: { exclude: ["framework-internal-header"] },
  defaultAgent: "claude",
  dataDir: "./data",
});
```

Single-project configs auto-resolve `--project-id`. Multiple projects
require an explicit id (or comma-separated list for export).

### 4.5 Plugin slots (config-adjacent)

| Slot | Resolution |
|---|---|
| `matchers`, `notifiers`, `agents` | Additive |
| `ownership`, `people`, `executor` | Last plugin wins |

---

## 5. `config.json` — `priorityPaths`, `ignorePaths`, `promptAppend`

Optional file at `data/<projectId>/config.json`. Read by **scan** and **AI
agents** (`process` / prompt assembly). Overrides the same fields on
`ProjectDeclaration` when both are present (docs + sample `_comment`).

| Field | Type | Used by | Purpose |
|---|---|---|---|
| `priorityPaths` | `string[]` | `process` | Path prefixes sorted first in work selection. |
| `promptAppend` | `string` | `process` / prompt assemble | Free-form text appended after INFO.md / tech sections. |
| `ignorePaths` | `string[]` | `scan` | Extra globs merged with built-in ignores (`node_modules`, `dist`, `.git`, deepsec data dirs, …). CLI `ignorePaths` param if passed takes precedence over file. |

**Example** (`samples/webapp/config.json`):

```json
{
  "priorityPaths": [
    "src/api/admin/",
    "src/api/billing/",
    "src/api/auth/",
    "src/lib/auth/",
    "src/lib/vault/"
  ],
  "promptAppend": "Cross-tenant access via missing companyId scoping is the highest-impact bug shape in this codebase. Always check that DB queries filter by req.session.user.companyId.",
  "ignorePaths": ["**/legacy/**", "**/migrations/**", "**/seed/**"]
}
```

**Precedence (conceptual):**

```
CLI flags (e.g. --matchers, explicit ignorePaths)
  > data/<id>/config.json  (priorityPaths, promptAppend, ignorePaths)
  > ProjectDeclaration fields (priorityPaths, promptAppend, infoMarkdown)
  > data/<id>/INFO.md  (if infoMarkdown unset)
  > built-in defaults
```

Prompt assembly order (processor): core threat prompt → tech highlights →
slug notes → `INFO.md` / `infoMarkdown` → `promptAppend`.

---

## 6. Proposed Grok mapping

Map deepsec's workspace + data plane onto Grok's existing
project (`.grok/`) and user (`~/.grok/`) conventions.

### 6.1 Directory trees

```
# Project scope (checked into the repo, like .deepsec)
.grok/deepsec/
├── config.json                 # multi-root DeepsecConfig equivalent (JSON)
├── AGENTS.md                   # optional operator notes
├── matchers/                   # optional custom matcher modules / JSON defs
│   └── sql-injection-local.json
└── data/
    └── <projectId>/
        ├── project.json        # ProjectConfig
        ├── INFO.md
        ├── SETUP.md
        ├── config.json         # priorityPaths, ignorePaths, promptAppend
        ├── tech.json
        ├── files/
        │   └── path/to/file.rs.json   # FileRecord
        ├── runs/
        │   └── <runId>.json           # RunMeta
        └── reports/
            ├── report.md
            └── report.json

# User scope (machine-global defaults / credentials / caches)
~/.grok/deepsec/
├── config.json                 # user defaults: defaultAgent, matcher filters, dataDir override
├── credentials.env             # or reuse ~/.grok/auth.json patterns — API keys
├── agents/                     # optional user-level agent overrides
└── cache/                      # optional shared model / tech cache
```

**Resolution:** project `.grok/deepsec/config.json` wins over
`~/.grok/deepsec/config.json` for overlapping keys; user file supplies
defaults when project omits them. Data root default:
`.grok/deepsec/data` (project-local), overridable by user/project
`dataDir` or env e.g. `GROK_DEEPSEC_DATA_ROOT`.

### 6.2 Equivalent JSON schemas (no TS runtime)

#### Project multi-root config — `.grok/deepsec/config.json`

```json
{
  "projects": [
    {
      "id": "grok-shell",
      "root": "../..",
      "githubUrl": "https://github.com/xai-org/grok-fork/blob/main",
      "infoMarkdown": null,
      "promptAppend": "Focus on tool sandbox escape and path traversal.",
      "priorityPaths": ["crates/codegen/xai-grok-tools/", "crates/codegen/xai-grok-shell/"]
    },
    {
      "id": "sibling-svc",
      "root": "../../../sibling-svc"
    }
  ],
  "matchers": {
    "only": null,
    "exclude": ["framework-internal-header"]
  },
  "defaultAgent": "claude",
  "dataDir": "./data",
  "plugins": []
}
```

#### User defaults — `~/.grok/deepsec/config.json`

```json
{
  "defaultAgent": "claude",
  "matchers": { "exclude": [] },
  "dataDir": null
}
```

#### Per-project overrides — `.grok/deepsec/data/<id>/config.json`

Same three fields as deepsec:

```json
{
  "priorityPaths": ["crates/codegen/xai-grok-sandbox/"],
  "promptAppend": "Sandbox deny-path regressions are P0.",
  "ignorePaths": ["**/target/**", "**/node_modules/**", "**/.git/**"]
}
```

#### On-disk records (identical field sets to §2)

Use the same JSON shapes for:

| File | Schema |
|---|---|
| `project.json` | `ProjectConfig` |
| `files/**/*.json` | `FileRecord` (+ nested Candidate, Finding, AnalysisEntry, …) |
| `runs/*.json` | `RunMeta` |
| export artifact | `ExportedFinding[]` or md-dir layout |
| `reports/report.json` | report aggregate |

Port validation should re-express Zod rules as serde/`jsonschema` in Rust
with the same enums and optional-field backward compatibility.

---

## 7. Append-only / merge-safe write strategies (for port)

Deepsec never treats `FileRecord` as a pure last-write-wins blob under
concurrency. A Grok port should preserve these strategies.

### 7.1 Per-stage write semantics

| Stage | Strategy |
|---|---|
| **scan** | Upsert FileRecord; **merge candidates** by key `(vulnSlug, matchedPattern, lineNumbers.join(","))` — push only if not present. Refresh `lastScannedAt`, `lastScannedRunId`, `fileHash`. Do **not** clear `findings` / `analysisHistory`. Do **not** force `analyzed` → `pending`. |
| **process** | Claim with `status=processing`, `lockedByRunId`, `lockedAt`. On success: **append** net-new findings (signature `vulnSlug::title.trim().toLowerCase()`); **push** one `AnalysisEntry`; set `status=analyzed`; clear lock. Missing batch results → `status=error`, clear lock. |
| **revalidate** | Annotate existing findings' `revalidation` fields; may append `AnalysisEntry` with `phase: "revalidate"`. Do not delete history. |
| **triage** | Annotate `finding.triage` in place. |
| **enrich** | Set/update `gitInfo` only (never clear on empty). |
| **runs** | One new `runs/<runId>.json` per invocation (unique runId → safe overwrite of self only). |
| **report** | Overwrite `reports/*` (non-incremental; safe). |
| **export md-dir** | Authoritative rewrite of owned severity dirs + stale file sweep. |

### 7.2 Finding / history merge (sandbox + concurrent process)

From `merge-records.ts` `mergeFileRecord(host, incoming)`:

| Field | Merge rule |
|---|---|
| `analysisHistory` | Union by `runId`; same runId → prefer **incoming**; sort by `investigatedAt`. |
| `findings` | Union by signature `vulnSlug::title.trim().toLowerCase()`; same sig → field-merge preferring incoming, but keep host `revalidation`/`triage` if incoming lacks them; prefer host `producedByRunId`. |
| `gitInfo` | `incoming ?? host` (never drop enrich data). |
| `status` | If either is `analyzed` → `analyzed`; else prefer incoming. |
| `lockedByRunId` / `lockedAt` | Prefer incoming (process loop is authority). |
| Scan fields (`candidates`, `lastScanned*`, `fileHash`) | Prefer incoming on process-merge path (process doesn't race scan fields in normal use). |

### 7.3 Locking

| Lock | Mechanism | Purpose |
|---|---|---|
| Per-project process lock | Atomic `mkdir` on `data/<id>/.process.lock` + owner file; 1h stale reclaim | Serialize **selection + claim** only |
| Per-file lock | `lockedByRunId` + `lockedAt`; reclaim if run phase done/error/missing or pid dead (same host) or lock older than `STALE_LOCK_MS` (~1h) | Prevent double-analysis |
| Graceful shutdown | SIGINT/SIGTERM → `completeRun(..., "error")` for active runs | Immediate reclaim without waiting 1h |

### 7.4 Atomicity recommendations for a Grok/Rust port

1. **Write temp + rename** for each JSON record (`*.json.tmp` → `*.json`) to avoid torn reads.
2. Keep **runId-keyed** run metas immutable after `phase: done|error` except stats finalize.
3. Persist findings with stable signature; never replace entire `findings` array with a re-run's full list without union.
4. On multi-worker download/merge (sandbox equivalent): snapshot host records for paths in the payload **before** extract; merge after; validate schema + `projectId` + path consistency; restore host or drop on validation failure.
5. Optional **data-commit scrub**: before versioning `files/**`, redact `snippet` for secret-bearing matcher slugs; refuse commit if credential-shaped snippets remain.
6. Treat `analysisHistory` as append-only audit log — no deletes, no rewrites of past entries (except merge union by runId when reconciling concurrent writers).

### 7.5 Read patterns that stay valid after merge-safe design

- Filter findings by `revalidation.verdict` / severity via export filters, not by mutating history.
- Cost rollup: sum `analysisHistory[].costUsd` (per-file shares).
- Pending work: `status in {pending, error}` (and reclaimable `processing`).

---

## 8. Cross-reference: deepsec → Grok path map

| Deepsec | Grok (proposed) |
|---|---|
| `.deepsec/deepsec.config.ts` | `.grok/deepsec/config.json` |
| `.deepsec/data/<id>/` | `.grok/deepsec/data/<id>/` |
| `./data` or `DEEPSEC_DATA_ROOT` | `.grok/deepsec/data` or `GROK_DEEPSEC_DATA_ROOT` |
| User-global (none first-class) | `~/.grok/deepsec/` |
| `data/<id>/config.json` | same relative under Grok tree |
| `export --format json\|md-dir` | equivalent CLI / skill subcommands |
| `report` → `reports/report.{md,json}` | same |

---

## Summary

1. Deepsec state is per-project under `data/<id>/` with `FileRecord`, `RunMeta`, and `ProjectConfig` as the core on-disk JSON schemas (Zod-validated in core).
2. Findings and `analysisHistory` are append/merge oriented; candidates merge by slug+pattern+lines; concurrent writers union history by `runId` and findings by signature.
3. Export is `json` (ExportedFinding array) or `md-dir` (severity folders); `report` writes overwrite-style `reports/report.{md,json}`.
4. Multi-root lives in `deepsec.config.ts` (`projects[]`); per-project `config.json` owns `priorityPaths`, `ignorePaths`, `promptAppend` and overrides declaration fields.
5. Proposed Grok layout mirrors this under `.grok/deepsec/` (project) and `~/.grok/deepsec/` (user) with equivalent JSON schemas and the same merge-safe write rules.
