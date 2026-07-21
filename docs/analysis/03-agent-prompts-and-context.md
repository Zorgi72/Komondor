# DeepSec agent prompts and context injection

Analysis of AI prompt/context patterns in deepsec (`/tmp/grok-goal-f8e64663ee8a/implementer/deepsec`), focused on SKILL / SETUP / INFO scaffolding, modular process prompts, revalidate/triage agents, JSON schemas, model/thinking dials, and how those map onto Grok Build skills and sub-agents.

Source tree: deepsec monorepo under `packages/{deepsec,processor,core,scanner}`, plus `docs/`, `prompt-samples/`, and `samples/webapp/`.

---

## 1. INFO.md — section structure and why it matters

### Role

`data/<projectId>/INFO.md` is **project-aware context injected into every AI batch** for `process`, `revalidate`, and (truncated) `triage`. Vague INFO.md → vague findings; good INFO.md is the main non-code lever for precision and FP reduction.

The processor loads it from disk:

```text
data/<projectId>/INFO.md  →  assemblePrompt({ projectInfo })  or  buildRevalidatePrompt({ projectInfo })
```

Absence is allowed (empty string). Config field `infoMarkdown` on a `ProjectDeclaration` is documented as overriding the file when both exist; the process/revalidate/triage runtime paths in `packages/processor/src` currently read the on-disk `INFO.md` (samples often mirror file content into config for packaging).

### Scaffold sections (from `init` / `init-project`)

`registerProject()` writes a placeholder via `infoMdTemplate(id)`:

| Section | Intent |
|--------|--------|
| `# <id>` + length budget note | H1 title; hard guidance: **50–100 lines total** |
| **What this codebase does** | One paragraph: product, stack, users |
| **Auth shape** | 3–5 auth primitives **by name** (helpers, middleware) — enough to spot *missing* checks |
| **Threat model** | 2–4 sentences, ranked attacker goals; no generic CWE boilerplate |
| **Project-specific patterns to flag** | 3–5 repo-unique patterns with one example each |
| **Known false-positives** | 3–5 intentional risky-looking paths (stubs, fixtures, intended-public) |

Rubric (also in `SETUP.md` and the post-init agent paste prompt):

- Pick **3–5 items per section**, not exhaustive lists.
- Name primitives (`withAuthentication`, `auth.can()`, `requireUser`) — **no line numbers**.
- Skip generic CWEs (matchers cover those); cover **project-specific** only.
- One short paragraph **or** 3–5 bullets per section, not both.

### Worked example quality bar

`samples/webapp/INFO.md` shows the intended density:

- Stack + layout in one short block.
- Auth: session shape, `auth.has(actor, action, resource)`, rate-limit conventions.
- Threat model: ranked IDOR, priv-esc, webhook forgery, vault/credential leaks, debug flags.
- FP sources: migrations, seeds, tests, intentional unauth health.
- Conventions: Drizzle style, `safeRedirect`, server actions under `src/actions/`.

### Why injection placement matters

In the modular **process** path, INFO.md is appended **after** core + tech highlights + slug notes, separated by `---`, so it does not compete with fixed severity tables for early-token attention but still anchors every investigation. Verbose context **dilutes signal** in the same window as the investigation instructions — hence the 50–100 line budget and the explicit “verbose context dilutes signal” copy in init output.

Triage only injects a **2 000-character slice** under `## Project Context (summary only)` — cheap classification does not re-read code or load full INFO.md.

---

## 2. SETUP.md / AGENTS.md / SKILL.md roles

These three files form a **layered agent onboarding stack**. They are not all injected into scan batches; they teach *coding agents* how to configure deepsec and fill INFO.md.

### SKILL.md (`packages/deepsec/SKILL.md`)

| Field | Value |
|-------|--------|
| Frontmatter `name` | `deepsec` |
| Frontmatter `description` | When to activate (scan/configure/extend in a project with deepsec installed) |
| Body | Doc map under `node_modules/deepsec/dist/docs/` (or clone `docs/`), worked sample path, Q→doc routing |

Pattern: **skill = router to docs**, not a second source of truth. “Read the doc before paraphrasing.” Same shape as Grok Build skills (`name` + `description` + markdown procedure).

Shipped so that after `pnpm install` inside `.deepsec/`, any coding agent that understands SKILL.md can load deepsec’s user guide without training-data drift.

### SETUP.md (`data/<id>/SETUP.md`)

Per-project **setup runbook**, written by `setupMdTemplate(id, targetRel)` on init/init-project.

Contents:

1. Read SKILL.md + key docs (`getting-started`, `configuration`, `writing-matchers`).
2. Fill `data/<id>/INFO.md` with the section rubric and source order: target `README.md` → `AGENTS.md`/`CLAUDE.md` → package manifests → 5–10 representative files.
3. Optional custom matchers **only after a real TP**.
4. When done: user runs `scan` / `process`; SETUP.md may be deleted.

SETUP.md is **checked into git**, human/agent-editable, and **not** injected into process prompts. It is the instruction set that *produces* INFO.md.

### AGENTS.md (workspace-level)

`init` writes `.deepsec/AGENTS.md` via `workspaceAgentsMd()`:

- Points agents at `data/<id>/SETUP.md` for setup.
- Lists common tasks (setup, init-project, matchers).
- Points at SKILL.md and dist docs.

Role: **workspace index** for coding agents that auto-load AGENTS.md (Claude Code, Codex, Grok Build project rules). It is *not* deepsec’s security context for scan batches — that is INFO.md.

### Init paste prompt (stdout)

After scaffold, `printAgentPrompt` prints a short cyan block:

```text
Read node_modules/deepsec/SKILL.md → read data/<id>/SETUP.md →
skim target README/AGENTS/code → replace each section of data/<id>/INFO.md.
Keep SHORT (50–100 lines). Project-specific only. INFO.md is injected every batch.
```

That three-step chain is the product’s intended human→agent bootstrap.

### Related config knobs (not markdown files)

| Knob | Where | Effect on prompts |
|------|--------|-------------------|
| `promptAppend` | `data/<id>/config.json` or project declaration | Free-form text appended **after** INFO.md (modular path) or after custom template |
| `priorityPaths` | config.json | Scheduling only (which files process first) |
| `ignorePaths` | config.json | Scan-time path filtering |

---

## 3. Process batch prompt structure + expected JSON schema

### Assembly pipeline (modular; default path)

Architecture docs still mention a monolithic `DEFAULT_PROMPT_TEMPLATE`; **runtime default** is modular assembly in `packages/processor/src/prompt/`:

```
assemblePrompt()
  [1] CORE_PROMPT                          # core.ts — persona, severity, categories, FP, auth bypasses, out-of-scope
  [2] ## Threat highlights…                # highlights.ts filtered by detectTech tags ∩ batch languages
      OR polyglot one-line fallback        # if framework section > 6000 chars
  [3] ## Slug-specific reviewer notes      # slug-notes.ts, only slugs present in this batch
  [4] --- + projectInfo (INFO.md)          # optional
  [5] --- + promptAppend                   # optional
```

Then each agent backend wraps with `buildInvestigatePrompt()` (`agents/shared.ts`):

```
[assembled system half]
## Target Files
  - **path** 
      - [vulnSlug] L…: matchedPattern
  (or “no scanner hits — full holistic review” for direct/diff mode)

## Investigation Instructions
  1 Read fully  2 Trace data flows  3 Follow imports
  4 Check mitigations  5 Think broadly beyond scanner

## Output Format  →  JSON array schema (below)
```

**Double-injection guard:** when using the modular assembler, `process()` passes `projectInfo: ""` into the agent layer so INFO.md is not repeated under `## Project Context`. Custom `--prompt-template` callers still get INFO.md injected by the agent layer.

**Per-batch adaptation:**

- `detectedTags` from `data/<id>/tech.json` (written by scan).
- `batchLanguages` from file extensions → language filter so a Python batch in a Next.js+Django monorepo does not carry Next.js bullets.
- `batchSlugs` from candidates on files in the batch only.

Golden snapshots live under `prompt-samples/*.md` (regenerated via `UPDATE_PROMPT_SAMPLES=1` unit tests).

### Persona / constraints in CORE_PROMPT

- World-class security researcher; attacker mindset; subtle logic bugs.
- Candidates are **heuristic wide-net** — many FPs expected.
- **Static analysis only** — no exploit/repro/runtime against the target.
- Severity: CRITICAL / HIGH / MEDIUM (security) + HIGH_BUG / BUG (non-security).
- Known vuln slug table + `other-*` escape hatch.
- FP guidance: sanitization, **handler-wrapping** middleware only (edge/CDN not enough), trusted data.
- Auth-bypass micro-patterns (param pollution, encoding, OAuth, cross-tenant, inverted checks).
- Out-of-scope: dist/vendor/generated/gitignored → empty findings array.

### Expected investigate JSON schema

Agents must emit a JSON **array** (fenced ` ```json ` preferred). Schema from `buildInvestigatePrompt` / repair prompt:

```json
[
  {
    "filePath": "relative/path/to/file.ts",
    "findings": [
      {
        "severity": "CRITICAL|HIGH|MEDIUM|HIGH_BUG|BUG",
        "vulnSlug": "the-vuln-slug-or-other",
        "title": "Brief title of the issue",
        "description": "Attack scenario + code evidence",
        "lineNumbers": [10, 15],
        "recommendation": "How to fix",
        "confidence": "high|medium|low"
      }
    ]
  }
]
```

Rules:

- One entry **per target file**; empty `findings: []` when clean.
- `vulnSlug` may be registry slug or `other-<topic>`.
- Files missing from the model array are filled with empty findings by `parseInvestigateResults` (so partial output does not leave files stuck forever — but parse failure is fail-loud).

### Persistence shape (on-disk Finding)

After merge into FileRecord (`packages/core` types / data-layout):

| Field | Notes |
|-------|--------|
| severity, vulnSlug, title, description, lineNumbers, recommendation, confidence | From agent |
| producedByRunId | Stamped by process |
| triage? | Later stage |
| revalidation? | Later stage |

`analysisHistory[]` appends agentType, model, modelConfig, cost/tokens (split per file), refusal, reinvestigateMarker, phase `"process"`.

### Follow-ups after the main turn

1. **JSON repair** (`buildInvestigateJsonRepairPrompt`) — toolless, fixed cheap effort; re-emit same conclusions as pure JSON.
2. **Refusal report** (`REFUSAL_FOLLOWUP_PROMPT`) — structured `{ refused, reason, skipped[] }`; refused batches surface in run meta / FileRecord; files stay pending for retry with another backend.

### Parse stack (must work without a healthy model)

```
extractAgentJsonPayload (fence / open fence / raw)
  → JSON.parse
  → on failure: jsonrepair(extractArrayCandidate)
  → still fail: writeParseFailureDebug + throw (errorBatchCount++)
```

Missing files in array → empty findings. Re-runs **merge** findings by `vulnSlug + normalized title`. Concurrent sandboxes **merge** FileRecords by runId history + finding signature (`merge-records.ts`).

### Models / thinking (process)

| Backend | Default model | Thinking flag |
|---------|---------------|---------------|
| `codex` (default agent resolve may vary by CLI defaultAgent) | `gpt-5.5` | `reasoningEffort` |
| `claude` | `claude-opus-4-8` | adaptive + effort map |
| `pi` | `zai/glm-5.2` | thinkingLevel |

`--thinking-level`: `minimal | low | medium | high | xhigh` (default **xhigh**). Claude maps minimal/low→low, medium/high→same, xhigh/unset→**max**. Follow-ups always cheap/low effort.

---

## 4. Revalidate vs triage prompt differences

### Revalidate (`buildRevalidatePrompt` + agent.revalidate)

| Dimension | Process | Revalidate |
|-----------|---------|------------|
| Goal | Discover findings from candidates | Verdict existing findings |
| Code access | Full agent tools (read/grep/…) | Same tool-using agents |
| Git | Not forced | `git log --oneline --since=3 months -n 10 -- <file>` inlined per file |
| INFO.md | Full (in assemble or Project Context) | Full under `## Project Context` |
| Input unit | File candidates | Per-finding text (title, severity, slug, lines, confidence, description, recommendation) |
| Output | File → findings[] | Flat verdict array keyed by filePath + title |
| Cost / model | Same heavy backends as process | Same; default high effort |
| When | status pending/error or --reinvestigate | findings without `revalidation` or `--force` |

**Revalidate persona:** adversarial review of prior findings; “incorrect verdicts impact security decisions”; static only; take time.

**Investigation steps (7):** read full file → imports → end-to-end data flow → attacker scenario → framework protections → code vs finding / git → honest confidence.

**Verdict enum:**

```text
true-positive | false-positive | fixed | uncertain | duplicate
```

JSON schema:

```json
[
  {
    "filePath": "exact/path/to/file.ts",
    "title": "exact title from the finding",
    "verdict": "true-positive|false-positive|fixed|uncertain|duplicate",
    "adjustedSeverity": "CRITICAL|HIGH|MEDIUM|HIGH_BUG|BUG",
    "duplicateOf": "title of primary (only when verdict is duplicate)",
    "reasoning": "5–10 sentences; show work"
  }
]
```

Duplicate rules are strict (same file only; exactly one primary; primary must have non-duplicate verdict; rejected duplicates stay unrevalidated for retry).

On-disk `Revalidation`: `{ verdict, reasoning, adjustedSeverity?, duplicateOf?, revalidatedAt, runId, model }`.

Same refusal follow-up + JSON repair path as process. Empirically marketed as **~50%+ FP cut** on HIGH+.

### Triage (`packages/processor/src/triage.ts`)

| Dimension | Triage |
|-----------|--------|
| Goal | Prioritize remediation without re-reading code |
| Backend | **Claude only** (`@anthropic-ai/claude-agent-sdk` `query`) |
| Default model | `claude-sonnet-4-6` (~1¢/finding); overridable (e.g. haiku) |
| Tools | `allowedTools: []`, `maxTurns: 1` — pure classification |
| Batch size | 30 findings |
| INFO.md | First **2000** chars only |
| Input | Finding metadata + description text only |
| Output | Priority buckets |

**Classification criteria:**

| Priority | Meaning |
|----------|---------|
| P0 | External attacker, trivial effort, auth/data/RCE, no mitigations |
| P1 | Real but conditional (internal, flags, races) |
| P2 | Low impact / defense-in-depth |
| skip | FP, mitigated, test-only, too vague |

Plus exploitability (`trivial|moderate|difficult`) and impact (`critical|high|medium|low`).

JSON schema:

```json
[
  {
    "title": "exact title",
    "priority": "P0|P1|P2|skip",
    "exploitability": "trivial|moderate|difficult",
    "impact": "critical|high|medium|low",
    "reasoning": "1-2 sentences"
  }
]
```

Matching is **by exact title** to batch items. Failed JSON parse → empty verdicts (batch reported complete with 0); no jsonrepair path here. Writes `finding.triage` with `triagedAt` + `model`.

### Prompt difference summary

```text
process:    CORE + tech + slugs + INFO + files + investigate steps → Finding[]
revalidate: adversarial prompt + INFO + findings + git log + 7 steps → Verdict[]
triage:     short classifier + truncated INFO + finding text → Priority[]  (no tools)
```

---

## 5. Mapping to Grok Build skills (sub-agents, skill body injection, effort levels)

Deepsec’s agent UX is designed for **any** coding agent that understands SKILL.md / AGENTS.md. Mapping onto Grok Build:

### SKILL.md → Grok skills

| Deepsec | Grok Build |
|---------|------------|
| `packages/deepsec/SKILL.md` (`name`, `description`, body → docs) | `SKILL.md` under `.grok/skills/`, repo, or user skills; frontmatter `name` / `description` / optional `effort` / `model` |
| Skill activates when user asks to scan/configure | Auto-invocation from description; slash command if `user-invocable` |
| “Read docs, don’t invent CLI flags” | Skill body injection into context when activated |

**Recommendation for a Grok skill packing deepsec:**

- Frontmatter: `name: deepsec`, rich `description` with trigger phrases (scan, process, INFO.md, matchers).
- Optional `effort: high` or `xhigh` equivalent for setup that fills INFO.md (quality of project context matters).
- Body: short procedure + absolute pointers to `node_modules/deepsec/dist/docs/…` and `data/<id>/SETUP.md`.
- Do **not** paste CORE_PROMPT into a Grok skill — process agents already own that; Grok skill is for **operator/setup**, not for reimplementing the scanner loop.

### AGENTS.md / SETUP.md → project rules + one-shot setup

| Deepsec | Grok Build |
|---------|------------|
| `.deepsec/AGENTS.md` workspace pointer | Project rules discovery (`AGENTS.md`, `CLAUDE.md`, …) with nested precedence |
| `data/<id>/SETUP.md` | One-shot setup procedure; could be a `/deepsec-setup` skill or persona instructions |
| Target repo’s own AGENTS.md | Source material when drafting INFO.md (SETUP step 2) |

Grok’s nested AGENTS.md scoping matches deepsec’s advice: fill INFO.md from the **target** tree’s README/AGENTS, write result under `.deepsec/data/<id>/`.

### INFO.md → durable context injection

| Deepsec | Grok Build |
|---------|------------|
| INFO.md in every process/revalidate batch | Closest analogues: project rules, memory, or a skill that injects a short “security context” block |
| 50–100 line budget | Same discipline: short, high-signal rules beat long dumps |

For a Grok-native security review workflow that is *not* deepsec process, treat INFO.md content as a **persona or role-instructions** block on a read-only explore subagent.

### Process / revalidate agents → subagents

| Deepsec | Grok Build |
|---------|------------|
| Batch workers (concurrency N, batch size B) | `spawn_subagent` with parallel children, each with own context window |
| Read-only static analysis contract | `capability_mode: read-only` (or explore type) |
| Same prompt/schema across codex/claude/pi | Same task prompt; swap parent `model` / subagent model overrides |
| `--thinking-level xhigh` default | Persona `reasoning_effort` or skill `effort`; prefer high effort for investigate/revalidate, low for triage-like classification |
| JSON-only final answer + repair turn | Subagent prompt must require structured JSON; parent parses/merges |
| Refusal follow-up | Optional second turn or parent QA checklist |

Concrete mapping for a Grok-orchestrated “deepsec-like” pipeline:

1. **Parent:** plan batches from candidates; merge FileRecord-like JSON.
2. **Investigate subagent:** inject CORE-like instructions + INFO.md + target files; `capability_mode: read-only`; high effort; require investigate JSON schema.
3. **Revalidate subagent:** prior findings + git history instructions; same tools; verdict schema.
4. **Triage subagent:** no tools, cheaper model, truncated context, priority schema.
5. **Skill body:** only the deepsec *product* skill for init/INFO authoring — not the multi-KB CORE_PROMPT unless packaging an offline reviewer skill deliberately.

### Effort levels

Deepsec thinking ladder: `minimal → low → medium → high → xhigh` (default xhigh for process/revalidate; follow-ups fixed low).

Grok skill/persona `effort` / `reasoning_effort` should mirror:

| Task | Suggested effort |
|------|------------------|
| Fill INFO.md from SETUP.md | medium–high |
| Investigate / revalidate | high–max |
| Triage / JSON repair / refusal | low–minimal |
| Doc lookup via SKILL.md | low |

---

## 6. Fallback when model is unavailable (parser / merger must still work)

Design principle: **the data plane is append-only and agent-agnostic**. Model failure must not corrupt state or block recovery.

### Agent call failures

| Failure | Behavior |
|---------|----------|
| Transient 429/5xx/timeout | Retry with backoff (`MAX_ATTEMPTS`, `isTransientError`) |
| Quota exhausted | `QuotaExhaustedError` → abort controller → stop new batches; CLI remediation message; exit non-zero |
| Batch throw | FileRecords → `status: "error"`, locks cleared; `errorBatchCount++`; safe to re-run process |
| SIGINT/SIGTERM | Run phase → `error`; locks reclaimable |
| Stale lock | Reclaim if owner done/error/missing, PID dead on same host, or age > 1h |

### Parse / schema failures

| Stage | Behavior |
|-------|----------|
| Investigate/revalidate non-JSON | jsonrepair path; optional model repair turn; else debug dump under `data/<id>/debug/parse-error-*.txt` + batch error |
| Partial array | Missing files get empty findings (process completes those files as analyzed with 0 findings) |
| Triage bad JSON | Soft skip (0 verdicts for batch); findings remain untriaged |
| Refusal non-JSON | Heuristic refused flag from prose keywords |

Parsers live in `packages/processor/src/agents/shared.ts` and do **not** require a live model for offline fixtures/tests (`stub-agent`, unit tests with fixed result strings).

### Merge / resume without a model

| Mechanism | Purpose |
|-----------|---------|
| `process` re-run | Skips analyzed; retries pending/error; optional `--reinvestigate` / wave markers |
| Finding merge signature | `vulnSlug + lower(trim(title))` — multi-agent multi-model append |
| `mergeFileRecord` (sandbox) | Union analysisHistory by runId; union findings by signature; preserve triage/revalidation from either side; status analyzed wins |
| Export / report / metrics | Read-only; work entirely offline on `data/` |
| Scan | No AI; regenerates candidates anytime |

### Model swap as fallback

Same prompt + same JSON schema across backends. If Opus/codex refuses or is unavailable:

- Re-run with `--agent` / `--model` alternate.
- Refused files stay pending; other backend picks them up.
- Findings dedupe so dual-agent cost is not fully doubled.
- Future models: pass `--model` string through; pricing table optional for cost readout only.

### What “must still work” means in practice

Even with **zero** successful model calls:

1. `scan` still populates candidates and FileRecords.
2. Disk layout, locks, and RunMeta remain consistent.
3. Parsers accept golden `prompt-samples` / fixture agent outputs offline.
4. `export` / `report` / `metrics` operate on any prior findings.
5. A later process with a working credential resumes without cleanup.

When the model is intermittently available, **jsonrepair + empty-findings fill + error status + re-run** keep the pipeline idempotent; the merger ensures concurrent sandboxes do not clobber history.

---

## Reference map (absolute paths in the analyzed tree)

| Concern | Path |
|---------|------|
| Skill | `/tmp/grok-goal-f8e64663ee8a/implementer/deepsec/packages/deepsec/SKILL.md` |
| INFO/SETUP templates | `…/packages/deepsec/src/commands/init-project.ts` |
| Workspace AGENTS.md | `…/packages/deepsec/src/commands/init.ts` (`workspaceAgentsMd`) |
| CORE_PROMPT | `…/packages/processor/src/prompt/core.ts` |
| assemblePrompt | `…/packages/processor/src/prompt/assemble.ts` |
| Investigate/revalidate prompts + parsers | `…/packages/processor/src/agents/shared.ts` |
| Process/revalidate orchestration | `…/packages/processor/src/index.ts` |
| Triage prompt | `…/packages/processor/src/triage.ts` |
| Agent config / thinking | `…/packages/deepsec/src/agent-config.ts`, `docs/models.md` |
| Prompt goldens | `…/prompt-samples/*.md` |
| Sample INFO.md | `…/samples/webapp/INFO.md` |
| FileRecord / Finding schemas | `…/packages/core/src/types.ts`, `docs/data-layout.md` |
| Sandbox merge | `…/packages/deepsec/src/sandbox/merge-records.ts` |

---

## 5-line summary

1. **INFO.md** (50–100 lines: product, auth names, threats, project patterns, known FPs) is the only project context injected into every process/revalidate batch; verbose text hurts more than it helps.  
2. **SKILL.md / SETUP.md / AGENTS.md** onboard coding agents to fill INFO.md; they are not the scanner system prompt.  
3. **Process** assembles CORE + tech highlights + slug notes + INFO + per-batch files, then requires a strict file→findings JSON array with repair/refusal follow-ups.  
4. **Revalidate** re-reads code+git for TP/FP/fixed/uncertain/duplicate verdicts; **triage** is a cheap, toolless P0–skip classifier on finding text with truncated INFO.  
5. Map to Grok via skills for setup, read-only high-effort subagents for investigate/revalidate, low-effort for triage; parsers, merges, and re-runs keep `data/` correct when models fail or change.
