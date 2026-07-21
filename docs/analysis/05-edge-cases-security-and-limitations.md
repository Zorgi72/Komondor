# DeepSec → Grok Port: Edge Cases, Sandbox, FP Reduction, Cost Controls

**Source tree analyzed:** `/tmp/grok-goal-f8e64663ee8a/implementer/deepsec`  
**Primary packages:** `packages/deepsec`, `packages/processor`, `packages/core`, `packages/scanner`  
**Grok sandbox reference:** `crates/codegen/xai-grok-pager/docs/user-guide/18-sandbox.md`  
**Date:** 2026-07-21

This note inventories upstream DeepSec edge-case handling, sandbox design, false-positive reduction, cost knobs, and security boundaries — then maps what a Grok/Zyth port should keep, adapt, or skip.

---

## 1. No git / empty / binary-only / huge monorepo

### No git

| Path | Behavior |
|------|----------|
| `ensureProject` / `detectGithubUrl` | `git remote` / `rev-parse` run with stderr silenced; failure → `githubUrl` left unset. No hard fail. Tests assert non-git roots do not print git fatals. |
| Sandbox tarball (`makeTarball`) | If `.git` present: `git ls-files --cached --others --exclude-standard` (honors `.gitignore`, skips deleted + symlinks). If **not** a git repo: falls back to fixed exclude lists (`TARGET_EXCLUDES`: `node_modules`, `.git`, `dist`, etc.). |
| Direct mode (`--diff*`) | **Hard dependency on git.** `resolveFiles` → `spawnSync("git", …)`; non-zero exit throws with stderr. Non-git trees must use `--files` / `--files-from` instead. |
| Enrich (`gitInfo`) | Best-effort; missing git history just omits committer data. |

**Port implication:** Grok-side scan/process must tolerate non-git workspaces (common in extracted tarballs, monorepo slices). Diff mode should document “git required” or fall back to explicit file lists.

### Empty project

- `process` / `revalidate` with zero eligible files: emit `all_complete` (“No files to process” / “No findings to revalidate”), mark run `done`, return zeros — exit 0.
- Direct mode with empty resolved list after ignore filter: yellow “No files matched…”, exit 0 (CI green).
- Empty after claim race (“another run owned every candidate”): same clean completion.

### Binary-only / unreadable files

Scanner (`scanFiles` and full scan):

```text
readFileSync(…, "utf-8") → catch → content = "" (still writes FileRecord)
```

- Binary / permission / encoding failures do **not** abort the scan.
- Empty content → no matcher hits; hash empty; record still `pending` so process can see the path.
- Direct-mode scan explicitly: “Unreadable (binary, permissions); still write a record so process can decide.”
- Agent prompt (`CORE_PROMPT`) tells the model to skip gitignored/generated/vendored files and return empty findings — binaries that slip through tend to get empty analysis rather than junk findings.

**Gap:** There is no explicit magic-byte / null-byte binary detector; “binary” is whatever Node’s UTF-8 decode rejects. Large UTF-8 blobs (minified JS, data URIs) still get fully scanned and may burn AI budget if they match globs.

### Huge monorepo

Mitigations already in upstream:

| Control | Where |
|---------|--------|
| `IGNORE_DIRS` | `node_modules`, `dist`, `.next`, tests, fixtures, `*.md`, deepsec `data/**`, … |
| `config.json` `ignorePaths` / `priorityPaths` | Per-project |
| `--filter` prefix, `--only-slugs` / `--skip-slugs` | process/revalidate |
| `--limit N` | Caps files per run (FAQ: calibrate with `--limit 50`) |
| Noise-tier sort | Precise matchers first → budget lands on high-signal files |
| Sandbox partitioner | Directory-aware bin-pack across N microVMs |
| Tarball git-ls-files | 5–20× smaller upload vs raw tree |

FAQ cost model (Claude Opus, concurrency 5, batch-size 5): ~$25–60 / 100 files; ~$500–1200 / 2k files. Full monorepo process without limits is the primary cost risk.

**Port implication:** Default Grok runs should prefer PR/`--diff` scope or aggressive `--limit` + ignore globs; full-tree process must be opt-in and cost-gated.

---

## 2. Interrupt mid-process; lock recovery

### Why locks exist

Unit of work = one source file → one `FileRecord`. Concurrent `process` runs without coordination both load `pending`, both write `status=processing` + different `lockedByRunId`, and last writer clobbers analysisHistory/findings.

### Layers

1. **Per-project claim mutex** (`acquireProcessLock` in `packages/core/src/run.ts`)  
   - Atomic `mkdir(data/<id>/.process.lock)`.  
   - Held only for claim I/O (seconds), not during AI work.  
   - Stale after 1h (`PROCESS_LOCK_STALE_MS`); timeout 30s wait with clear “remove lock dir” message.

2. **Per-file locks** (`lockedByRunId`, `lockedAt`, `status: "processing"`)  
   - Set under the project mutex; cleared on batch success (`analyzed`) or failure (`error`).

3. **Reclaim policy** (`isReclaimableLock` in processor) — reclaim when **any** of:  
   - Owning run meta missing/corrupt, or phase `done`/`error`.  
   - Same hostname + recorded `pid` and `!isPidAlive(pid)` (instant recovery after SIGKILL/OOM).  
   - No `lockedAt` (legacy) **or** age ≥ `STALE_LOCK_MS` (1 hour).  
   - Cross-host live runs: only the 1h backstop (cannot probe remote PID).

### Graceful interrupt (SIGINT / SIGTERM)

`registerActiveRun` installs handlers that:

- Flip active runs to `phase: "error"` so locks are immediately reclaimable (without waiting 1h).  
- Exit 130 (SIGINT) / 143 (SIGTERM) if sole listener.  
- Defer to other listeners (sandbox shutdown needs async `sandbox.stop()`).  
- `beforeExit` also flushes so thrown errors don’t strand `phase: "running"`.

### Hard kill / power loss

- PID liveness recovers same-host stranded locks immediately.  
- Cross-host / PID-less records wait up to 1h.  
- FAQ guidance: **just re-run the same command** — finished files stay `analyzed` (no double bill); unfinished/`error`/`processing` get picked up.

### Sandbox interrupt

`packages/deepsec/src/sandbox/shutdown.ts`: tracks live Sandbox instances; on signal stops them (10s race) then exits. Second Ctrl+C force-exits. Run state under `data/<id>/sandbox-runs/` is separate from per-file locks; worker merges still apply on next successful download.

### Resume paths

| Mechanism | Semantics |
|-----------|-----------|
| Re-run without flags | Pending/error + reclaimable processing only |
| `--run-id <id>` | Resume that run meta if not already `done`; same claim logic |
| `--reinvestigate` | All files again (force claim) |
| `--reinvestigate N` | Wave marker: skip files already productively analyzed by **same agent** with marker N (idempotent sandbox retries) |
| revalidate `--force` | Re-check findings that already have verdicts |

**Port implication:** Implement the three-layer lock model (or equivalent SQLite leases) before multi-worker process. Grok’s process model should register the same “mark run failed on SIGINT” behavior so interrupted sessions don’t stick files for an hour.

---

## 3. Permission errors

| Surface | Handling |
|---------|----------|
| Project `rootPath` missing | Hard error with source of path (`--root` vs `project.json`) and rescan hint |
| File unreadable at scan | Empty content + empty hash; continue |
| File missing in direct list | Skip with progress message |
| Path escapes root (`--files`) | Dropped in `resolveFiles` (`../` / absolute outside root) |
| Credential missing | `assertAgentCredential` / `assertSandboxCredential` fail **before** spinning agents/VMs (preflight) |
| Agent batch throw | Files in batch → `status=error`, locks cleared; run continues other batches unless quota abort |
| Quota exhaustion | AbortController cancels in-flight; `quotaExhausted` on result; CLI exit 1 with tailored message |
| Enrich / progress callbacks | try/catch; never crash processor |

There is **no** special handling for read-only project trees beyond OS errors becoming empty content or write failures on `data/` (data dir is expected writable). If `data/<id>/` cannot be written, the run fails loudly on first `writeFileRecord` / `writeRunMeta`.

**Port implication:** Grok sandbox `read-only` / `strict` profiles must still allow write to deepsec `data/` (or a designated state dir under `~/.grok/` / workspace). Map that as an explicit `read_write` exception in any Grok sandbox profile used for scanning.

---

## 4. Concurrent runs

### Local multi-process

- Claim serialized by `.process.lock`.  
- Disjoint file sets process truly in parallel after claim.  
- Overlapping claims: second run skips non-reclaimable `processing` files.  
- Codex-specific: concurrent Codex CLIs on one host stomp session DB under `CODEX_HOME` — DeepSec isolates per-invocation tempdirs for that reason. Port must not share a mutable session store across workers.

### Sandbox multi-VM

- Partitioner splits eligible paths into disjoint manifests (directory grouping + bin packing).  
- Each worker gets `--manifest` + `--root /vercel/sandbox/target`.  
- Download merge (`merge-records.ts`): union `analysisHistory` by `runId`, findings by `(vulnSlug, normalized title)`, prefer `analyzed` status, preserve revalidation/triage on either side.  
- Designed after real race: last tarball extract wiped sibling sandboxes’ history.

### Same project, process + revalidate concurrent

- revalidate does **not** take per-file process locks (only RunMeta registration).  
- Concurrent process writing findings while revalidate reads can race; revalidate writes `finding.revalidation` onto whatever it loads. Low practical risk if operators serialize stages; not strongly synchronized.

**Port implication:** Prefer single-writer process per project, or reuse claim mutex. If fanning out workers (subagents / pool), partition file lists disjointly and merge append-only like `merge-records`.

---

## 5. Sandbox mode — what to port vs skip for Grok sandbox profiles

### Upstream DeepSec sandbox (Vercel)

Architecture:

1. Bootstrap microVM → upload app + target + data tarballs → install deps/tools → snapshot.  
2. Spawn N workers from snapshot with **network allowlist** + **header-injected credentials**.  
3. Workers run process/revalidate with `DEEPSEC_INSIDE_SANDBOX=1`.  
4. Download deltas; merge file records; stop VMs.

Security-relevant properties:

| Property | Implementation |
|----------|----------------|
| Credentials never in VM env | Placeholder `deepsec-sandbox-brokered-credential`; real Bearer injected at egress firewall |
| Single AI host allowlist | Host derived from base URL; off-backend host denied |
| Nested OS sandboxes disabled | `DEEPSEC_INSIDE_SANDBOX=1` → Claude `buildSandbox()` returns undefined; Codex `danger-full-access` (VM is the boundary; nested read-only rejected ~7% of tool calls) |
| Telemetry suppressed | Claude nonessential traffic env; Codex `config.toml` analytics/otel/plugins off |
| Output caps | Worker: 2k chars/line, 8 MiB total stdout/stderr; orchestrator: 10 MiB/log stream + 3 GiB memory watchdog abort |
| Target excludes secrets patterns | gitignore-aware tar; excludes `.vercel`, logs; still uploads **source** the agent will read |

### Grok built-in profiles (reference)

| Profile | FS Read | FS Write | Child net (Linux) | Fit for security agent |
|---------|---------|----------|-------------------|-------------------------|
| `off` | Full | Full | Full | Too open for untrusted analysis |
| `workspace` | Everywhere | CWD + `~/.grok/` + tmp | Allowed | OK for trusted local repos if data dir is CWD |
| `devbox` | Everywhere | Most top-level except `/data` | Allowed | Dev VM only |
| `read-only` | Everywhere | `~/.grok/` + tmp | Blocked | **Best default for investigation** if state dir allowed |
| `strict` | CWD + system | CWD + `~/.grok/` + tmp | Blocked | Untrusted trees; force root=CWD |

### Port vs skip

| Upstream concept | Port to Grok? | Notes |
|------------------|---------------|--------|
| Read-only investigation tools (read/grep/find/ls; no app run / no exploit) | **Yes — core** | Align with Pi’s prompt: source inspection only |
| Disable network for agent child tools during investigation | **Yes** | Map to `read-only` / `strict` (`restrict_network`) or custom profile |
| Credential isolation from agent-visible env | **Yes** | Don’t dump full process env into tool runners; allowlist like Claude’s `buildClaudeEnv` |
| Nested sandbox off when outer sandbox is Grok Landlock/Seatbelt | **Yes** | Avoid double-sandbox tool failures (same lesson as `DEEPSEC_INSIDE_SANDBOX`) |
| Output / log byte caps | **Yes** | Bound tool output before it hits model context or host memory |
| Partition + multi-VM orchestrator | **Optional / later** | Local concurrency + Grok subagents may replace Vercel Sandbox for v1 |
| Vercel OIDC / `@vercel/sandbox` / snapshot bootstrap | **Skip** | Platform-specific |
| Request-proxy for Bedrock `eager_input_streaming` | **Skip** unless Grok hits same API shape | |
| Firewall header MITM credential brokering | **Adapt** | Grok may use gateway auth outside the sandbox process instead of MITM; keep “agent never sees long-lived secrets in env” principle |
| Codex/Claude native binary remediation in VM | **Skip** | Grok agent is native Rust |

**Recommended Grok profile for DeepSec-like process/revalidate:**

```toml
# Conceptual — deepsec investigation profile
[profiles.deepsec]
extends = "read-only"
# Allow append-only scan state under workspace
read_write = [".deepsec/data", "data"]  # whatever path the port uses
deny = ["**/.env", "**/*.pem", "**/*credentials*", "**/.ssh/**"]
restrict_network = true   # Linux child net; agent should use only model API via host broker
```

If investigation must call the model from inside the sandboxed process, use host-side API proxy + allow only that host — never “full network” for bash.

---

## 6. False-positive reduction (revalidate)

### Pipeline role

```text
scan (regex candidates) → process (AI findings) → revalidate (TP/FP/Fixed/Uncertain) → triage/export
```

Revalidate is the main precision stage. Docs claim **~50%+ FP reduction**; post-revalidate HIGH+ FP rate cited ~**10–29%**.

### Selection

- Files with ≥1 finding lacking `revalidation` (unless `--force`).  
- Optional `--min-severity HIGH` (CRITICAL…BUG order).  
- `--only-slugs` / `--skip-slugs`, `--filter`, `--limit`, `--batch-size`, `--concurrency`.  
- Sorted CRITICAL first, then noise tier.

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `true-positive` | Confirmed issue |
| `false-positive` | Not a real vuln / not attacker-reachable as claimed |
| `fixed` | Code/history shows already fixed |
| `uncertain` | Insufficient confidence |
| `duplicate` | Same as another finding in-file; only accepted if primary has non-duplicate verdict |

Duplicate enforcement (two-pass writeback): agent-marked DUPEs without a valid primary are **rejected** and stay unrevalidated for retry (`duplicatesRejected`).

### Other FP / quality levers (not only revalidate)

| Lever | Effect |
|-------|--------|
| Strong models (Opus / gpt-5.5, thinking `xhigh` default) | Lower FP at higher cost |
| Project `INFO.md` (auth shape, threat model) | Large precision gain |
| Noise-tier matchers + custom matchers | Better file selection |
| Finding merge by `(vulnSlug, title)` | Stops re-run inflation |
| Refusal follow-up turn | No silent skips; refused files stay pending |
| Second-agent opinion (`--agent codex --reinvestigate`) | Cross-check |
| Prompt: skip tests/generated/vendored | Fewer junk findings |

**Port implication:** Ship revalidate as a first-class stage, not an optional script. Gate “act on HIGH+” on revalidated TP only. Preserve duplicate invariant.

---

## 7. Cost controls (`limit`, `concurrency`, `batch-size`)

### CLI knobs (process / revalidate)

| Flag | Default | Role |
|------|---------|------|
| `--limit <n>` | unlimited | Max files this run — **primary spend brake** |
| `--concurrency <n>` | `availableParallelism() - 1` | Parallel batches |
| `--batch-size <n>` | 5 | Files per agent call (peak files ≈ concurrency × batch-size) |
| `--thinking-level` | `xhigh` | Reasoning effort; dial down for smoke |
| `--model` / `--agent` | Backend defaults | Opus vs Sonnet vs Codex vs Pi |
| `--filter` / slugs | — | Scope |
| `--max-turns` | backend default | Cap agent loops |
| Sandbox `--sandboxes N` | — | Horizontal scale (wall clock ↓, $ ≈ same) |

### Operational patterns (from FAQ / reviewing-changes)

1. **`--limit 50`** first to calibrate $/file.  
2. Prefer **PR / `--diff`** over full tree for CI.  
3. Full scan free; **process is the $ stage**; revalidate ≈ process; triage ~1¢/finding.  
4. Drop thinking level for reinvestigation waves.  
5. Sonnet ~3× cheaper, ~10–20% higher FP vs Opus.  
6. Quota path: stop launching batches, abort in-flight, exit 1 — do not spin retries on empty credits.

### Accounting

- Run meta accumulates cost/tokens when SDKs report them.  
- Per-file `analysisHistory` splits batch cost by valid result count (avoids × batch-size inflation in metrics).  
- Codex needs explicit `MODEL_PRICING_*` for readout; missing pricing omits cost display only.

**Port implication:** Expose the same three knobs with conservative defaults for Grok (e.g. lower concurrency, medium thinking, required `--limit` for full-repo mode). Surface estimated/actual cost in status.

---

## 8. Diff mode

Documented in `docs/reviewing-changes.md`; implemented by `process` direct mode + `file-sources.ts`.

### Mutually exclusive sources

| Flag | Resolution |
|------|------------|
| `--diff <ref\|range>` | `git diff --name-only --diff-filter=AMRC <ref>` |
| `--diff-staged` | index vs HEAD |
| `--diff-working` | unstaged + untracked (`ls-files --others --exclude-standard`) |
| `--files <csv>` | explicit |
| `--files-from <path\|->` | newline list / stdin |

### Lifecycle

1. Resolve POSIX-relative paths under root; drop ignore globs (unless `--no-ignore`).  
2. Auto-create `data/<id>/project.json` if needed (no config rewrite).  
3. **Scoped `scanFiles`** — always creates records; matcher hits become prompt signals only.  
4. **Always process listed files** (bypasses pending-only filter) — even zero candidates.  
5. Optional `--comment-out` markdown for **net-new** findings only (`producedByRunId`).  
6. Exit codes: `0` no new findings; `1` new findings **or** agent batch errors / quota; other = runtime error.

### CI security pattern (upstream)

- Two-job split: analyze (secrets, no write) vs comment (`pull-requests: write`, no PR code).  
- Same-repo-only gate for forks.  
- `fetch-depth: 0` for merge-base diffs.  
- Threat: never give PR code + write perms in one job (postinstall / config load).

### Cost / misuse

- Wide diffs are expensive (per-file AI). Scope to merge base, not full ancestry.  
- Not for initial whole-repo sweep (use scan+process).  
- Not for revalidation (use `revalidate`).  
- `--reinvestigate` / `--manifest` ignored in direct mode (warn).

**Port implication:** Grok CI skill should mirror diff mode + exit-code gate + net-new-only comments. Use Grok’s worktree/git helpers when available; keep `--files-from -` for scripted filters.

---

## 9. Security: never exfiltrate more than the base agent; respect Grok sandbox

### What DeepSec sends out

- **Only** source snippets / paths the investigation agent includes in model prompts (and tool results the model requested).  
- FAQ: no phone-home telemetry; `data/` stays local unless user exports.  
- Gateway path: zero data retention marketed for Vercel AI Gateway; direct Anthropic follows Anthropic retention.

### Containment patterns worth preserving

1. **Tool surface:** read/grep/find/ls (and carefully constrained bash). Pi explicitly forbids running the app, network requests, exploitation.  
2. **Env scrubbing:** Claude child gets allowlisted env only — no `GITHUB_TOKEN`, `AWS_*`, etc.  
3. **Credential brokering:** real API keys not visible inside remote workers.  
4. **Egress allowlist:** one AI host when sandboxed.  
5. **No nested privilege escalation:** approval modes that never auto-approve network.  
6. **PR comment path:** only sanitized markdown artifact crosses privilege boundary.  
7. **Tarball hygiene:** skip symlinks that could point outside tree; honor gitignore (drops `.env*` if ignored).  
8. **Output caps:** prevent log/exfil bombs via huge stdout.

### Grok port hard rules

| Rule | Rationale |
|------|-----------|
| Run investigation under Grok `read-only` or `strict` (or custom `deepsec` profile) | Kernel FS + optional child-net block |
| Do **not** expand filesystem or network beyond what a normal Grok code-review session would have | “Never exfiltrate more than base agent” |
| Model API calls should use the same host broker / credentials path as the base Grok agent | No extra secret channels |
| Deny globs for secrets (`**/.env`, keys, `~/.ssh`) on top of profile | Kernel-enforced on Grok |
| State writes only under designated data dir | Compatible with read-only project files |
| Do not upload whole monorepo to third-party sandboxes without user opt-in | Upstream Vercel path is opt-in `sandbox process` |
| Export/report are user-initiated | No automatic sharing of `data/` |

### Threat notes from upstream that still apply

- Loading project `deepsec.config.ts` / plugins = **code execution** in the analyzer process — treat config as trusted as the repo.  
- AI gateway secret in CI still flows through install steps; use label gates / two-job splits.  
- Agents can read any file the sandbox allows — deny lists matter more than prompt text.

---

## 10. Known limitations of upstream

1. **FP remains material** even after revalidate (~10–29% on HIGH+). Human review still required for action.  
2. **Cost scales ~linearly with files × model strength**; no automatic budget hard-stop except quota errors and `--limit`.  
3. **Regex scan is incomplete coverage** — process is language-agnostic but selection quality depends on matchers; thin languages rely on expensive always-process (diff mode) or weak prioritization.  
4. **Binary / non-UTF8** handled as empty — no structured binary analysis.  
5. **No git** breaks `--diff*` entirely; github links optional.  
6. **Cross-host lock reclaim** waits up to 1h without PID visibility.  
7. **revalidate vs process concurrency** not fully mutexed on findings.  
8. **Model refusals** (exploit-like patterns) leave files pending; rare but needs re-run / other agent / ignorePaths.  
9. **Nested sandbox friction** forced `danger-full-access` inside Vercel VMs — correctness/security tradeoff.  
10. **Codex session DB** concurrency hazard if isolation regresses.  
11. **Sandbox upload still sends full source** of the target tree (minus gitignore/excludes) to remote VMs — trust Vercel Sandbox + gateway.  
12. **Windows path / CRLF** mostly handled, but matcher byte offsets are on normalized LF content.  
13. **Huge log / `rg '^'`** class failures require multi-layer output caps (still a residual OOM risk if caps regress).  
14. **Plugin/config RCE surface** in analyzer host.  
15. **Default thinking `xhigh`** optimizes for bugs not cost — easy to overspend.  
16. **Fixture expectations** (`fixtures/vulnerable-app`): intentional vulns (RCE via `exec`/`eval`, XSS, IDOR, SSRF, weak crypto, open redirect, etc.) — useful for port regression tests; not a complete vuln taxonomy.

---

## Prioritized risk list for the Grok port

| P | Risk | Mitigation |
|---|------|------------|
| **P0** | Accidental full-repo Opus-class process on monorepo → runaway $ | Require `--limit` or explicit `--all`; default to diff/PR scope; show estimate |
| **P0** | Agent under weak sandbox reads secrets / phones home via bash | Default `read-only`/`strict` + deny globs; env scrub; no open network for tools |
| **P0** | Concurrent workers clobber FileRecords | Port claim mutex + reclaim rules + append-only merge |
| **P1** | Interrupt leaves stuck `processing` locks | SIGINT→run error; PID liveness; document re-run safety |
| **P1** | Shipping findings without revalidate → noisy triage | Make revalidate recommended/default for HIGH+ export gates |
| **P1** | Credential leakage into tool env or logs | Allowlist env; never log secrets; host-side API auth |
| **P1** | Diff mode without git / shallow clone fails CI | Detect and message; document `fetch-depth`; `--files-from` fallback |
| **P2** | Nested Landlock + tool sandbox double-deny | Single outer Grok sandbox; disable redundant inner wrappers |
| **P2** | Binary/generated noise burns budget | Keep IGNORE_DIRS; add size/binary skip heuristics |
| **P2** | Model refusals on exploit samples | Retry policy / alternate model / ignorePaths |
| **P2** | Remote multi-VM complexity (Vercel) | Defer; use local concurrency first |
| **P3** | Metrics cost inflation if batch cost not split | Copy per-file cost split semantics |
| **P3** | Plugin/config execution trust | Document trust boundary; optional pure-JSON config mode |

---

## 5-line summary

DeepSec is an append-only, file-locked pipeline (scan → process → revalidate) with strong interrupt/reclaim semantics, PR diff mode, and multi-layer cost knobs — but process is expensive and FP remains non-zero without revalidate. Sandbox design centers on credential isolation, egress allowlisting, nested-sandbox avoidance, and log caps; Vercel microVMs are optional scale-out, not the core security model. For Grok, prefer `read-only`/`strict` profiles with an explicit data-dir write exception, never grant more FS/network than the base agent, and port locks + revalidate before fan-out. Gate CI on net-new findings from scoped diffs; require `--limit` (or equivalent) for full trees. Highest port risks: cost runaway, secret exposure under weak sandbox, and concurrent state clobber.
