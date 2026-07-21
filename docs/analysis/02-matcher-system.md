# DeepSec Matcher System Analysis

Source analyzed: `/tmp/grok-goal-f8e64663ee8a/implementer/deepsec`  
Primary packages: `packages/scanner`, `packages/core`  
Docs: `docs/writing-matchers.md`, `docs/supported-tech.md`  
Fixtures: `fixtures/vulnerable-app`  
Custom samples: `samples/webapp/matchers/*`

---

## 1. Matcher interface

Defined in `packages/core/src/plugin.ts` as `MatcherPlugin`. Re-exported via `@deepsec/scanner` and `deepsec/config`.

### `MatcherPlugin` fields

| Field | Type | Required | Role |
|-------|------|----------|------|
| `slug` | `string` | yes | Stable kebab-case ID; becomes `CandidateMatch.vulnSlug`; unique key in `MatcherRegistry` (custom plugins overwrite built-ins on collision) |
| `description` | `string` | yes | Human-readable purpose (docs / CLI) |
| `noiseTier` | `"precise" \| "normal" \| "noisy"` | yes | Ranking hint for AI process order; lower noise = higher priority (`precise=0`, `normal=1`, `noisy=2`) |
| `filePatterns` | `string[]` | yes | Glob seeds for the scanner driver (POSIX paths under project root). Tight globs preferred |
| `requires` | `MatcherGate` | no | Repo-level gate: skip matcher if tech/sentinels don't match. Omitted = always run |
| `examples` | `string[]` | no | Development-time positive snippets; exercised by `matcher-examples.test.ts`; not used at scan runtime |
| `match` | `(content: string, filePath: string) => CandidateMatch[]` | yes | Pure function over normalized file content + relative path |

### `MatcherGate` (optional `requires`)

```ts
interface MatcherGate {
  tech?: string[];                          // any-of: match if detectTech() tags include any
  sentinelFiles?: string[];                 // any-of: path or glob must exist under root
  sentinelContains?: (path, content) => boolean; // deeper content check on sentinel hit
}
```

Gate semantics (`evaluateGate` in `packages/scanner/src/index.ts`):

- No gate → always run.
- `tech` and `sentinelFiles` are a **union** (either layer may activate the matcher).
- Within each layer, tags/paths are **any-of**.
- Explicit `--matchers <slug,...>` **honors all named matchers** and bypasses gates (per-matcher, not all-or-nothing).

### Output: `CandidateMatch`

```ts
interface CandidateMatch {
  vulnSlug: string;        // usually === matcher.slug
  lineNumbers: number[];   // 1-based
  snippet: string;         // typically ±2 lines around first hit
  matchedPattern: string;  // human label for the sub-regex / shape
}
```

### Accumulator: `FileRecord.candidates`

Scanner never invents findings. It only appends `CandidateMatch[]` onto per-file records. Later AI `process` turns candidates into `Finding[]`.

### Helper: `regexMatcher`

```ts
// packages/scanner/src/matchers/utils.ts
function regexMatcher(
  slug: string,
  patterns: { regex: RegExp; label: string }[],
  content: string,
): CandidateMatch[]
```

Line-oriented: splits on `\n`, tests each regex per line, collects 1-based line numbers, stores first-hit context as `snippet`, one `CandidateMatch` **per pattern label** (not per line). Many matchers wrap this; others implement custom multi-line / negative-precheck logic in `match()`.

### Noise tiers (from docs + code)

| Tier | Intent | Typical use |
|------|--------|-------------|
| `precise` | Unambiguous vulnerable API / shape | `sql-injection`, `rce`, `prisma-raw-sql`, `secrets-exposure` |
| `normal` | Broader; AI disambiguates | `ssrf`, `xss`, `auth-bypass`, `open-redirect` |
| `noisy` | Entry-point coverage; force AI to read the file | `missing-auth`, framework route matchers, `path-traversal`, `service-entry-point` |

---

## 2. Complete inventory of built-in matcher slugs

**Registry size:** ~198 matchers registered in `createDefaultRegistry()` (`packages/scanner/src/matchers/index.ts`).  
**Note:** Some file names differ from slugs (especially Next.js: `js-nextjs-route-handlers.ts` → slug `all-route-handlers`).

Rough **CWE / category** grouping (CWE IDs are analytical mappings — DeepSec stores slugs, not CWE numbers):

### 2.1 Core injection & classic CWE shapes (always-on, JS/TS-centric globs)

| Slug | Noise | Rough CWE / category |
|------|-------|----------------------|
| `sql-injection` | precise | CWE-89 SQLi |
| `xss` | normal | CWE-79 XSS |
| `rce` | precise | CWE-78 / CWE-94 command/code injection |
| `ssrf` | normal | CWE-918 SSRF |
| `path-traversal` | noisy | CWE-22 path traversal |
| `open-redirect` | normal | CWE-601 open redirect |
| `unsafe-redirect` | normal | CWE-601 (related) |
| `untrusted-redirect-following` | normal | CWE-601 / fetch redirect abuse |
| `secrets-exposure` | precise | CWE-798 hardcoded credentials |
| `secrets-plaintext-exposure` | precise | CWE-312 plaintext secrets |
| `insecure-crypto` | noisy | CWE-327 / CWE-330 weak crypto / PRNG |
| `crypto-usage` | (surface) | crypto review surface |
| `unsafe-deserialization` | normal | CWE-502 deserialization |
| `object-injection` | (normal) | CWE-915 / mass-assignment-like |
| `spread-operator-injection` | precise | prototype / property injection |
| `cors-wildcard` | normal | CWE-942 CORS misconfig |
| `algorithm-confusion` | normal | JWT alg confusion (CWE-347) |
| `jwt-handling` | normal | CWE-287 / CWE-347 JWT misuse |
| `oauth-flow` | normal | OAuth/OIDC flaws |
| `session-cookie-config` | normal | CWE-614 / cookie flags |
| `postmessage-origin` | normal | CWE-346 origin checks |
| `dangerous-html` | normal | CWE-79 HTML sink |
| `unsafe-json-in-html` | normal | CWE-79 JSON-in-script XSS |
| `url-regex-validation` | precise | weak URL validation bypass |
| `rate-limit-bypass` | normal | CWE-770 missing rate limit |
| `env-exposure` | normal | env/secret leakage |
| `env-var-as-bool` | normal | insecure feature flags |
| `process-env-access` | normal | env surface |
| `secret-env-var` | precise | secret env patterns |
| `secret-in-fallback` | precise | secrets in default/fallback |
| `secret-in-log` | precise | CWE-532 secret logging |
| `sensitive-data-in-traces` | normal | PII/secret in telemetry |
| `error-message-leak` | normal | CWE-209 info disclosure |
| `response-header-leak` | normal | header leakage |
| `cache-key-poisoning` | normal | cache poisoning |
| `cache-key-scope` | normal | cache key tenant scope |
| `cross-tenant-id` | precise | multi-tenant IDOR-ish |
| `unverified-lookup` | precise | missing ownership check on lookup |
| `non-atomic-operation` | normal | TOCTOU / race |
| `non-atomic-read-delete` | normal | race on delete |
| `missing-await` | normal | async correctness / security side effects |
| `fs-write-symlink-boundary` | normal | symlink escape on write |
| `git-provider-url-injection` | normal | URL injection into git providers |
| `expensive-api-abuse` | normal | cost amplification |
| `streaming-endpoint` | normal | streaming attack surface |
| `debug-endpoint` | normal | debug surfaces left on |
| `dev-auth-bypass` | normal | dev-mode auth skip |
| `test-header-bypass` | precise | test header auth bypass |
| `security-behind-flag` | precise | security gated only by flag |
| `cron-secret-check` | normal | cron auth via weak secret |
| `event-handler-mismatch` | normal | handler/event wiring bugs |
| `agent-tool-definition` | normal | agent tool surface |
| `agent-loop-no-cap` | normal | unbounded agent loops |
| `agentic-untrusted-prompt-input` | normal | prompt injection input paths |
| `prompt-leaks-system-prompt` | normal | system prompt leakage |
| `mcp-tool-handler` | precise | MCP tool handlers |
| `slack-signing-verification` | precise | webhook signing |
| `webhook-handler` | precise | webhook entry points |
| `public-endpoint` | normal | public HTTP surface |
| `service-entry-point` | noisy | lambda/event/service entry |
| `auth-bypass` | normal | CWE-287 auth flaws |
| `missing-auth` | normal | CWE-306 missing auth (weak entry-point net) |
| `iam-permissions` | normal | over-broad IAM |
| `server-action` | normal | Next server action surface |
| `server-action-no-auth` | normal | server action missing auth |
| `use-server-export` | normal | `"use server"` exports |
| `all-route-handlers` | noisy | all Next route handlers |
| `all-server-actions` | noisy | all server actions |
| `nextjs-middleware` | normal | middleware surface |
| `nextjs-middleware-only-auth` | normal | middleware-only auth anti-pattern |
| `catchall-router` | normal | catch-all routers |
| `catch-all-route-auth` | normal | catch-all auth gaps |
| `page-data-fetch` | normal | page data fetches |
| `page-without-auth-fetch` | normal | unauth page data |
| `framework-untrusted-fetch` | normal | Next untrusted fetch |
| `framework-internal-header` | normal | internal header trust |
| `framework-server-action` | normal | framework server action |
| `framework-image-optimizer` | normal | image optimizer abuse |
| `framework-edge-sandbox` | normal | edge sandbox issues |
| `zod-passthrough-mass-assignment` | normal | mass assignment via Zod passthrough |
| `drizzle-mass-assignment` | normal | Drizzle mass assignment |
| `drizzle-raw-sql` | precise | Drizzle raw SQL |
| `prisma-raw-sql` | precise | Prisma `$queryRaw*` (CWE-89) |
| `soql-injection` | precise | SOQL injection |
| `snowflake-bigquery-sql` | precise | warehouse SQL injection |
| `trpc-public-procedure` | normal | unauth tRPC procedures |
| `sandbox-runtime-script` | precise | sandbox runtime scripts |
| `proto-rpc-surface` | normal | protobuf RPC surface |
| `connectrpc-handler-impl` | normal | ConnectRPC handlers |
| `unix-socket-listener` | precise | Unix socket listeners |
| `go-http-handler` | noisy | net/http handlers |
| `go-ssrf` | normal | Go SSRF |
| `go-command-injection` | precise | Go command injection |
| `go-embed-asset` | normal | embed FS surface |
| `lua-string-concat-url` | normal | Lua URL concat |
| `lua-ngx-exec` | precise | OpenResty exec |
| `lua-shared-dict-poisoning` | normal | shared dict poisoning |
| `lua-regex-bypass` | precise | Lua regex bypass |
| `lua-crypto-weakness` | precise | Lua crypto weakness |
| `dockerfile-from-mutable-tag` | precise | mutable image tags |
| `dockerfile-curl-pipe-unverified` | precise | curl \| sh supply chain |
| `dockerfile-run-as-root` | normal | container root |
| `github-workflow-security` | precise | GHA injection / secrets |
| `k8s-secret-reference` | normal | K8s secret refs |
| `k8s-secrets-init-container` | normal | secrets via init containers |
| `tf-iam-wildcard` | precise | Terraform IAM `*` |
| `tf-public-ingress` | precise | 0.0.0.0/0 ingress |
| `tf-encryption-missing` | normal | missing encryption |
| `tf-secret-in-data` | precise | secrets in TF data |
| `tf-module-unpinned` | precise | unpinned modules |
| `tf-iac-surface` | normal | IaC attack surface |

### 2.2 Framework entry-point matchers (gated on `detectTech` tags; mostly `noisy`)

| Ecosystem | Slugs |
|-----------|-------|
| **Node/JS** | `js-express-route`, `js-fastify-route`, `js-nestjs-controller`, `js-hono-route`, `js-koa-route`, `js-hapi-route`, `js-remix-route`, `js-sveltekit-route`, `js-nuxt-route`, `js-astro-endpoint`, `js-solidstart-action`, `js-graphql-resolver`, `js-socketio-handler`, `js-bullmq-processor`, `js-bun-serve`, `js-deno-route`, `js-workers-fetch` |
| **PHP** | `php-laravel-route`, `php-symfony-controller`, `php-slim-route`, `php-yii-controller`, `php-cakephp-controller`, `php-codeigniter-controller`, `php-wordpress-rest`, `php-drupal-controller`, `php-magento-controller` |
| **Python** | `py-django-view`, `py-fastapi-route`, `py-flask-route`, `py-starlette-route`, `py-aiohttp-route`, `py-tornado-handler`, `py-sanic-route`, `py-bottle-route`, `py-falcon-resource`, `py-celery-task`, `py-airflow-dag` |
| **Ruby** | `rb-rails-controller`, `rb-sinatra-route`, `rb-grape-endpoint`, `rb-hanami-action`, `rb-roda-route` |
| **Go frameworks** | `go-gin-route`, `go-echo-route`, `go-fiber-route`, `go-chi-route`, `go-gorilla-route`, `go-buffalo-route`, `go-cobra-command` |
| **Rust** | `rs-actix-route`, `rs-axum-route`, `rs-rocket-route`, `rs-warp-filter`, `rs-tide-route`, `rs-poem-route`, `rs-tonic-grpc`, `rs-lambda-runtime` |
| **JVM** | `jvm-spring-controller`, `jvm-ktor-route`, `jvm-micronaut-controller`, `jvm-jaxrs-resource` |
| **.NET** | `dotnet-aspnet-controller`, `dotnet-minimal-api`, `dotnet-razor-pages`, `dotnet-azure-function` |
| **Other** | `ex-phoenix-controller`, `cr-kemal-route`, `clj-ring-handler`, `erl-cowboy-handler`, `swift-vapor-route`, `dart-shelf-handler`, `apex-rest-resource` |
| **Cloud functions** | `lambda-aws-handler`, `gcp-cloud-function`, `azure-function-handler` |
| **Mobile** | `android-manifest-export`, `ios-url-scheme` |

### 2.3 Language-scoped raw SQL / NoSQL (gated on language or ORM tech)

| Slug | Gate (typical) | Category |
|------|----------------|----------|
| `js-sql-raw` | JS/TS ecosystem | CWE-89 |
| `js-nosql-injection` | JS/TS | CWE-943 NoSQL |
| `py-sql-raw` | `python` | CWE-89 |
| `py-nosql-injection` | `python` | CWE-943 |
| `jvm-sql-raw` | `jvm` | CWE-89 |
| `php-sql-raw` | `php` | CWE-89 |
| `rb-sql-raw` | `ruby` | CWE-89 |
| `go-sql-raw` | `go` | CWE-89 |
| `rs-sql-raw` | `rust` | CWE-89 |
| `dotnet-sql-raw` | `dotnet` | CWE-89 |
| `prisma-raw-sql` | `prisma` | CWE-89 |
| `drizzle-raw-sql` | drizzle tech | CWE-89 |

### 2.4 Category summary (for port planning)

| Category bucket | Approx. share | Examples |
|-----------------|---------------|----------|
| Entry-point / framework surface (`noisy`) | ~half of registry | `*-route`, `*-controller`, `all-route-handlers`, `missing-auth` |
| Injection (SQL/NoSQL/cmd/XSS/SSRF/path) | ~25 | `sql-injection`, `rce`, `xss`, language `*-sql-raw` |
| Auth / session / IAM | ~15 | `auth-bypass`, `jwt-handling`, `server-action-no-auth` |
| Secrets / crypto / config | ~15 | `secrets-exposure`, `insecure-crypto`, TF/K8s secret matchers |
| Infra (Docker, TF, GHA, K8s) | ~15 | `tf-*`, `dockerfile-*`, `github-workflow-security` |
| AI / agentic / messaging | ~8 | `mcp-tool-handler`, `agentic-untrusted-prompt-input` |
| Race / cache / multi-tenant | ~10 | `non-atomic-*`, `cache-key-*`, `cross-tenant-id` |

Built-in always-on matchers tilt heavily toward **TypeScript/JavaScript** globs (`**/*.{ts,tsx,js,jsx}`). Other languages rely on gated framework matchers + language SQL matchers.

---

## 3. How scan applies matchers and merges candidates into FileRecords

### 3.1 High-level flow (`scan()`)

```
ensureProject → detectTech (once) → write tech.json
  → select matchers (all | --matchers slugs)
  → evaluateGate per matcher (unless honor-all via --matchers)
  → create RunMeta (type: scan)
  → RegexScannerDriver.scan(...)
  → write FileRecords
  → languageStats + completeRun
```

Plugins merge via:

```
createDefaultRegistry()  +  getRegistry().matchers (from deepsec.config plugins)
```

Custom plugin matchers `register()` into the same `MatcherRegistry` Map keyed by `slug` — **last write wins** for a given slug.

### 3.2 `RegexScannerDriver` algorithm

1. **Ignore set:** `IGNORE_DIRS` (node_modules, dist, tests, fixtures, md, …) + DeepSec data-tree ignores + optional `ignorePaths` from CLI/config.
2. **Pre-glob dedupe:** Group matchers by sorted `filePatterns` join key; one `glob()` per unique pattern set; cache relative POSIX paths.
3. **Per matcher, per file:**
   - Read content once (content cache); **CRLF → LF** normalize.
   - `matcher.match(content, relPath)`.
   - Load or create in-memory `FileRecord` for `relPath`.
4. **Candidate merge (dedupe key):**

```
(vulnSlug, matchedPattern, lineNumbers.join(","))
```

If that triple already exists on `record.candidates`, skip. Else `push`.  
**Does not clear** prior candidates from previous scans when reusing a loaded record.

5. Update `lastScannedAt`, `lastScannedRunId`, `fileHash` (sha256 of **normalized** content).
6. After all matchers: `writeFileRecord` for every upserted path.
7. **Does not** reset `status` / invalidate prior AI analysis on re-scan.

### 3.3 `scanFiles()` (diff / explicit list mode)

- File universe = caller list (not glob seed).
- Each matcher's `filePatterns` become **minimatch filters** on each path.
- Writes a `FileRecord` for **every** listed file (even zero matches) so `process --diff` can still investigate.

### 3.4 Progress events

`ScanProgress`: `matcher_started` / `matcher_done` / `file_scanned` with optional `matcherIndex`/`matcherTotal` for CLI bars.

### 3.5 Priority scoring for process phase

```ts
noiseScore(slugs) = min(tierValue of each candidate slug)
// precise=0, normal=1, noisy=2, none=3
```

Files with precise candidates are processed first.

---

## 4. Custom matcher authoring pattern

Documented in `docs/writing-matchers.md`; reference samples in `samples/webapp/`.

### 4.1 Layout

```
.deepsec/
├── deepsec.config.ts
└── matchers/
    ├── webapp-debug-flag.ts
    └── webapp-route-no-rate-limit.ts
```

### 4.2 Config wiring

```ts
import { defineConfig, type DeepsecPlugin } from "deepsec/config";
import { webappDebugFlag } from "./matchers/webapp-debug-flag.js";
import { webappRouteNoRateLimit } from "./matchers/webapp-route-no-rate-limit.js";

const webappPlugin: DeepsecPlugin = {
  name: "webapp-internal",
  matchers: [webappDebugFlag, webappRouteNoRateLimit],
};

export default defineConfig({
  projects: [{ id: "webapp", root: "./your-app", /* ... */ }],
  plugins: [webappPlugin],
});
```

### 4.3 Two sample styles

**A. Thin regex via `regexMatcher`** (`webapp-debug-flag`):

- `noiseTier: "normal"`
- Tight `filePatterns`
- Skip tests by path
- Multiple `{ regex, label }` entries

**B. Custom logic with negative pre-check** (`webapp-route-no-rate-limit`):

- Skip `_internal/` and webhooks
- If file already has rate-limit wrapper → return `[]`
- Else flag exported HTTP handlers

### 4.4 Authoring checklist

1. Prefer one concern per slug.
2. Choose noise tier deliberately (`precise` when shape is unambiguous; `noisy` for entry-point nets).
3. Keep `filePatterns` tight (language + directory anchors).
4. Generalize shapes, not one-off identifiers (`requireSession` → any auth dependency pattern).
5. Optional `requires: { tech: [...] }` for framework-specific matchers.
6. Optional `examples: [...]` for CI contract tests.
7. Spot-check with `scan --matchers <slug>`: 0 hits = too strict; huge hit counts = too loose.

### 4.5 Upstream vs local

| Catches… | Where |
|----------|--------|
| Org-specific helpers / layouts | Inline plugin |
| Generic CWE or popular framework | Consider upstreaming to deepsec |

---

## 5. Port strategy for Grok Build

**Goal:** Reproduce DeepSec's scan-side value without requiring Node at runtime. Prefer declarative matchers + a lightweight walker.

### 5.1 Recommended architecture

```
matchers/*.yaml|json   →  load/validate  →  regex engine walker  →  candidates.json / FileRecord-like store
       ↑                         ↑
  (optional skill packages)   tech detection (lockfile/sentinel heuristics)
```

| Component | Port approach | Avoid |
|-----------|---------------|--------|
| Matcher defs | **JSON or YAML** schemas: `slug`, `description`, `noiseTier`, `filePatterns`, `requires.tech`, `patterns[{regex,label,flags}]`, optional `pathExclude`, optional `fileContentNegative` (string/regex that zeros the matcher) | Shipping ~200 TS modules |
| `match()` logic | Cover **≥90%** of built-ins with pure multi-pattern regex + line context. For negative pre-checks / multi-step logic, either (a) extend schema with `whenNot` / `allOf` / `skipIfContentMatches`, or (b) allow a small set of named **predicate plugins** in Rust/Python | Full JS `Function` eval of matchers |
| Regex engine | Rust (`regex` crate + `globwalk`/`ignore`) **or** Python (`pathlib` + `re` + `fnmatch`/`wcmatch`) | Embedding Node solely for matchers |
| File walk | Same ignore list as `IGNORE_DIRS`; normalize CRLF; POSIX relative paths | Re-scanning `node_modules` / `dist` |
| Registry | Directory of YAML files + optional user override dir (last-wins by slug) | Compile-time registry |
| Gates | Tech tags from lockfile/sentinels (port `detect-tech.ts` heuristics as data) | Running all framework matchers on every repo |
| Merge | Same triple-key dedupe into per-file candidate lists | Overwriting history |

### 5.2 Declarative schema sketch (illustrative)

```yaml
slug: sql-injection
description: Raw SQL string concatenation or interpolation
noiseTier: precise
filePatterns: ["**/*.{ts,tsx,js,jsx}"]
# requires: { tech: ["typescript"] }   # optional
pathExclude: ['\.(test|spec)\.']
patterns:
  - regex: '`\s*SELECT\s+[^`]{0,400}\$\{'
    label: "template literal SELECT with interpolation"
  - regex: 'query\s*\(\s*`[^`]*\$\{'
    label: "query() with interpolation"
examples:
  - "const q = `SELECT * FROM users WHERE id = ${id}`;"
```

For `missing-auth`-style negative checks:

```yaml
slug: webapp-route-no-rate-limit
noiseTier: normal
filePatterns: ["src/api/**/route.ts"]
skipIfContentMatches:
  - '\bwithRateLimit\s*\('
  - '\brateLimiter\s*\.\s*check\s*\('
patterns:
  - regex: 'export\s+(?:async\s+)?(?:default|const|function)\s+(?:GET|POST|...)'
    label: "exported handler with no rate-limit wrapper in file"
```

### 5.3 What needs non-declarative escape hatches

| Pattern in DeepSec | Example | Port option |
|--------------------|---------|-------------|
| Conditional second pass | `insecure-crypto` only flags `Math.random` if security keywords present | Schema: `patterns[].onlyIfContentMatches` |
| Multi-line / function-level | Custom auth-shape "handler without Depends(...)" | Allow small Python/Rust helper ID: `helpers: ["fastapi_route_no_auth"]` |
| Sentinel content predicates | `requires.sentinelContains` | YAML cannot express closures — use `sentinelContainsRegex` on path content |

### 5.4 Prefer pure skill packaging

- Ship matcher packs as **data** under a Grok skill (`matchers/core/*.yaml`, `matchers/nextjs/*.yaml`).
- Runner can be a **skill script** (Python preferred for iteration) or a tiny Rust binary if performance on monorepos matters.
- Keep AI triage outside the matcher layer (same split as DeepSec: scan cheap → process expensive).

### 5.5 Parity tiers

1. **MVP:** Core 10 fixture matchers (below) + merge + ignore globs + noise tier metadata.  
2. **Productive:** + entry-point noisy matchers for top stacks you care about (Express/Next/FastAPI/Rails).  
3. **Full port:** Declarative conversion of all ~198 + tech gates + language SQL packs.

---

## 6. Minimum viable matcher set for `fixtures/vulnerable-app` correctness

Fixture root: `fixtures/vulnerable-app/src`. Unit coverage lives in `packages/scanner/src/__tests__/matchers.test.ts`.

| Fixture file | Comment / intended vuln | MVP matcher slug | Why required |
|--------------|-------------------------|------------------|--------------|
| `api/admin.ts` | auth-bypass | **`auth-bypass`** | Session / `verifyToken` / admin check patterns |
| `api/users.ts` | missing access control + SQLi in handlers | **`missing-auth`** (+ optional `sql-injection`) | HTTP entry points as weak candidates |
| `api/upload.ts` | path-traversal | **`path-traversal`** | `readFile`/`path.join` with request-derived paths |
| `components/comment.tsx` | XSS | **`xss`** | `dangerouslySetInnerHTML`, `innerHTML` |
| `lib/db.ts` | SQL injection | **`sql-injection`** | Template literal / concat SQL |
| `lib/fetch-proxy.ts` | SSRF | **`ssrf`** | `fetch` with user-controlled URL |
| `lib/crypto.ts` | insecure crypto | **`insecure-crypto`** | MD5, `createCipher`, `Math.random` in token context |
| `utils/exec-helper.ts` | RCE | **`rce`** | `exec` / `execSync` / `eval` |
| `utils/redirect.ts` | open redirect | **`open-redirect`** | `res.redirect` / redirect URL params |
| `config.ts` | secrets exposure | **`secrets-exposure`** | Hardcoded keys/passwords/AWS IDs |

### MVP set (exact 10 slugs)

```
auth-bypass
missing-auth
xss
rce
sql-injection
ssrf
path-traversal
secrets-exposure
insecure-crypto
open-redirect
```

These are the **core security** block registered first in `createDefaultRegistry()` and the only ones asserted against the vulnerable-app fixtures.

### Implementation notes for fixture parity

- Globs must include `**/*.{ts,tsx,js,jsx}` (and `.json` for secrets if config moves).
- Content must be line-split after CRLF normalization.
- `path-traversal` on `upload.ts` hits via `` `/data/${req.query.file}` `` and request-derived path patterns — keep those regexes.
- `secrets-exposure` must accept `sk-live-` / `sk_live_` and generic `password = "..."` shapes (fixture uses hyphenated Stripe-like key and plaintext password).
- `missing-auth` is intentionally **weak/noisy**: it flags handlers even when some auth symbols exist (admin.ts is still a candidate).
- Do **not** require Next.js gated matchers for this fixture; the app is plain TS handlers, not a full Next project.

### Optional stretch (still small)

| Slug | Reason |
|------|--------|
| `dangerous-html` | Overlaps XSS sinks |
| `public-endpoint` | Extra entry-point coverage |

---

## Architecture diagram (scan path)

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ detectTech(root)│────▶│ evaluateGate()   │────▶│ active MatcherPlugin│
└─────────────────┘     │ per matcher      │     │ list                │
                        └──────────────────┘     └──────────┬──────────┘
                                                           │
                        ┌──────────────────────────────────▼──────────┐
                        │ RegexScannerDriver                          │
                        │  glob(filePatterns) → read → match()        │
                        │  merge candidates by (slug,label,lines)     │
                        └──────────────────────────────────┬──────────┘
                                                           │
                        ┌──────────────────────────────────▼──────────┐
                        │ FileRecord { candidates[], fileHash, ... }  │
                        │ writeFileRecord → data/<project>/files/...  │
                        └─────────────────────────────────────────────┘
```

---

## 5-line summary

1. Matchers are pure plugins (`slug`, `noiseTier`, `filePatterns`, optional `requires`, `match() → CandidateMatch[]`) registered in a Map, with plugins last-winning on slug collisions.  
2. Scan pre-globs by shared patterns, runs every active matcher over normalized file text, and merges candidates into FileRecords with triple-key dedupe without wiping prior analysis.  
3. ~198 built-ins span classic CWEs, Next/JS-heavy always-on rules, and tech-gated multi-language entry-point/SQL packs.  
4. Custom matchers are YAML/TS plugins wired through `deepsec.config`; Grok Build should port defs as JSON/YAML + a Rust/Python regex walker (no Node).  
5. Fixture correctness needs only the ten core slugs: auth-bypass, missing-auth, xss, rce, sql-injection, ssrf, path-traversal, secrets-exposure, insecure-crypto, open-redirect.
