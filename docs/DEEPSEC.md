# DeepSec in this fork — documentation index

Native **zero-Node** security pipeline ported from [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec).

## Upstream baseline (what we refactored from)

| Field | Value |
|-------|--------|
| **Upstream version** | **2.2.4** |
| **Upstream commit** | `97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04` |
| **Date** | 2026-07-19 |
| **Tree** | https://github.com/vercel-labs/deepsec/tree/97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04 |

Canonical pins in the plugin tree:

- [`plugins/deepsec/UPSTREAM.md`](../plugins/deepsec/UPSTREAM.md)
- [`plugins/deepsec/SOURCE_REV`](../plugins/deepsec/SOURCE_REV)
- [`plugins/deepsec/plugin.json`](../plugins/deepsec/plugin.json) → `upstream` field

## Code & packaging

| Path | Role |
|------|------|
| [`plugins/deepsec/`](../plugins/deepsec/) | Installable Grok plugin |
| `plugins/deepsec/scripts/deepsec_cli.py` | Headless CLI (all stages) |
| `plugins/deepsec/scripts/deepsec/` | Python engine (scan, process, export, state) |
| `plugins/deepsec/scripts/matchers/` | ~146 JSON matcher packs from upstream |
| `plugins/deepsec/skills/` | Slash skills: `/deepsec`, `/deepsec-scan`, … |
| `plugins/deepsec/fixtures/vulnerable-app/` | Official-style vulnerable fixture |
| `plugins/deepsec/scripts/tests/test_deepsec.py` | Shipped-path unit/integration tests |

Install for TUI slash commands:

```bash
ln -sfn "$(pwd)/plugins/deepsec" ~/.grok/plugins/deepsec
```

## Design & analysis docs

| Doc | Contents |
|-----|----------|
| [deepsec-full-analysis.md](deepsec-full-analysis.md) | Phase 0 synthesis |
| [deepsec-port-design.md](deepsec-port-design.md) | Command surface, state, packaging design |
| [verification-report.md](verification-report.md) | 100% checklist + edge results |
| [analysis/01-pipeline-and-architecture.md](analysis/01-pipeline-and-architecture.md) | Pipeline, resume, locks |
| [analysis/02-matcher-system.md](analysis/02-matcher-system.md) | Matchers / CWE inventory |
| [analysis/03-agent-prompts-and-context.md](analysis/03-agent-prompts-and-context.md) | INFO.md / process prompts |
| [analysis/04-data-layout-and-config.md](analysis/04-data-layout-and-config.md) | On-disk schemas |
| [analysis/05-edge-cases-security-and-limitations.md](analysis/05-edge-cases-security-and-limitations.md) | Edge cases & security |
| [analysis/06-grok-build-mapping.md](analysis/06-grok-build-mapping.md) | Grok skills/plugins mapping |

## Commands

| Slash / CLI | Stage |
|-------------|--------|
| `/deepsec` · `help` | Help + status overview |
| `/deepsec-init` · `init` | Scaffold `.grok/deepsec/` |
| `/deepsec-scan` · `scan [path]` | Regex matchers → candidates |
| `/deepsec-process` · `process [--diff]` | AI / heuristic / inject-response → findings |
| `/deepsec-revalidate` · `revalidate` | TP / FP / fixed / uncertain |
| `/deepsec-triage` · `triage` | P0 / P1 / P2 / skip |
| `/deepsec-enrich` · `enrich` | Git committers |
| `/deepsec-export` · `export --format md\|json\|md-dir` | Read-only export |
| `/deepsec-status` · `status` | Counts + lock |
| `/deepsec-resume` · `resume` | Reclaim locks, continue |
| `/deepsec-report` · `report` | `reports/report.md` + `.json` |

State: **`.grok/deepsec/data/<projectId>/`** (project) or override with `--data-dir`.

## Quick verify

```bash
python3 plugins/deepsec/scripts/tests/test_deepsec.py
python3 plugins/deepsec/scripts/deepsec_cli.py help   # shows upstream pin
```

## Release tags

- Git tag **`deepsec-v1.0.0`** on this fork marks the DeepSec plugin ship line.
- Remote: `origin` → `git@github.com:0xpid00/Komondor.git`
