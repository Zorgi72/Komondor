# DeepSec for Grok Build

Native port of [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec) as a **zero-Node** Grok plugin.

## Upstream baseline

This plugin was **refactored from upstream DeepSec `2.2.4`** at commit
[`97ebd04`](https://github.com/vercel-labs/deepsec/tree/97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04)
(2026-07-19). Full pin: [`UPSTREAM.md`](UPSTREAM.md) · [`SOURCE_REV`](SOURCE_REV).

| | |
|--|--|
| Upstream version | **2.2.4** |
| Upstream commit | `97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04` |
| This plugin | 1.0.0 |

## Install

```bash
# User plugin (auto-trusted)
cp -a plugins/deepsec ~/.grok/plugins/deepsec
# or symlink
ln -sfn /path/to/Grok-Fork/plugins/deepsec ~/.grok/plugins/deepsec
```

Skills appear as `/deepsec`, `/deepsec-scan`, `/deepsec-process`, …

## Quick start

```bash
cd your-repo
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py init --root .
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py scan --root .
# Offline findings from matcher candidates:
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py process --heuristic --root .
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py export --format md-dir --out ./findings --root .
python3 ~/.grok/plugins/deepsec/scripts/deepsec_cli.py status --root .
```

In the Grok TUI: `/deepsec init` → `/deepsec-scan` → `/deepsec-process` → `/deepsec-export`.

## State

`.grok/deepsec/data/<projectId>/` — FileRecords, runs, reports, INFO.md.

## Tests

```bash
python3 plugins/deepsec/scripts/tests/test_deepsec.py
```
