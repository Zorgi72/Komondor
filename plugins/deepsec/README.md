# DeepSec for Grok Build

Native port of [vercel-labs/deepsec](https://github.com/vercel-labs/deepsec) as a **zero-Node** Grok plugin.

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
