---
name: deepsec-scan
description: >
  Run DeepSec regex matcher scan (no AI). Writes candidates under .grok/deepsec/.
argument-hint: "[path] [--root path]"
user-invocable: true
---

# DeepSec scan

## Runtime

Resolve the plugin root (directory containing `plugin.json` and `scripts/deepsec_cli.py`). Prefer:

1. `${GROK_PLUGIN_ROOT}` if set
2. `~/.grok/plugins/deepsec`
3. Repo path `plugins/deepsec` relative to the Grok-Fork checkout

```bash
PLUGIN_ROOT="${GROK_PLUGIN_ROOT:-$HOME/.grok/plugins/deepsec}"
CLI="$PLUGIN_ROOT/scripts/deepsec_cli.py"
python3 "$CLI" <subcommand> [args…]
```

Always pass `--root` as the user project root (cwd of the codebase under review).
State lives under `<project>/.grok/deepsec/` unless `--data-dir` is set.


```bash
python3 "$CLI" scan --root "${1:-$PWD}"
# or: python3 "$CLI" scan /path/to/tree --root /path/to/tree
```

Report candidate counts from stdout. Idempotent re-scans merge candidates.

