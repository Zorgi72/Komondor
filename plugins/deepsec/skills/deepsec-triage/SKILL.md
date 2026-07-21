---
name: deepsec-triage
description: >
  Triage DeepSec findings into P0/P1/P2/skip priorities.
argument-hint: "[--force] [--min-severity HIGH] [--heuristic]"
user-invocable: true
---

# DeepSec triage

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
python3 "$CLI" triage --heuristic --root "$PWD"
python3 "$CLI" triage --min-severity HIGH --heuristic --root "$PWD"
```

