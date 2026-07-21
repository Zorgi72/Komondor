---
name: deepsec-revalidate
description: >
  Revalidate DeepSec findings (true-positive / false-positive / fixed / uncertain).
argument-hint: "[--force] [--limit N] [--heuristic]"
user-invocable: true
---

# DeepSec revalidate

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
python3 "$CLI" revalidate --heuristic --root "$PWD"
# or inject model JSON:
python3 "$CLI" revalidate --inject-response verdicts.json --root "$PWD"
```

