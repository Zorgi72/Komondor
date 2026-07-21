---
name: deepsec-process
description: >
  Investigate pending DeepSec candidate files and merge findings (AI or heuristic).
argument-hint: "[--diff] [--limit N] [--heuristic]"
user-invocable: true
---

# DeepSec process

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


## Preferred AI path

1. Claim + emit prompt:
```bash
python3 "$CLI" process --prompt-only --root "$PWD"
```
2. Read the written `.prompt.md`, investigate files with read-only tools (static analysis only).
3. Write JSON results and apply:
```bash
python3 "$CLI" process --inject-response /tmp/findings.json --root "$PWD"
```

## Offline / no-model path

```bash
python3 "$CLI" process --heuristic --root "$PWD"
```

## Diff mode

```bash
python3 "$CLI" process --diff HEAD --heuristic --root "$PWD"
```

Never invent merge logic — always use the CLI.

