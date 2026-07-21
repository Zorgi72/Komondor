---
name: deepsec
description: >
  DeepSec security pipeline: init, scan, process, revalidate, triage, enrich, export, status, resume, report. Use when the user mentions deepsec, vulnerability scan, SAST, or /deepsec.
argument-hint: "[init|scan|process|revalidate|triage|enrich|export|status|resume|report] [args…]"
user-invocable: true
---

# DeepSec

Umbrella command. If the user passes a subcommand, follow that subcommand skill.

- No args: run `status` if workspace exists, else print help.
- `init` → deepsec-init
- `scan` → deepsec-scan
- `process` → deepsec-process
- `revalidate` → deepsec-revalidate
- `triage` → deepsec-triage
- `enrich` → deepsec-enrich
- `export` → deepsec-export
- `status` → deepsec-status
- `resume` → deepsec-resume
- `report` → deepsec-report

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
python3 "$CLI" help
python3 "$CLI" status --root "$PWD"
```

