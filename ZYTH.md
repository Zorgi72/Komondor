# Zyth (Grok Build fork)

Private/custom fork of [xai-org/grok-build](https://github.com/xai-org/grok-build) rebranded as **Zyth**.

## What’s different

### Branding
- CLI binary / argv name: **`zyth`** (also still installable as `grok`)
- User-facing “Grok Build” / “Grok Build Beta” strings → **Zyth**
- Theme display names: **Zyth Dark**, **Zyth Light**, **ZYTH**
- Welcome badge no longer shows “Grok Build Beta”
- Welcome changelog panel + Changelog menu row removed (logo + menu only)

### Boot art
- Braille xAI logo replaced with the Zyth `$` ASCII mark from `assets/logo/`

### ZYTH theme (`theme = "zyth"`)
- Pure-black OLED canvas, **brighter** near-white body text (`#fafafa`)
- Pure white (`#ffffff`) accents for focus / headings
- **Code highlighting** uses a Vercel-accurate `.tmTheme` (`assets/zyth.tmTheme`):
  - Keyword / storage: `#FF0080`
  - String: `#50E3C2`
  - Function: `#3291FF`
  - Type / cyan: `#00DFD8`
  - Number: `#F5A623`
  - Comment: `#666666`
  - Background: `#000000`
- Aliases: `zyth`, `vercel`, `geist`, `mono`, `monochrome`

### UI polish
- `~/.grok/pager.toml` companion settings for density/chrome (optional)

## Build

```sh
cargo build -p xai-grok-pager-bin --release
# artifacts:
#   target/release/zyth
#   target/release/xai-grok-pager
```

## Install prebuilt Linux binary

```sh
./release/install-linux.sh
# or manually:
xz -dk release/zyth-linux-x86_64.xz
# place binary on PATH as `zyth`
```

## Config

```toml
[ui]
theme = "zyth"
```

Settings, auth, and sessions stay under `~/.grok/` (same layout as upstream).

## Upstream

Based on xAI’s public Apache-2.0 tree. External contributions to upstream are not accepted by xAI; this fork is for personal/local use.
