# Zyth (Grok Build fork)

Private/custom fork of [xai-org/grok-build](https://github.com/xai-org/grok-build) rebranded as **Zyth**.

**Deep dive (SSO, models, security, release):** see **[docs/LOGINZYTH.md](docs/LOGINZYTH.md)**.

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
- **Code highlighting** uses a Vercel-accurate `.tmTheme` (`assets/zyth.tmTheme`)
- Aliases: `zyth`, `vercel`, `geist`, `mono`, `monochrome`

### Authentication (this fork)
| Command | Purpose |
|---------|---------|
| `/login` | SpaceXAI OAuth (`auth.x.ai`) — unchanged upstream path |
| **`/loginzyth`** | **Zyth AuthStack SSO** (`auth.zyth.app`) + AI Gateway models |
| `/logout` | Clear default (SpaceXAI) session |
| **`/logoutzyth`** | Clear **only** Zyth session + gateway models; keep SpaceXAI |

After `/loginzyth`:

1. Browser SSO on Auth0 Universal Login  
2. PKCE loopback on registered ports `56120–56139`  
3. Server-side mint of LiteLLM virtual key (SSO, not manual API key UI)  
4. Inference → `https://ai-gateway.zyth.app/v1`  
5. **All** live gateway models written to `~/.grok/models_cache.json` (context + thinking levels)

## Build

```sh
# Release (recommended)
cargo build -p xai-grok-pager-bin --release
# → target/release/zyth
# → target/release/xai-grok-pager

# Package for ./release/install-linux.sh
xz -f -k -T0 -c target/release/zyth > release/zyth-linux-x86_64.xz
```

## Install prebuilt Linux binary

From a clone of this repo:

```sh
./release/install-linux.sh
zyth --version
```

This installs:

- `~/.grok/downloads/zyth-linux-x86_64` — binary  
- `~/.grok/bin/{zyth,grok,agent}` — symlinks  
- `~/.local/bin/zyth` — PATH helper  

## Config

```toml
[ui]
theme = "zyth"
```

Settings, auth, and sessions stay under `~/.grok/` (same layout as upstream).

### Optional env (Zyth SSO)

```bash
export ZYTH_OIDC_ISSUER=https://auth.zyth.app/
export ZYTH_OIDC_CLIENT_ID=K8m9VaNO6p7LKEUdXj7qbsGKWEWdxRQb   # public
export ZYTH_AI_GATEWAY_BASE_URL=https://ai-gateway.zyth.app/v1
export ZYTH_CLI_EXCHANGE_URL=https://ai-gateway.zyth.app/zyth/cli/v1/exchange
```

## Tests

```sh
cargo test -p xai-grok-shell --test loginzyth_protocol
```

## Upstream

Based on xAI’s public Apache-2.0 tree. This fork is for personal/local use.
