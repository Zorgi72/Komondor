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

## Authentication: `/loginzyth` (Zyth AuthStack + AI Gateway)

SpaceXAI `/login` (auth.x.ai) remains unchanged. This fork adds **`/loginzyth`**, which mirrors the same OIDC Auth Code + PKCE loopback model but targets **Zyth**:

| Piece | Value |
|-------|--------|
| IdP issuer | `https://auth.zyth.app/` (AuthStack / Auth0) |
| Public CLI client | Auth0 native app **Zyth CLI** (PKCE, no client secret) |
| AI endpoint | `https://ai-gateway.zyth.app/v1` (LiteLLM OpenAI-compatible gateway) |
| Credential after SSO | LiteLLM **virtual key** (`sk-…`), minted via server-side exchange |

### Flow

1. `/loginzyth` opens the browser to Auth0 Universal Login on `auth.zyth.app`.
2. Loopback redirect on `http://127.0.0.1:{port}/callback` (random port) with CSRF `state` validation; paste-fallback for remote/SSH.
3. CLI exchanges the authorization code for tokens (public client + PKCE).
4. CLI calls `POST https://ai-gateway.zyth.app/zyth/cli/v1/exchange` with the Auth0 JWT; the gateway validates JWKS and mints a virtual key (master key never leaves the server).
5. Credentials are stored under a **distinct** `auth.json` scope (`https://auth.zyth.app::{client_id}`) so SpaceXAI sessions are not overwritten; inference is pointed at the Zyth gateway via `zyth_endpoints.toml` + API-key activation.

### Overrides (optional)

```bash
export ZYTH_OIDC_ISSUER=https://auth.zyth.app/
export ZYTH_OIDC_CLIENT_ID=<public client id>
export ZYTH_AI_GATEWAY_BASE_URL=https://ai-gateway.zyth.app/v1
export ZYTH_CLI_EXCHANGE_URL=https://ai-gateway.zyth.app/zyth/cli/v1/exchange
```

### `/logoutzyth`

Mirrors SpaceXAI `/logout` structure (attributable telemetry, fail-soft disk
updates) but is **scope-scoped** to Zyth:

| Cleared | Kept |
|---------|------|
| `auth.json` scopes under `https://auth.zyth.app::…` | `https://auth.x.ai::…` OAuth sessions |
| `xai::api_key` **only if** it equals the Zyth virtual key | Unrelated BYOK / `XAI_API_KEY` values |
| `~/.grok/zyth_endpoints.toml` | User `config.toml` unrelated settings |
| Process env set by `/loginzyth` (when values match) | Other env vars |

Idempotent: running `/logoutzyth` with no Zyth session is a soft no-op toast.

### Security notes

- No Auth0 client secrets or LiteLLM master keys in the binary.
- Tokens/secrets are not logged at info level; `auth.json` stays mode `0600`.
- Failures (IdP deny, timeout, bind failure, bad paste, network) are user-visible and non-corruptive.
- Key-exchange URL is allowlisted (`https://*.zyth.app`); no embedded URL credentials.
- `/logoutzyth` integrity-checks that non-Zyth scopes are never dropped.

## Upstream

Based on xAI’s public Apache-2.0 tree. External contributions to upstream are not accepted by xAI; this fork is for personal/local use.
