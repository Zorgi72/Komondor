# `/loginzyth` and `/logoutzyth` — how they work

This document explains **how Zyth SSO login is implemented**, how it differs from SpaceXAI `/login`, and how models/endpoints are managed.

## Architecture overview

```
  User types /loginzyth in TUI
           │
           ▼
  ┌────────────────────┐
  │  Pager (zyth CLI)  │  slash → Action::LoginZyth → Effect → ACP
  └─────────┬──────────┘
            │  x.ai/auth/loginzyth
            ▼
  ┌────────────────────┐     browser      ┌──────────────────────┐
  │  Shell agent       │ ───────────────► │ auth.zyth.app (Auth0) │
  │  OIDC PKCE flow    │ ◄── code ─────── │ Universal Login      │
  │  loopback :5612x   │                  └──────────────────────┘
  └─────────┬──────────┘
            │ Auth0 id_token (JWT)
            ▼
  ┌────────────────────────────────────┐
  │ POST ai-gateway.zyth.app           │
  │      /zyth/cli/v1/exchange         │
  │  • validate JWT vs Auth0 JWKS      │
  │  • mint LiteLLM virtual key (sk-)  │  ← master key stays on server
  └─────────┬──────────────────────────┘
            │ sk-… virtual key
            ▼
  ~/.grok/auth.json   scope: https://auth.zyth.app::{client_id}
  ~/.grok/zyth_endpoints.toml   → inference base = gateway
  ~/.grok/models_cache.json     → all /v1/models from gateway
```

## Why not store a raw Auth0 access token as the API key?

The AI Gateway edge only accepts:

| Credential | Role |
|------------|------|
| `sk-…` LiteLLM virtual key | Humans after SSO |
| `cpa_…` CLIProxyAPI keys | Machines / legacy |

Auth0 tokens alone return **401**. So after SSO the CLI **exchanges** the JWT for a virtual key via a server endpoint that holds the LiteLLM master key. The user never creates a key in the UI and never sees the master key — login is still SSO.

## Auth0 application setup

Terraform resource: `auth0_client.zyth_cli` in [AuthStack](https://github.com/0xpid00/AuthStack) (or local `/home/elliot/AuthStack`).

| Setting | Value |
|---------|--------|
| App type | **Native** (public client) |
| Auth method | `none` (PKCE only, no client secret) |
| Client ID (public) | `K8m9VaNO6p7LKEUdXj7qbsGKWEWdxRQb` |
| Callbacks | `http://127.0.0.1:{56120–56139}/callback` (+ localhost) |
| Grants | `authorization_code`, `refresh_token` |

**Important:** Auth0 does **not** accept a random OS port. The CLI binds the first free port in the registered range. Using `127.0.0.1:0` causes “Callback URL mismatch”.

## CLI flow (code map)

| Step | Code |
|------|------|
| Slash command | `crates/codegen/xai-grok-pager/src/slash/commands/loginzyth.rs` |
| Dispatch / effect | `app/dispatch/auth.rs`, `app/effects/helpers.rs` → `x.ai/auth/loginzyth` |
| ACP handler | `crates/codegen/xai-grok-shell/src/extensions/auth.rs` |
| OIDC + exchange | `auth/zyth/login.rs` |
| Pure protocol (tested) | `auth/zyth/protocol.rs` |
| Model catalog | `auth/zyth/models.rs` |
| Logout | `auth/zyth/logout.rs` + slash `logoutzyth.rs` |
| Defaults / ports | `auth/zyth/config.rs` |

### Loopback + paste

1. Bind `127.0.0.1` on a registered port (`ZYTH_LOOPBACK_PORTS`).
2. Open authorize URL (PKCE S256, `state`, `nonce`, `prompt=login`).
3. Race: HTTP `/callback` vs TUI/stdin paste of **full callback URL** (must include `state`).
4. Constant-time `state` check (empty state = fail — CSRF defense).
5. Token exchange (public client + `code_verifier`).
6. Prefer `id_token` JWT for gateway exchange.

### After success

- Persist under **distinct** `auth.json` scope (does not wipe `auth.x.ai`).
- Activate process env: `XAI_API_KEY` = virtual key, `GROK_XAI_API_BASE_URL` / `GROK_MODELS_BASE_URL` = gateway.
- Write `zyth_endpoints.toml` for restarts.
- `GET {gateway}/models` with virtual key → enrich + write `models_cache.json`.
- Backup prior catalog to `models_cache.pre-zyth.json`.
- Hot-reload models via `models_manager.on_auth_changed()`.

## Models

Live list comes from the gateway (example inventory):

- `grok-4.5` — 500k context, thinking high/medium/low  
- `grok-4.3`, `grok-4.20-*-reasoning` — reasoning efforts  
- `grok-4.20-*-non-reasoning` — no thinking controls  
- `grok-composer-2.5-fast`, `grok-build-0.1`, `grok-3-mini*`, imagine image/video  

Metadata (context, reasoning) is enriched from known slugs and from any prior cache entry with the same id. Every gateway id is installed with `supported_in_api = true` and `base_url` = gateway.

## `/logoutzyth`

Removes **Zyth model access only** — never logs out of the whole CLI or forces the welcome screen.

| Action | Detail |
|--------|--------|
| Remove | Zyth `auth.json` scopes only |
| Clear API key | Only if `xai::api_key` **equals** the Zyth virtual key |
| Endpoints | Delete `zyth_endpoints.toml`; unset matching env |
| Models | Restore `models_cache.pre-zyth.json` or strip gateway `base_url` entries |
| SpaceXAI | **Never** deleted (integrity check fails closed) |
| CLI session | **Always stays open** (toast only; never maps to full `/logout` welcome) |

## Gateway exchange service

Deployed on host `192.168.1.110` as container `litellm-cli-exchange` (AI-Gateway / litellm-cliproxy stack).

- Path: `POST /zyth/cli/v1/exchange` (no CPA key required; JWT required)
- Validates Auth0 RS256 JWT (issuer, exp, client allowlist)
- Calls LiteLLM `/key/generate` with master key
- Nginx rate-limits `/zyth/cli/`

Source: `litellm-cliproxy/sync/cli_key_exchange.py` (AI-Gateway deploy tree).

## Build & release

```sh
# Debug
cargo build -p xai-grok-pager-bin

# Release (what ships in release/)
cargo build -p xai-grok-pager-bin --release
# → target/release/zyth

# Package for install script
xz -f -k -T0 -c target/release/zyth > release/zyth-linux-x86_64.xz

# Install on this machine
./release/install-linux.sh
# or replace ~/.grok/downloads/zyth-linux-x86_64 directly
```

### Install layout

```
~/.grok/downloads/zyth-linux-x86_64   # real binary
~/.grok/bin/{zyth,grok,agent}         # symlinks → downloads
~/.local/bin/zyth                     # symlink for PATH
```

## Tests

```sh
cargo test -p xai-grok-shell --test loginzyth_protocol
# paste parser, state, scope isolation, exchange allowlist, model enrichment, logout
```

## Security checklist

- [x] Public PKCE client only (no client secret in binary)  
- [x] CSRF `state` always validated  
- [x] Loopback-only paste URLs  
- [x] Exchange + gateway base URL allowlisted (`*.zyth.app`)  
- [x] Master key never in client  
- [x] `auth.json` / caches mode `0600`  
- [x] Logout cannot wipe `auth.x.ai` via mis-set env issuer  

## Related repos

| Repo | Role |
|------|------|
| [0xpid00/Grok-Fork](https://github.com/0xpid00/Grok-Fork) | This CLI |
| [0xpid00/AuthStack](https://github.com/0xpid00/AuthStack) | Auth0 Terraform (Zyth CLI client) |
| AI-Gateway / litellm-cliproxy | LiteLLM + exchange + nginx edge |
| [xai-org/grok-build](https://github.com/xai-org/grok-build) | Upstream template for `/login` |
