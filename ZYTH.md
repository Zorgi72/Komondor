# ZYTH CLI (Grok Build fork)

Fork of [xai-org/grok-build](https://github.com/xai-org/grok-build) rebranded as **ZYTH CLI**.

**Deep dive (SSO, models, security, release):** see **[docs/LOGINZYTH.md](docs/LOGINZYTH.md)**.

## Highlights

- CLI name: **`zyth`** (launcher + all user-facing command hints)
- Themes: **ZYTH Dark** (`zyth-dark`) and **ZYTH Light** (`zyth-light`) only
- Welcome: braille mark baked into source, no tip row, no Grok news/changelog
- Tab title: no `grok` brand
- Telemetry: hard-disabled (mode + Mixpanel + `track()` no-op)

### ZYTH Dark theme (`theme = "zyth-dark"`)

- Pure-black OLED canvas, near-white body text
- Pure white prompt borders
- Vercel-accurate code highlighting (`zyth.tmTheme`)
- Aliases: `zyth`, `zyth-dark`, `vercel`, `geist`, `mono`

### Authentication (this fork)

| Command | Purpose |
|---------|---------|
| **`/login`** | **Default:** Zyth AuthStack SSO (`auth.zyth.app`) + AI Gateway models |
| `/loginzyth` | Legacy alias for `/login` |
| **`/logout`** | **Default:** remove **only** Zyth models + gateway; keep CLI session + SpaceXAI (never forces welcome) |
| `/logoutzyth` | Legacy alias for `/logout` |
| `/xailogin` | SpaceXAI OAuth (`auth.x.ai`) — former upstream `/login` |
| `/xailogout` | Full SpaceXAI logout + welcome screen — former upstream `/logout` |

Welcome banner **“Login with Zyth”** starts the Zyth path (`Action::LoginZyth`), not SpaceXAI.

After `/login` (or `/loginzyth`):

1. Browser SSO on Auth0 Universal Login
2. PKCE loopback on registered ports `56120–56139`
3. Server-side mint of LiteLLM virtual key
4. Inference → `https://ai-gateway.zyth.app/v1`
5. Live gateway models written to `~/.grok/models_cache.json`

## Install prebuilt Linux x86_64

```sh
./release/install-linux.sh
# or:
xz -dk release/zyth-linux-x86_64.xz
# place on PATH as `zyth`
```

This installs:

- `~/.grok/downloads/zyth-linux-x86_64` — binary
- `~/.grok/bin/{zyth,grok,agent}` — symlinks
- `~/.local/bin/zyth` — PATH helper

## Build

```sh
cargo build -p xai-grok-pager-bin --release --bin zyth
# → target/release/zyth

# Package for ./release/install-linux.sh
xz -f -k -T0 -c target/release/zyth > release/zyth-linux-x86_64.xz
```

## Config

```toml
[ui]
theme = "zyth-dark"
```

Settings/auth still live under `~/.grok/` (upstream layout).

### Optional env (Zyth SSO)

```bash
export ZYTH_OIDC_ISSUER=https://auth.zyth.app/
export ZYTH_OIDC_CLIENT_ID=K8m9VaNO6p7LKEUdXj7qbsGKWEWdxRQb   # public
export ZYTH_AI_GATEWAY_BASE_URL=https://ai-gateway.zyth.app/v1
export ZYTH_CLI_EXCHANGE_URL=https://ai-gateway.zyth.app/zyth/cli/v1/exchange
```

## License

Apache-2.0 (upstream). Personal/local fork.

## Remote branches (Komondor)

| Branch | Contents |
|--------|----------|
| `main` | Zyth fork features + **DeepSec plugin** (see [`docs/DEEPSEC.md`](docs/DEEPSEC.md)); tag `deepsec-v1.0.0` |
| `upgrade/latest-upstream-with-zyth` | Latest xai-org/grok-build merge + Zyth + **hard-stripped product telemetry** (no unsolicited SpaceXAI phone-home) |

Upstream DeepSec baseline for the port: **2.2.4** @ `97ebd04` — [`plugins/deepsec/UPSTREAM.md`](plugins/deepsec/UPSTREAM.md).
