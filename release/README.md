# Prebuilt Zyth Linux x86_64

## Install

```sh
./install-linux.sh
zyth --version
```

## Contents

| File | Description |
|------|-------------|
| `zyth-linux-x86_64.xz` | Compressed release binary (`cargo build -p xai-grok-pager-bin --release`) |
| `install-linux.sh` | Installs to `~/.grok/downloads/` and links `zyth` / `grok` on PATH |

## Rebuild

From repo root:

```sh
cargo build -p xai-grok-pager-bin --release
xz -f -k -T0 -c target/release/zyth > release/zyth-linux-x86_64.xz
```

See [docs/LOGINZYTH.md](../docs/LOGINZYTH.md) for `/loginzyth` architecture.
