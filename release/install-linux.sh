#!/usr/bin/env bash
# Install Zyth CLI on Linux x86_64
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
XZ="$ROOT/zyth-linux-x86_64.xz"
DEST_DIR="${HOME}/.grok/downloads"
BIN_DIR="${HOME}/.grok/bin"
mkdir -p "$DEST_DIR" "$BIN_DIR" "${HOME}/.local/bin"
xz -dkc "$XZ" > "$DEST_DIR/zyth-linux-x86_64"
chmod 755 "$DEST_DIR/zyth-linux-x86_64"
ln -sfn ../downloads/zyth-linux-x86_64 "$BIN_DIR/zyth"
ln -sfn ../downloads/zyth-linux-x86_64 "$BIN_DIR/grok"
ln -sfn ../downloads/zyth-linux-x86_64 "$BIN_DIR/agent"
ln -sfn "$BIN_DIR/zyth" "${HOME}/.local/bin/zyth"
# default theme
if [ -f "${HOME}/.grok/config.toml" ]; then
  if grep -q '^theme' "${HOME}/.grok/config.toml"; then
    sed -i 's/^theme = .*/theme = "zyth"/' "${HOME}/.grok/config.toml" || true
  fi
fi
echo "Installed zyth -> $DEST_DIR/zyth-linux-x86_64"
echo "Run: zyth   (ensure ~/.grok/bin or ~/.local/bin is on PATH)"
"$BIN_DIR/zyth" --version || true
