#!/bin/sh
# Usage: sh test/oxish-chacha-interop.sh   (uses dist/macos/bin/ssh when built, else the system ssh)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -x "$ROOT/dist/macos/bin/ssh" ]; then
    SSH_BIN="$ROOT/dist/macos/bin/ssh"
    SSH_ORIGIN="built no-libcrypto client"
else
    SSH_BIN=$(command -v ssh)
    SSH_ORIGIN="system ssh (client not built)"
fi
echo "interop ssh client: $SSH_BIN ($SSH_ORIGIN)"
"$SSH_BIN" -V 2>&1 || true

export OXISH_TEST_SSH="$SSH_BIN"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/.work/target-oxish}"

cargo test \
    --manifest-path "$ROOT/vendor/oxish/Cargo.toml" \
    -p oxish \
    handshake_chacha_graviola \
    -- --nocapture

echo "interop ok: chacha20-poly1305@openssh.com negotiated with $SSH_BIN"
