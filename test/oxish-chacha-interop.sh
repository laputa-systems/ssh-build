#!/bin/sh
# S4 interop gate: real handshake between the vendored OxiSH server and an
# OpenSSH client over loopback with only chacha20-poly1305@openssh.com
# negotiated. Prefers the just-built no-libcrypto client (dist/macos/bin/ssh,
# owned by the S1 lane) and falls back to the system ssh.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -x "$ROOT/dist/macos/bin/ssh" ]; then
    SSH_BIN="$ROOT/dist/macos/bin/ssh"
    SSH_ORIGIN="s1 no-libcrypto client"
else
    SSH_BIN=$(command -v ssh)
    SSH_ORIGIN="system ssh (s1 client not built yet)"
fi
echo "interop ssh client: $SSH_BIN ($SSH_ORIGIN)"
"$SSH_BIN" -V 2>&1 || true

export OXISH_TEST_SSH="$SSH_BIN"
# Keep build artifacts out of the committed vendor tree.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/.work/target-oxish}"

# The handshake itself runs inside the vendored OxiSH tree: an in-process
# server plus the real client binary above over TCP loopback, restricted to
# the chacha cipher (`-c`) with negotiation + output assertions.
cargo test \
    --manifest-path "$ROOT/vendor/oxish/Cargo.toml" \
    -p oxish \
    handshake_chacha_graviola \
    -- --nocapture

echo "interop ok: chacha20-poly1305@openssh.com negotiated with $SSH_BIN"
