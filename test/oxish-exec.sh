#!/bin/sh
# S5 exec gate: non-PTY `exec` for Git against the vendored OxiSH server.
# Prefers the just-built no-libcrypto client (dist/macos/bin/ssh, owned by
# the S1 lane) and falls back to the system ssh. The handshake itself runs
# inside the vendored OxiSH tree: an in-process server plus the real client
# binary (or real git over it) over TCP loopback with throwaway keys.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -x "$ROOT/dist/macos/bin/ssh" ]; then
    SSH_BIN="$ROOT/dist/macos/bin/ssh"
    SSH_ORIGIN="s1 no-libcrypto client"
else
    SSH_BIN=$(command -v ssh)
    SSH_ORIGIN="system ssh (s1 client not built yet)"
fi
echo "exec ssh client: $SSH_BIN ($SSH_ORIGIN)"
"$SSH_BIN" -V 2>&1 || true

command -v git >/dev/null 2>&1 || { echo "git not found in PATH" >&2; exit 1; }
git --version

export OXISH_TEST_SSH="$SSH_BIN"
# Keep build artifacts out of the committed vendor tree.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/.work/target-oxish}"

# exec_git_* (clone, push, fetch through the product server, asserting file
# bytes + commit SHA + exit 0), exec_rejects_non_git (`rm -rf /` must fail),
# and exec_forced_command (authorized-key command wins).
cargo test \
    --manifest-path "$ROOT/vendor/oxish/Cargo.toml" \
    -p oxish \
    exec_ \
    -- --nocapture

echo "exec ok: git pack commands + rejection green with $SSH_BIN"
