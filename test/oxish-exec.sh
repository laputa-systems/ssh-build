#!/bin/sh
# Usage: sh test/oxish-exec.sh   (uses dist/macos/bin/ssh when built, else the system ssh)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -x "$ROOT/dist/macos/bin/ssh" ]; then
    SSH_BIN="$ROOT/dist/macos/bin/ssh"
    SSH_ORIGIN="built no-libcrypto client"
else
    SSH_BIN=$(command -v ssh)
    SSH_ORIGIN="system ssh (client not built)"
fi
echo "exec ssh client: $SSH_BIN ($SSH_ORIGIN)"
"$SSH_BIN" -V 2>&1 || true

command -v git >/dev/null 2>&1 || { echo "git not found in PATH" >&2; exit 1; }
git --version

export OXISH_TEST_SSH="$SSH_BIN"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/.work/target-oxish}"

cargo test \
    --manifest-path "$ROOT/vendor/oxish/Cargo.toml" \
    -p oxish \
    exec_ \
    -- --nocapture

echo "exec ok: git pack commands + rejection green with $SSH_BIN"
