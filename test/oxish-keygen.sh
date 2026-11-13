#!/bin/sh
# Qualify oxish-keygen from released-style bytes against the OpenSSH ssh-keygen of the ssh archive.
#
#   SSH_BIN_DIR=dist/ssh/<triple>/bin OXISH_BIN_DIR=dist/oxish/<triple>/bin sh test/oxish-keygen.sh
set -eu

: "${SSH_BIN_DIR:?set SSH_BIN_DIR to the directory with the built ssh-keygen}"
: "${OXISH_BIN_DIR:?set OXISH_BIN_DIR to the directory with oxish-keygen}"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
abs() { (CDPATH= cd -- "$1" && pwd -P); }
ssh_keygen=$(abs "$SSH_BIN_DIR")/ssh-keygen
keygen=$(abs "$OXISH_BIN_DIR")/oxish-keygen
for bin in "$ssh_keygen" "$keygen"; do
    [ -x "$bin" ] || { echo "FAIL: $bin is missing" >&2; exit 1; }
done

work=$root/.work/oxish-keygen
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

ok() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

"$keygen" -f "$work/id" -C "qualify@host" 2>/dev/null >"$work/generated" || fail "generation failed"
[ "$(ls -l "$work/id" | cut -c1-10)" = "-rw-------" ] || fail "private key is not mode 0600"
ok "generated a 0600 key pair"

ours=$("$keygen" -l -f "$work/id")
theirs=$("$ssh_keygen" -l -f "$work/id")
[ "$ours" = "$theirs" ] || fail "fingerprints differ: '$ours' vs '$theirs'"
[ "$ours" = "$(cat "$work/generated")" ] || fail "generation did not print the fingerprint"
[ "$("$keygen" -l -f "$work/id.pub")" = "$ours" ] || fail "the public file has another fingerprint"
ok "OpenSSH agrees on the fingerprint: $ours"

[ "$("$keygen" -y -f "$work/id")" = "$("$ssh_keygen" -y -f "$work/id")" ] || fail "public keys differ"
[ "$("$keygen" -y -f "$work/id")" = "$(cat "$work/id.pub")" ] || fail "-y differs from the .pub file"
ok "OpenSSH derives the same public key"

cp "$work/id" "$work/before"
if "$keygen" -f "$work/id" 2>/dev/null; then fail "an existing key was overwritten"; fi
cmp -s "$work/id" "$work/before" || fail "an existing key was modified"
ok "an existing key is never overwritten"

ln -s "$work/elsewhere" "$work/link"
if "$keygen" -f "$work/link" 2>/dev/null; then fail "wrote through a symbolic link"; fi
[ ! -e "$work/elsewhere" ] || fail "created a file through a symbolic link"
ok "symbolic links are refused"
