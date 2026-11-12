#!/bin/sh
# Fetch and verify pinned sources. sources.lock.json is the single editable pin for the OpenSSH
# version and checksum and the OxiSH revision; Makefile, Dockerfile, and tests derive from it.
# Fails closed.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
. "$script_dir/lock.sh"

command -v jaq >/dev/null 2>&1 || { echo "fetch-sources: jaq not found" >&2; exit 1; }
OPENSSH_VERSION=$(lock_field openssh version)
OPENSSH_SHA256=$(lock_field openssh sha256)
OPENSSH_TARBALL=$(lock_field openssh tarball)
OXISH_REV=$(lock_field oxish rev)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
work_dir=${SOURCES_DIR:-$root_dir/.work/sources}
mkdir -p "$work_dir"

fail() { echo "fetch-sources: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl not found"

archive=$work_dir/$OPENSSH_TARBALL
if [ ! -f "$archive" ]; then
    downloaded=0
    for mirror in $(lock_urls openssh); do
        echo "fetching $mirror"
        if curl -fsSL -o "$archive.tmp" "$mirror"; then
            mv "$archive.tmp" "$archive"
            downloaded=1
            break
        fi
    done
    [ "$downloaded" -eq 1 ] || fail "could not download $OPENSSH_TARBALL from any mirror"
else
    echo "reusing $archive"
fi

actual=$(sha256 "$archive" | awk '{ print $1 }')
[ "$actual" = "$OPENSSH_SHA256" ] || \
    fail "SHA-256 mismatch for $OPENSSH_TARBALL: got $actual want $OPENSSH_SHA256"
echo "verified $OPENSSH_TARBALL $actual"

src_dir=$work_dir/openssh-${OPENSSH_VERSION}
if [ ! -f "$src_dir/configure.ac" ]; then
    rm -rf "$src_dir"
    tar -xzf "$archive" -C "$work_dir" || fail "extract failed"
fi
[ -f "$src_dir/configure.ac" ] || fail "extract produced no configure.ac"

echo "--- foundation evidence (verified from pinned source) ---"
grep -n -- "--without-openssl" "$src_dir/configure.ac" | head -n 3
echo "--- ciphers without libcrypto ($src_dir/cipher.c) ---"
sed -n '/^#else/,/^#endif/p' "$src_dir/cipher.c" | grep -n '{ "' | head -n 8
grep -n 'chacha20-poly1305@openssh.com' "$src_dir/cipher.c" | head -n 3
echo "--- oxish pin ---"
echo "oxish rev $OXISH_REV (verify: git ls-remote https://github.com/djc/oxish HEAD)"
if [ -d "$work_dir/oxish" ]; then
    got_rev=$(git -C "$work_dir/oxish" rev-parse HEAD) || \
        fail "oxish checkout unusable"
    [ "$got_rev" = "$OXISH_REV" ] || \
        fail "oxish rev mismatch: got $got_rev want $OXISH_REV"
    echo "oxish checkout at $got_rev"
    echo "--- oxish graviola ciphers (oxish-graviola/src/lib.rs) ---"
    grep -n "EncryptionAlgorithm::" "$work_dir/oxish/oxish-graviola/src/lib.rs" | head -n 6
    grep -n "encryption:" "$work_dir/oxish/oxish-graviola/src/lib.rs" | head -n 3
    echo "--- oxish exec handling (oxish/src/session/connections.rs) ---"
    grep -n "ignoring channel request" "$work_dir/oxish/oxish/src/session/connections.rs" | head -n 3
else
    echo "(oxish checkout absent; S4 clones and checks out $OXISH_REV fail-closed)"
fi
echo "sources ready in $work_dir"
