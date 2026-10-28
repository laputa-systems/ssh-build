#!/bin/sh
# Regenerate the chacha20-poly1305@openssh.com differential vectors from the pinned OpenSSH build.
# Usage: sh scripts/gen-chachapoly-vectors.sh   (needs `make macos` or a linux build tree first)
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
version=$(sed -n 's/^OPENSSH_VERSION=//p' "$root/scripts/fetch-sources.sh")
src=$root/.work/sources/openssh-$version
build=$root/.work/build-macos
out=$root/vendor/oxish/oxish-graviola/tests/openssh-chachapoly.vectors

test -f "$build/libssh.a" || { echo "gen-chachapoly-vectors: build OpenSSH first (make macos)" >&2; exit 1; }
mkdir -p "$(dirname "$out")" "$root/.work/tmp"
cc -O1 -I"$build" -I"$src" -I"$src/openbsd-compat" "$root/tools/chachapoly-vectors.c" \
    "$build/libssh.a" "$build/openbsd-compat/libopenbsd-compat.a" -o "$root/.work/tmp/chachapoly-vectors"
"$root/.work/tmp/chachapoly-vectors" > "$out"
echo "wrote $(wc -l < "$out" | tr -d ' ') vectors to $out"
