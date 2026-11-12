#!/bin/sh
# Regenerate the chacha20-poly1305@openssh.com differential vectors from the pinned OpenSSH build.
# Usage: sh scripts/gen-chachapoly-vectors.sh   (needs `make binaries PRODUCT=ssh` on macOS first)
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/lock.sh"
root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
version=$(lock_field openssh version)
src=$root/.work/sources/openssh-$version
build=$root/.work/build-macos
out=$root/vendor/oxish/oxish-graviola/tests/openssh-chachapoly.vectors

test -f "$build/libssh.a" || { echo "gen-chachapoly-vectors: build OpenSSH first (make binaries PRODUCT=ssh)" >&2; exit 1; }
mkdir -p "$(dirname "$out")" "$root/.work/tmp"
cc -O1 -I"$build" -I"$src" -I"$src/openbsd-compat" "$root/tools/chachapoly-vectors.c" \
    "$build/libssh.a" "$build/openbsd-compat/libopenbsd-compat.a" -o "$root/.work/tmp/chachapoly-vectors"
"$root/.work/tmp/chachapoly-vectors" > "$out"
echo "wrote $(wc -l < "$out" | tr -d ' ') vectors to $out"
