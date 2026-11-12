#!/bin/sh
# Check the packaged assets for one target and exercise the bytes they contain: SHA256SUMS, each
# manifest, then test/runtime.sh and test/e2e-git.sh on the unpacked archives. The host must run
# the target natively.
# Usage: TARGET=<triple> sh scripts/verify-release.sh [out_dir]      (default: dist/release)
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
. "$script_dir/lock.sh"
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
out_dir=${1:-$repo_root/dist/release}
triple=${TARGET:?verify-release: set TARGET to a Rust target triple}

fail() { echo "verify-release: $*" >&2; exit 1; }

case "$(uname -s):$(uname -m)" in
    Darwin:arm64) host=aarch64-apple-darwin ;;
    Linux:x86_64) host=x86_64-unknown-linux-musl ;;
    Linux:aarch64|Linux:arm64) host=aarch64-unknown-linux-musl ;;
    *) host=unknown ;;
esac
[ "$host" = "$triple" ] || fail "this host runs $host, not $triple"

for tool in tar xz jaq; do
    command -v "$tool" >/dev/null || fail "$tool is required"
done

out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P)
(cd "$out_dir" && sha256 -c SHA256SUMS) >/dev/null || fail "SHA256SUMS does not match the assets in $out_dir"

commit=$(git -C "$repo_root" rev-parse HEAD)
lock_sha256=$(sha256 "$repo_root/sources.lock.json" | awk '{ print $1 }')
unpack=$repo_root/.work/verify/$triple
rm -rf "$unpack"
mkdir -p "$unpack"

for product in ssh oxish; do
    version=$(lock_field "$(if [ "$product" = ssh ]; then echo openssh; else echo oxish; fi)" version)
    name=$product-$version-$triple
    archive=$out_dir/$name.tar.xz
    manifest=$out_dir/$name.manifest.json
    [ -f "$archive" ] || fail "$archive is missing"
    [ -f "$manifest" ] || fail "$manifest is missing"
    jaq -e --arg product "$product" --arg version "$version" --arg target "$triple" \
        --arg commit "$commit" --arg lock_sha256 "$lock_sha256" \
        '.schema_version == 1 and .product == $product and .version == $version and .target == $target
         and .source_revision == $commit and .sources_lock_sha256 == $lock_sha256' "$manifest" >/dev/null \
        || fail "$manifest does not describe $name at $commit"
    if [ "${ALLOW_DIRTY:-0}" != 1 ]; then
        jaq -e '.build_dirty == false' "$manifest" >/dev/null || fail "$manifest was built from a dirty tree"
    fi
    mkdir -p "$unpack/$product"
    tar -xJf "$archive" -C "$unpack/$product"
done

cd "$repo_root"
SSH_BIN_DIR=$unpack/ssh sh test/runtime.sh
SSH_BIN_DIR=$unpack/ssh OXISH_BIN_DIR=$unpack/oxish/bin sh test/e2e-git.sh
