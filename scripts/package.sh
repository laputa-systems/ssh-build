#!/bin/sh
# Package the OpenSSH client for one target as ssh-<version>-<triple>.zip plus
# ssh-<version>-<triple>.manifest.json, then write and verify
# <out_dir>/SHA256SUMS over all assets.
# Usage: TARGET=<triple> sh scripts/package.sh [out_dir]      (default: dist/release)
# Input: dist/ssh/<triple>/bin, which needs the build-record.json its build wrote
# (scripts/build-record.sh); stale, modified or foreign binaries are refused, and nothing in
# <out_dir> changes unless the target passes.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
. "$script_dir/lock.sh"
. "$script_dir/archive.sh"
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
out_dir=${1:-$repo_root/dist/release}
triple=${TARGET:?package: set TARGET to a Rust target triple}

fail() { echo "package: $*" >&2; exit 1; }

for tool in cargo jaq file; do
    command -v "$tool" >/dev/null || fail "$tool is required"
done

case $triple in
    aarch64-apple-darwin) expected=arm64 ;;
    x86_64-unknown-linux-musl) expected=x86-64 ;;
    aarch64-unknown-linux-musl) expected="ARM aarch64" ;;
    *) fail "unsupported target $triple" ;;
esac

version=$(lock_field openssh version)
upstream_sha256=$(lock_field openssh sha256)
test -n "$version" || fail "cannot read the openssh version from sources.lock.json"
test -n "$upstream_sha256" || fail "cannot read the openssh sha256 from sources.lock.json"

mkdir -p "$out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P)
stage=$(mktemp -d "$out_dir/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

bin_dir=$repo_root/dist/ssh/$triple/bin
sh "$script_dir/build-record.sh" verify ssh "$bin_dir" "$triple"
record=$bin_dir/build-record.json
build_commit=$(jaq -r .commit "$record")
build_dirty=$(jaq -r .dirty "$record")
toolchain=$(jaq -r .toolchain "$record")

for b in ssh ssh-keygen ssh-agent ssh-add sftp scp; do
    test -x "$bin_dir/$b" || fail "$bin_dir/$b missing; build $triple first"
    description=$(file -b "$bin_dir/$b")
    case $description in
        *"$expected"*) ;;
        *) fail "$bin_dir/$b is not $expected: $description" ;;
    esac
done
case $triple in
    *-linux-musl)
        for b in ssh ssh-keygen ssh-agent ssh-add sftp scp; do
            case $(file -b "$bin_dir/$b") in
                *static-pie*|*"statically linked"*) ;;
                *) fail "$bin_dir/$b is not static" ;;
            esac
        done
        ;;
    *) sh "$script_dir/qualify-binaries.sh" "$bin_dir" macos ;;
esac

name=ssh-$version-$triple
make_archive "$stage/$name.zip" "$bin_dir" ssh ssh-keygen ssh-agent ssh-add sftp scp

lock_sha256=$(sha256 "$repo_root/sources.lock.json" | awk '{ print $1 }')
jaq -n \
    --arg version "$version" --arg target "$triple" --arg commit "$build_commit" \
    --arg lock_sha256 "$lock_sha256" --argjson dirty "$build_dirty" \
    --arg upstream_sha256 "$upstream_sha256" --arg toolchain "$toolchain" \
    '{schema_version: 1, product: "ssh", version: $version, target: $target,
      source_revision: $commit, sources_lock_sha256: $lock_sha256, build_dirty: $dirty,
      upstream_sha256: $upstream_sha256, toolchain: $toolchain}' > "$stage/$name.manifest.json"

rm -f "$out_dir/ssh-"*"-$triple.zip" "$out_dir/ssh-"*"-$triple.manifest.json"
mv "$stage/$name.zip" "$stage/$name.manifest.json" "$out_dir"/
sh "$script_dir/write-sums.sh" "$out_dir"

echo "Packaged $triple (ssh) in $out_dir"
