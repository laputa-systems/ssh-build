#!/bin/sh
# Package the OxiSH server, client and key generator for one target as oxish-<version>-<triple>.tar.xz plus
# oxish-<version>-<triple>.manifest.json, enforce the size budget, then refresh and verify the
# consolidated SHA256SUMS in <out_dir>.
# Usage: TARGET=<triple> sh scripts/package-oxish.sh [out_dir]      (default: dist/release)
# Input: dist/oxish/<triple>/bin, which needs the build-record.json its build wrote
# (scripts/build-record.sh); stale, modified or foreign binaries are refused, and nothing in
# <out_dir> changes unless the target passes.
# The archive holds bin/oxish (the client, once it is built; see scripts/oxish-bins.sh),
# bin/oxish-server, bin/oxish-session, bin/oxish-keygen, the upstream licenses, and a
# provenance.json naming the OxiSH revision, Graviola version, patch identity, toolchain, build
# commit, target, and the SHA-256 of each executable. No Git binary is included.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
. "$script_dir/lock.sh"
. "$script_dir/archive.sh"
. "$script_dir/oxish-bins.sh"
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
budgets=$repo_root/release-budgets.json
out_dir=${1:-$repo_root/dist/release}
triple=${TARGET:?package-oxish: set TARGET to a Rust target triple}

fail() { echo "package-oxish: $*" >&2; exit 1; }

for tool in tar xz jaq file; do
    command -v "$tool" >/dev/null || fail "$tool is required"
done

case $triple in
    aarch64-apple-darwin) expected=arm64 ;;
    x86_64-unknown-linux-musl) expected=x86-64 ;;
    aarch64-unknown-linux-musl) expected="ARM aarch64" ;;
    *) fail "unsupported target $triple" ;;
esac

sh "$script_dir/vendor-oxish.sh" verify >/dev/null
sh "$script_dir/vendor-graviola.sh" verify >/dev/null
sh "$script_dir/check-crypto-graph.sh" >/dev/null

version=$(lock_field oxish version)
oxish_rev=$(lock_field oxish rev)
graviola_version=$(lock_field graviola version)
graviola_sha256=$(lock_field graviola sha256)
crate_version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo_root/vendor/oxish/oxish/Cargo.toml" | sed -n '1p')
[ -n "$version" ] && [ "$version" = "$crate_version" ] \
    || fail "sources.lock.json oxish version '$version' does not match vendor/oxish/oxish/Cargo.toml '$crate_version'"
patch_sha256=$(cat "$repo_root"/patches/oxish/*.patch "$repo_root"/patches/graviola/*.patch | sha256 | awk '{ print $1 }')

mkdir -p "$out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P)
stage=$(mktemp -d "$out_dir/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

stage_root=$repo_root/.work/package-oxish
rm -rf "$stage_root"
mkdir -p "$stage_root"

bin_dir=$repo_root/dist/oxish/$triple/bin
sh "$script_dir/build-record.sh" verify oxish "$bin_dir" "$triple"
record=$bin_dir/build-record.json
build_commit=$(jaq -r .commit "$record")
build_dirty=$(jaq -r .dirty "$record")
toolchain=$(jaq -r .toolchain "$record")

bins=$(oxish_bins "$bin_dir")
for required in oxish-server oxish-keygen; do
    test -x "$bin_dir/$required" || fail "$bin_dir/$required missing; build $triple first"
done
for b in $bins; do
    test -x "$bin_dir/$b" || fail "$bin_dir/$b missing; build $triple first"
    case $(file -b "$bin_dir/$b") in
        *"$expected"*) ;;
        *) fail "$bin_dir/$b is not $expected: $(file -b "$bin_dir/$b")" ;;
    esac
done
case $triple in
    *-linux-musl)
        for b in $bins; do
            case $(file -b "$bin_dir/$b") in
                *static-pie*) ;;
                *) fail "$bin_dir/$b is not static-pie" ;;
            esac
        done
        ;;
    *) QUALIFY_BINS="$bins" sh "$script_dir/qualify-binaries.sh" "$bin_dir" macos >/dev/null || fail "$bin_dir failed qualification" ;;
esac

pkg=$stage_root/$triple
mkdir -p "$pkg/bin"
for b in $bins; do
    cp "$bin_dir/$b" "$pkg/bin/"
done
cp "$repo_root/vendor/oxish/LICENSE-APACHE" "$repo_root/vendor/oxish/LICENSE-MIT" "$pkg/"
cat > "$pkg/THIRD-PARTY.md" <<EOT
# Third-party code in this archive

- OxiSH ($oxish_rev, https://github.com/djc/oxish): Apache-2.0 OR MIT, see LICENSE-APACHE and
  LICENSE-MIT. Local patches: https://github.com/laputa-systems/ssh-build/tree/$build_commit/patches
- Graviola $graviola_version (https://github.com/ctz/graviola): Apache-2.0 OR ISC OR MIT-0,
  patched to add the OpenSSH chacha20-poly1305 packet construction.
- The OxiSH client and oxish-keygen (client/ in https://github.com/laputa-systems/ssh-build):
  Apache-2.0 OR MIT.
- Rust standard library and the crates in vendor/oxish/Cargo.lock and client/Cargo.lock under
  their own licenses (MIT or Apache-2.0).
EOT

executables=$(
    for b in $bins; do
        printf 'bin/%s %s\n' "$b" "$(sha256 "$pkg/bin/$b" | awk '{ print $1 }')"
    done | jaq -R -s 'split("\n") | map(select(length > 0) | split(" ") | {key: .[0], value: .[1]}) | from_entries'
)
jaq -n \
    --arg target "$triple" --arg oxish_rev "$oxish_rev" --arg graviola "$graviola_version" \
    --arg graviola_sha256 "$graviola_sha256" --arg patch_sha256 "$patch_sha256" \
    --arg toolchain "$toolchain" --arg commit "$build_commit" --argjson dirty "$build_dirty" \
    --argjson executables "$executables" \
    '{product: "oxish", status: "experimental", target: $target,
      oxish: {repo: "https://github.com/djc/oxish", rev: $oxish_rev},
      graviola: {version: $graviola, crate_sha256: $graviola_sha256},
      patches_sha256: $patch_sha256, toolchain: $toolchain,
      build_commit: $commit, build_dirty: $dirty,
      cpu_floor: {x86_64: "Broadwell-class: AES-NI PCLMULQDQ BMI1 ADX AVX2", aarch64: "NEON with AES PMULL SHA2"},
      executables: $executables}' > "$pkg/provenance.json"

name=oxish-$version-$triple
archived=$(for b in $bins; do printf 'bin/%s ' "$b"; done)
# shellcheck disable=SC2086
make_archive "$stage/$name.tar.xz" "$pkg" $archived LICENSE-APACHE LICENSE-MIT THIRD-PARTY.md provenance.json

archive_bytes=$(wc -c < "$stage/$name.tar.xz" | tr -d ' ')
budget=$(jaq -r --arg t "$triple" '.targets[$t].oxish.max_archive_bytes // empty' "$budgets")
[ -n "$budget" ] || fail "no budget for $triple"
[ "$archive_bytes" -le "$budget" ] || fail "$name.tar.xz is $archive_bytes bytes, over the $budget byte budget"
echo "budget: $name.tar.xz $archive_bytes/$budget bytes"

lock_sha256=$(sha256 "$repo_root/sources.lock.json" | awk '{ print $1 }')
jaq -n \
    --arg version "$version" --arg target "$triple" --arg commit "$build_commit" \
    --arg lock_sha256 "$lock_sha256" --argjson dirty "$build_dirty" \
    --arg oxish_rev "$oxish_rev" --arg graviola "$graviola_version" \
    --arg graviola_sha256 "$graviola_sha256" --arg patch_sha256 "$patch_sha256" \
    --arg toolchain "$toolchain" --argjson executables "$(printf '%s\n' $bins | jaq -R -s 'split("\n") | map(select(length > 0))')" \
    '{schema_version: 1, product: "oxish", version: $version, target: $target, executables: $executables,
      source_revision: $commit, sources_lock_sha256: $lock_sha256, build_dirty: $dirty,
      upstream_oxish_rev: $oxish_rev, graviola_version: $graviola,
      graviola_crate_sha256: $graviola_sha256, patches_sha256: $patch_sha256,
      toolchain: $toolchain}' > "$stage/$name.manifest.json"

rm -f "$out_dir/oxish-"*"-$triple.tar.xz" "$out_dir/oxish-"*"-$triple.manifest.json"
mv "$stage/$name.tar.xz" "$stage/$name.manifest.json" "$out_dir"/
sh "$script_dir/write-sums.sh" "$out_dir"
echo "Packaged $triple (oxish) in $out_dir"
