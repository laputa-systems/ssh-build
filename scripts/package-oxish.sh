#!/bin/sh
# Package the OxiSH Git server for every target as oxish-<triple>.zip plus a manifest, enforce
# the size budgets, then refresh and verify the consolidated SHA256SUMS in <out_dir>.
# Usage: sh scripts/package-oxish.sh [out_dir]      (default: dist/release)
# Inputs: dist/oxish-macos/bin, dist/oxish-linux-x86_64/bin, dist/oxish-linux-aarch64/bin.
# Each input directory needs the build-record.json its build wrote (scripts/build-record.sh);
# stale, modified or foreign binaries are refused, and nothing in <out_dir> changes unless every
# target passes.
# The archive holds bin/oxish-server, bin/oxish-session, the upstream licenses, and a
# provenance.json naming the OxiSH revision, Graviola version, patch identity, toolchain, build
# commit, target, and the SHA-256 of each executable. No Git binary is included.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
budgets=$repo_root/release-budgets.json
out_dir=${1:-$repo_root/dist/release}

for tool in zip jaq file; do
    command -v "$tool" >/dev/null || { echo "package-oxish: $tool is required" >&2; exit 1; }
done
fail() { echo "package-oxish: $*" >&2; exit 1; }

sh "$script_dir/vendor-oxish.sh" verify >/dev/null
sh "$script_dir/vendor-graviola.sh" verify >/dev/null
sh "$script_dir/check-crypto-graph.sh" >/dev/null

oxish_rev=$(sed -n 's/^OXISH_REV=//p' "$script_dir/fetch-sources.sh")
graviola_version=$(jaq -r '.graviola.version' "$repo_root/sources.lock.json")
graviola_sha256=$(jaq -r '.graviola.checksum' "$repo_root/sources.lock.json")
patch_sha256=$(cat "$repo_root"/patches/oxish/*.patch "$repo_root"/patches/graviola/*.patch | sha256 | awk '{ print $1 }')

mkdir -p "$out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P)
stage=$(mktemp -d "$out_dir/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

stage_root=$repo_root/.work/package-oxish
rm -rf "$stage_root"
mkdir -p "$stage_root"

package_target() {
    triple=$1
    bin_dir=$repo_root/$2
    expected=$3

    sh "$script_dir/build-record.sh" verify oxish "$bin_dir" "$triple"
    record=$bin_dir/build-record.json
    build_commit=$(jaq -r .commit "$record")
    build_dirty=$(jaq -r .dirty "$record")
    toolchain=$(jaq -r .toolchain "$record")

    for b in oxish-server oxish-session; do
        test -x "$bin_dir/$b" || fail "$bin_dir/$b missing; build $triple first"
        case $(file -b "$bin_dir/$b") in
            *"$expected"*) ;;
            *) fail "$bin_dir/$b is not $expected: $(file -b "$bin_dir/$b")" ;;
        esac
    done
    case $triple in
        *-linux-musl)
            for b in oxish-server oxish-session; do
                case $(file -b "$bin_dir/$b") in
                    *static-pie*) ;;
                    *) fail "$bin_dir/$b is not static-pie" ;;
                esac
            done
            ;;
        *) QUALIFY_BINS="oxish-server oxish-session" sh "$script_dir/qualify-binaries.sh" "$bin_dir" macos >/dev/null || fail "$bin_dir failed qualification" ;;
    esac

    pkg=$stage_root/$triple
    mkdir -p "$pkg/bin"
    cp "$bin_dir/oxish-server" "$bin_dir/oxish-session" "$pkg/bin/"
    cp "$repo_root/vendor/oxish/LICENSE-APACHE" "$repo_root/vendor/oxish/LICENSE-MIT" "$pkg/"
    cat > "$pkg/THIRD-PARTY.md" <<EOF
# Third-party code in this archive

- OxiSH ($oxish_rev, https://github.com/djc/oxish): Apache-2.0 OR MIT, see LICENSE-APACHE and
  LICENSE-MIT. Local patches: https://github.com/laputa-systems/ssh-build/tree/$build_commit/patches
- Graviola $graviola_version (https://github.com/ctz/graviola): Apache-2.0 OR ISC OR MIT-0,
  patched to add the OpenSSH chacha20-poly1305 packet construction.
- Rust standard library and the crates in vendor/oxish/Cargo.lock under their own licenses
  (MIT or Apache-2.0).
EOF

    server_sha256=$(sha256 "$pkg/bin/oxish-server" | awk '{ print $1 }')
    session_sha256=$(sha256 "$pkg/bin/oxish-session" | awk '{ print $1 }')
    jaq -n \
        --arg target "$triple" --arg oxish_rev "$oxish_rev" --arg graviola "$graviola_version" \
        --arg graviola_sha256 "$graviola_sha256" --arg patch_sha256 "$patch_sha256" \
        --arg toolchain "$toolchain" --arg commit "$build_commit" --argjson dirty "$build_dirty" \
        --arg server "$server_sha256" --arg session "$session_sha256" \
        '{product: "oxish", status: "experimental", target: $target,
          oxish: {repo: "https://github.com/djc/oxish", rev: $oxish_rev},
          graviola: {version: $graviola, crate_sha256: $graviola_sha256},
          patches_sha256: $patch_sha256, toolchain: $toolchain,
          build_commit: $commit, build_dirty: $dirty,
          cpu_floor: {x86_64: "Broadwell-class: AES-NI PCLMULQDQ BMI1 ADX AVX2", aarch64: "NEON with AES PMULL SHA2"},
          executables: {"bin/oxish-server": $server, "bin/oxish-session": $session}}' > "$pkg/provenance.json"

    zip_name=oxish-$triple.zip
    (cd "$pkg" && zip -y -X -q -r "$stage/$zip_name" bin LICENSE-APACHE LICENSE-MIT THIRD-PARTY.md provenance.json)

    zip_bytes=$(wc -c < "$stage/$zip_name" | tr -d ' ')
    budget=$(jaq -r --arg t "$triple" '.oxish[$t].max_zip_bytes // empty' "$budgets")
    [ -n "$budget" ] || fail "no budget for $triple"
    [ "$zip_bytes" -le "$budget" ] || fail "$zip_name is $zip_bytes bytes, over the $budget byte budget"
    echo "budget: $zip_name $zip_bytes/$budget bytes"

    cat > "$stage/oxish-$triple.manifest" <<EOF
upstream_oxish_rev=$oxish_rev
graviola_version=$graviola_version
graviola_crate_sha256=$graviola_sha256
patches_sha256=$patch_sha256
target=$triple
build_commit=$build_commit
build_dirty=$build_dirty
toolchain=$toolchain
EOF
}

package_target aarch64-apple-darwin dist/oxish-macos/bin "arm64"
package_target x86_64-unknown-linux-musl dist/oxish-linux-x86_64/bin "x86-64"
package_target aarch64-unknown-linux-musl dist/oxish-linux-aarch64/bin "ARM aarch64"

rm -f "$out_dir"/oxish-*.zip "$out_dir"/oxish-*.manifest
mv "$stage"/oxish-* "$out_dir"/
sh "$script_dir/write-sums.sh" "$out_dir"
echo "Packaged 3 server ZIPs and manifests in $out_dir"
