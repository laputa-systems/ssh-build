#!/bin/sh
# Package every target as ssh-<triple>.zip plus a build manifest, enforce the
# size budgets, then write and verify <out_dir>/SHA256SUMS over all assets.
# Usage: sh scripts/package.sh [out_dir]      (default: dist/release)
# Inputs: dist/macos/bin, dist/linux-x86_64/bin, dist/linux-aarch64/bin.
# Linux linkage is qualified with readelf inside the Docker build that
# produced those bytes; here they are re-checked with file(1) for arch and
# static-pie so a stale or wrong-arch directory cannot be packaged.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
canonical=$repo_root/scripts/fetch-sources.sh
budgets=$repo_root/release-budgets.json
dockerfile=$repo_root/Dockerfile
out_dir=${1:-$repo_root/dist/release}

for tool in zip shasum jaq file; do
    command -v "$tool" >/dev/null || { echo "package: $tool is required" >&2; exit 1; }
done

upstream_version=$(sed -n 's/^OPENSSH_VERSION=//p' "$canonical")
upstream_sha256=$(sed -n 's/^OPENSSH_SHA256=//p' "$canonical")
test -n "$upstream_version" || { echo "package: cannot read version" >&2; exit 1; }
test -n "$upstream_sha256" || { echo "package: cannot read archive sha" >&2; exit 1; }

build_commit=$(git -C "$repo_root" rev-parse HEAD)
build_dirty=false
if git -C "$repo_root" status --short | grep -q .; then build_dirty=true; fi

linux_toolchain=$(awk -F'[= ]+' '$2 ~ /^(binutils|gcc|musl-dev)$/ { printf "%s %s;", $2, $3 }' "$dockerfile")
test -n "$linux_toolchain" || { echo "package: cannot read Dockerfile toolchain pins" >&2; exit 1; }
linux_toolchain="alpine apk: ${linux_toolchain%;}"
macos_toolchain=$("$(xcrun --sdk macosx --find clang)" --version | sed -n '1p')

mkdir -p "$out_dir"
out_dir=$(CDPATH= cd -- "$out_dir" && pwd -P)
rm -f "$out_dir"/ssh-*.zip "$out_dir"/ssh-*.manifest

package_target() {
    triple=$1
    bin_dir=$repo_root/$2
    expected=$3
    toolchain=$4

    for b in ssh ssh-keygen ssh-agent ssh-add sftp scp; do
        test -x "$bin_dir/$b" || { echo "package: $bin_dir/$b missing; build $triple first" >&2; exit 1; }
        description=$(file -b "$bin_dir/$b")
        case $description in
            *"$expected"*) ;;
            *) echo "package: $bin_dir/$b is not $expected: $description" >&2; exit 1 ;;
        esac
    done
    case $triple in
        *-linux-musl)
            for b in ssh ssh-keygen ssh-agent ssh-add sftp scp; do
                case $(file -b "$bin_dir/$b") in
                    *static-pie*|*"statically linked"*) ;;
                    *) echo "package: $bin_dir/$b is not static" >&2; exit 1 ;;
                esac
            done
            ;;
        *) sh "$script_dir/qualify-binaries.sh" "$bin_dir" macos ;;
    esac

    zip_name=ssh-$triple.zip
    (cd "$bin_dir" && zip -y -X -q "$out_dir/$zip_name" ssh ssh-keygen ssh-agent ssh-add sftp scp)

    zip_bytes=$(wc -c < "$out_dir/$zip_name" | tr -d ' ')
    budget=$(jaq -r --arg t "$triple" '.ssh[$t].max_zip_bytes' "$budgets")
    test -n "$budget" && [ "$budget" != null ] || { echo "package: no budget for $triple" >&2; exit 1; }
    if [ "$zip_bytes" -gt "$budget" ]; then
        echo "package: $zip_name is $zip_bytes bytes, over the $budget byte budget" >&2
        exit 1
    fi
    echo "budget: $zip_name $zip_bytes/$budget bytes"

    cat > "$out_dir/ssh-$triple.manifest" <<EOF
upstream_version=$upstream_version
upstream_sha256=$upstream_sha256
target=$triple
build_commit=$build_commit
build_dirty=$build_dirty
toolchain=$toolchain
EOF
}

package_target aarch64-apple-darwin dist/macos/bin "arm64" "$macos_toolchain"
package_target x86_64-unknown-linux-musl dist/linux-x86_64/bin "x86-64" "$linux_toolchain"
package_target aarch64-unknown-linux-musl dist/linux-aarch64/bin "ARM aarch64" "$linux_toolchain"

sh "$script_dir/write-sums.sh" "$out_dir"

echo "Packaged 3 ZIPs and manifests in $out_dir"
