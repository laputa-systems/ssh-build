#!/bin/sh
# Write and verify the consolidated SHA256SUMS over every packaged asset in <out_dir>.
# Usage: sh scripts/write-sums.sh <out_dir>
set -eu

out_dir=${1:?usage: write-sums.sh <out_dir>}
cd "$out_dir"
assets=
for asset in ssh-*.zip ssh-*.manifest oxish-*.zip oxish-*.manifest; do
    [ -f "$asset" ] && assets="$assets $asset"
done
[ -n "$assets" ] || { echo "write-sums: no assets in $out_dir" >&2; exit 1; }
# shellcheck disable=SC2086
shasum -a 256 $assets | sort -k 2 > SHA256SUMS.tmp
mv SHA256SUMS.tmp SHA256SUMS
shasum -a 256 -c SHA256SUMS
