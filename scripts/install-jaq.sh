#!/bin/sh
# Install the pinned owned jaq release (laputa-systems/jaq) into <dir> and print nothing else. Fails closed on a checksum mismatch.
# Usage: sh scripts/install-jaq.sh <dir>
set -eu

dir=${1:?usage: install-jaq.sh <dir>}
tag=release-545e3f7ba20beed0f77031dcc9aa74eb0ef0ba14

case "$(uname -s):$(uname -m)" in
    Darwin:arm64) triple=aarch64-apple-darwin sha=714b7f4bc1d032041971a3ff31e493767d6e0ab36ae49deeffe95bff64619728 ;;
    Linux:x86_64) triple=x86_64-unknown-linux-musl sha=3a24a3dc32dd19cb4e72ef70fcd9f1253b2804ff92222ca91491e32653a5faa2 ;;
    Linux:aarch64) triple=aarch64-unknown-linux-musl sha=b17a8d41058d15fad21eee822a8952dc40bf6f465f6ebf246f3ae67bb7d461a0 ;;
    *) echo "install-jaq: no pinned jaq for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

. "$(dirname "$0")/sha256.sh"
mkdir -p "$dir"
archive="$dir/jaq-$triple.tar.xz"
curl -fsSL -o "$archive" "https://github.com/laputa-systems/jaq/releases/download/$tag/jaq-$triple.tar.xz"
got=$(sha256 "$archive" | awk '{ print $1 }')
[ "$got" = "$sha" ] || { rm -f "$archive"; echo "install-jaq: jaq-$triple.tar.xz sha256 $got does not match the pin" >&2; exit 1; }
xz -dc "$archive" | (cd "$dir" && tar -xf - "jaq-$triple")
rm -f "$archive"
chmod +x "$dir/jaq-$triple"
mv "$dir/jaq-$triple" "$dir/jaq"
