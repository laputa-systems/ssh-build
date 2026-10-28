#!/bin/sh
# Install the pinned jaq release into <dir> and print nothing else. Fails closed on a checksum mismatch.
# Usage: sh scripts/install-jaq.sh <dir>
set -eu

dir=${1:?usage: install-jaq.sh <dir>}
version=v3.1.2

case "$(uname -s):$(uname -m)" in
    Darwin:arm64) asset=jaq-aarch64-apple-darwin sha=977685a0d4138585055c25631ec6970ab666ce37aefc7f6786033548292d18ef ;;
    Linux:x86_64) asset=jaq-x86_64-unknown-linux-musl sha=a469f5e6980fe2c7e73dce0a1db5176eb4a717b933b77fa32fa1da7847c12232 ;;
    Linux:aarch64) asset=jaq-aarch64-unknown-linux-gnu sha=1aa1b9c0a3b73f016f6a8d407fa21a89174d01a8e4b9df449eaad49603426734 ;;
    *) echo "install-jaq: no pinned jaq for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

. "$(dirname "$0")/sha256.sh"
mkdir -p "$dir"
curl -fsSL -o "$dir/jaq.tmp" "https://github.com/01mf02/jaq/releases/download/$version/$asset"
got=$(sha256 "$dir/jaq.tmp" | awk '{ print $1 }')
[ "$got" = "$sha" ] || { rm -f "$dir/jaq.tmp"; echo "install-jaq: $asset sha256 $got does not match the pin" >&2; exit 1; }
chmod +x "$dir/jaq.tmp"
mv "$dir/jaq.tmp" "$dir/jaq"
