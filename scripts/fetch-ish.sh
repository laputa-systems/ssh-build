#!/bin/sh
# Download the pinned ish release asset for this host and print the directory holding its
# executable `ish`. Read-only; fails closed on any checksum mismatch.
# Usage: sh scripts/fetch-ish.sh [triple]   (Linux musl triples only)
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
lock=$root_dir/ish.lock.json

fail() { echo "fetch-ish: $*" >&2; exit 1; }

command -v gh >/dev/null || fail "gh not found"
command -v jaq >/dev/null || fail "jaq not found"
command -v unzip >/dev/null || fail "unzip not found"

triple=${1:-}
if [ -z "$triple" ]; then
    case "$(uname -m)" in
        x86_64|amd64) triple=x86_64-unknown-linux-musl ;;
        aarch64|arm64) triple=aarch64-unknown-linux-musl ;;
        *) fail "no ish asset for $(uname -m)" ;;
    esac
fi

repo=$(jaq -r '.repo' "$lock")
tag=$(jaq -r '.tag' "$lock")
asset=$(jaq -r --arg t "$triple" '.assets[$t].name // empty' "$lock")
member=$(jaq -r --arg t "$triple" '.assets[$t].member // empty' "$lock")
want=$(jaq -r --arg t "$triple" '.assets[$t].sha256 // empty' "$lock")
[ -n "$asset" ] && [ -n "$member" ] && [ -n "$want" ] || fail "no pinned asset for $triple"

dest=$root_dir/.work/ish/$tag/$triple
if [ ! -x "$dest/ish" ]; then
    stage=$root_dir/.work/ish/$tag/stage-$triple
    rm -rf "$stage" "$dest"
    mkdir -p "$stage"
    gh release download "$tag" -R "$repo" -p "$asset" -p SHA256SUMS -D "$stage" >/dev/null
    got=$(sha256 "$stage/$asset" | awk '{ print $1 }')
    [ "$got" = "$want" ] || fail "$asset sha256 $got does not match the pin $want"
    listed=$(awk -v a="$asset" '$2 == a { print $1 }' "$stage/SHA256SUMS")
    [ "$listed" = "$want" ] || fail "release SHA256SUMS lists $listed for $asset, pin is $want"
    members=$(unzip -Z1 "$stage/$asset")
    [ "$members" = "$member" ] || fail "$asset holds '$members', the pin expects only $member"
    mkdir -p "$dest"
    unzip -p "$stage/$asset" "$member" > "$dest/ish"
    chmod 755 "$dest/ish"
    rm -rf "$stage"
fi
[ -x "$dest/ish" ] || fail "$dest/ish is missing"
echo "$dest"
