#!/bin/sh
# Download the pinned git-build prerelease for this host and print the directory holding
# its git, git-upload-pack and git-receive-pack. Read-only; fails closed on any checksum
# mismatch. Usage: sh scripts/fetch-git-build.sh [triple]
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
lock=$root_dir/git-build.lock.json

fail() { echo "fetch-git-build: $*" >&2; exit 1; }

command -v gh >/dev/null || fail "gh not found"
command -v jaq >/dev/null || fail "jaq not found"
command -v shasum >/dev/null || fail "shasum not found"

triple=${1:-}
if [ -z "$triple" ]; then
    case "$(uname -s):$(uname -m)" in
        Darwin:arm64) triple=aarch64-apple-darwin ;;
        Linux:x86_64) triple=x86_64-unknown-linux-musl ;;
        Linux:aarch64) triple=aarch64-unknown-linux-musl ;;
        *) fail "no git-build asset for $(uname -s)/$(uname -m)" ;;
    esac
fi

repo=$(jaq -r '.repo' "$lock")
tag=$(jaq -r '.tag' "$lock")
want=$(jaq -r --arg t "$triple" '.assets[$t] // empty' "$lock")
[ -n "$want" ] || fail "no pinned asset for $triple"

dest=$root_dir/.work/git-build/$tag/$triple
asset=git-$triple.zip
if [ ! -x "$dest/git" ]; then
    stage=$root_dir/.work/git-build/$tag/stage-$triple
    rm -rf "$stage" "$dest"
    mkdir -p "$stage"
    gh release download "$tag" -R "$repo" -p "$asset" -p SHA256SUMS -D "$stage" >/dev/null
    got=$(shasum -a 256 "$stage/$asset" | awk '{ print $1 }')
    [ "$got" = "$want" ] || fail "$asset sha256 $got does not match the pin $want"
    listed=$(awk -v a="$asset" '$2 == a { print $1 }' "$stage/SHA256SUMS")
    [ "$listed" = "$want" ] || fail "release SHA256SUMS lists $listed for $asset, pin is $want"
    mkdir -p "$dest"
    unzip -q "$stage/$asset" -d "$dest"
    rm -rf "$stage"
fi
for program in git git-upload-pack git-receive-pack; do
    [ -x "$dest/$program" ] || fail "$dest/$program is missing"
done
echo "$dest"
