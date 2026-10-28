#!/bin/sh
# Reproduce vendor/graviola from the pinned crates.io release plus patches/graviola.
#   sh scripts/vendor-graviola.sh verify   rebuild in .work/graviola-check, diff against vendor/graviola
#   sh scripts/vendor-graviola.sh export   regenerate patches/graviola from vendor/graviola (maintainers)
# The pin is graviola.version and graviola.checksum (SHA-256 of the .crate file) in sources.lock.json.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
work_dir=$root_dir/.work
patch_dir=$root_dir/patches/graviola
vendor_dir=$root_dir/vendor/graviola

fail() { echo "vendor-graviola: $*" >&2; exit 1; }

version=$(jaq -r '.graviola.version' "$root_dir/sources.lock.json")
checksum=$(jaq -r '.graviola.checksum' "$root_dir/sources.lock.json")
[ "${#checksum}" -eq 64 ] || fail "no checksum pinned for graviola $version"

crate=$work_dir/sources/graviola-$version.crate
fetch() {
    mkdir -p "$work_dir/sources"
    if [ ! -f "$crate" ]; then
        curl -fsSL -o "$crate.tmp" "https://static.crates.io/crates/graviola/graviola-$version.crate"
        mv "$crate.tmp" "$crate"
    fi
    got=$(sha256 "$crate" | awk '{ print $1 }')
    [ "$got" = "$checksum" ] || fail "graviola-$version.crate sha256 $got does not match the pin $checksum"
}

materialize_base() {
    dest=$1
    rm -rf "$dest"
    mkdir -p "$dest"
    tar -xzf "$crate" -C "$dest" --strip-components=1
    for entry in "$dest"/* "$dest"/.[!.]*; do
        case ${entry##*/} in Cargo.toml|README.md|src) ;; *) rm -rf "$entry" ;; esac
    done
}

case ${1:-} in
    verify)
        fetch
        check=$work_dir/graviola-check
        materialize_base "$check"
        for patch in "$patch_dir"/*.patch; do
            [ -f "$patch" ] || fail "no patches in $patch_dir"
            (cd "$check" && patch -p1 -s -N -E < "$patch") || fail "patch $patch does not apply to graviola $version"
        done
        find "$check" -depth -type d -empty -exec rmdir {} \;
        diff -r "$check" "$vendor_dir" > "$work_dir/graviola-check.diff" || {
            head -n 20 "$work_dir/graviola-check.diff" >&2
            fail "vendor/graviola differs from graviola $version plus patches/graviola"
        }
        echo "vendor/graviola == graviola $version (sha256 verified) + $(ls "$patch_dir"/*.patch | wc -l | tr -d ' ') patches"
        ;;
    export)
        fetch
        base=$work_dir/graviola-export
        materialize_base "$base"
        git -C "$base" init --quiet
        git -C "$base" add -A
        git -C "$base" -c user.name=vendor -c user.email=vendor@invalid commit --quiet -m base
        rsync -a --delete --exclude .git "$vendor_dir/" "$base/"
        git -C "$base" add -A
        mkdir -p "$patch_dir"
        rm -f "$patch_dir"/*.patch
        out=$patch_dir/0001-ssh-chacha20-poly1305.patch
        git -C "$base" diff --cached --binary --full-index --no-color > "$out"
        [ -s "$out" ] || fail "vendor/graviola has no changes to export"
        echo "wrote $out"
        ;;
    *) fail "usage: vendor-graviola.sh verify|export" ;;
esac
