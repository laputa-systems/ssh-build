#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/sha256.sh"
. "$script_dir/lock.sh"
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
work_dir=$root_dir/.work
vendor_dir=$root_dir/vendor/graviola

fail() { echo "vendor-graviola: $*" >&2; exit 1; }

rev=$(lock_field graviola rev)
checksum=$(lock_field graviola sha256)
[ "${#rev}" -eq 40 ] || fail "invalid graviola revision"
[ "${#checksum}" -eq 64 ] || fail "no checksum pinned for graviola $rev"
archive=$work_dir/sources/graviola-$rev.tar.gz

fetch() {
    mkdir -p "$work_dir/sources"
    if [ ! -f "$archive" ]; then
        curl -fsSL -o "$archive.tmp" "$(lock_field graviola url)"
        mv "$archive.tmp" "$archive"
    fi
    got=$(sha256 "$archive" | awk '{ print $1 }')
    [ "$got" = "$checksum" ] || fail "graviola $rev sha256 $got does not match the pin $checksum"
}

materialize() {
    dest=$1
    rm -rf "$dest"
    mkdir -p "$dest"
    tar -xzf "$archive" -C "$dest" --strip-components=2 \
        "graviola-$rev/graviola/Cargo.toml" "graviola-$rev/graviola/src"
    tar -xOzf "$archive" "graviola-$rev/README.md" > "$dest/README.md"
    awk '
        /^\[dev-dependencies\]$/ || /^\[target\..*\.dev-dependencies\]$/ { skip = 1; next }
        /^\[/ { skip = 0 }
        !skip { print }
    ' "$dest/Cargo.toml" > "$dest/Cargo.toml.tmp"
    mv "$dest/Cargo.toml.tmp" "$dest/Cargo.toml"
}

case ${1:-} in
    verify)
        fetch
        check=$work_dir/graviola-check
        materialize "$check"
        diff -r "$check" "$vendor_dir" > "$work_dir/graviola-check.diff" || {
            head -n 20 "$work_dir/graviola-check.diff" >&2
            fail "vendor/graviola differs from laputa-systems/graviola@$rev"
        }
        echo "vendor/graviola == laputa-systems/graviola@$rev (sha256 verified)"
        ;;
    export)
        fetch
        materialize "$work_dir/graviola-export"
        rm -rf "$vendor_dir"
        cp -R "$work_dir/graviola-export" "$vendor_dir"
        echo "exported laputa-systems/graviola@$rev to vendor/graviola"
        ;;
    *) fail "usage: vendor-graviola.sh verify|export" ;;
esac
