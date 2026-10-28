#!/bin/sh
# Reproduce vendor/oxish from the pinned upstream revision plus patches/oxish.
#   sh scripts/vendor-oxish.sh verify   rebuild in .work/vendor-check, diff against vendor/oxish
#   sh scripts/vendor-oxish.sh export   regenerate patches/oxish from vendor/oxish (maintainers)
# The revision comes from OXISH_REV in scripts/fetch-sources.sh. Every step fails closed.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
work_dir=$root_dir/.work
upstream_url=https://github.com/djc/oxish
patch_dir=$root_dir/patches/oxish
vendor_dir=$root_dir/vendor/oxish
groups="root oxish-proto oxish-graviola oxish-aws-lc oxish fuzz"

fail() { echo "vendor-oxish: $*" >&2; exit 1; }

rev=$(sed -n 's/^OXISH_REV=//p' "$script_dir/fetch-sources.sh")
[ "${#rev}" -eq 40 ] || fail "cannot read OXISH_REV"
lock_rev=$(jaq -r '.oxish.rev' "$root_dir/sources.lock.json")
[ "$lock_rev" = "$rev" ] || fail "sources.lock.json oxish rev $lock_rev != $rev"

checkout() {
    upstream=$work_dir/sources/oxish
    if [ ! -d "$upstream/.git" ]; then
        mkdir -p "$work_dir/sources"
        git clone --quiet --no-checkout "$upstream_url" "$upstream"
    fi
    git -C "$upstream" cat-file -e "$rev^{commit}" 2>/dev/null || git -C "$upstream" fetch --quiet origin "$rev"
    git -C "$upstream" checkout --quiet --detach "$rev"
    [ "$(git -C "$upstream" rev-parse HEAD)" = "$rev" ] || fail "upstream checkout is not $rev"
    [ -z "$(git -C "$upstream" status --porcelain)" ] || fail "upstream checkout is dirty"
}

materialize_base() {
    dest=$1
    rm -rf "$dest"
    mkdir -p "$dest"
    git -C "$work_dir/sources/oxish" archive "$rev" \
        -- Cargo.toml Cargo.lock LICENSE-APACHE LICENSE-MIT README.md deny.toml \
           openssh-vulnerabilities.md fuzz oxish oxish-aws-lc oxish-graviola oxish-proto \
        | tar -x -C "$dest"
}

pathspec() {
    case $1 in
        root) echo ':(glob)*' ;;
        *) echo "$1" ;;
    esac
}

apply_patches() {
    dest=$1
    for patch in "$patch_dir"/*.patch; do
        [ -f "$patch" ] || fail "no patches in $patch_dir"
        (cd "$dest" && patch -p1 -s -N < "$patch") || fail "patch $patch does not apply to $rev"
    done
}

case ${1:-} in
    verify)
        checkout
        check=$work_dir/vendor-check
        materialize_base "$check"
        apply_patches "$check"
        if ! diff -r -x target -x .work "$check" "$vendor_dir" > "$work_dir/vendor-check.diff"; then
            head -n 20 "$work_dir/vendor-check.diff" >&2
            fail "vendor/oxish differs from upstream $rev plus patches/oxish; run export if the change is intended"
        fi
        echo "vendor/oxish == upstream $rev + $(ls "$patch_dir" | wc -l | tr -d ' ') patches"
        ;;
    export)
        checkout
        base=$work_dir/vendor-export
        materialize_base "$base"
        git -C "$base" init --quiet
        git -C "$base" add -A
        git -C "$base" -c user.name=vendor -c user.email=vendor@invalid commit --quiet -m base
        rsync -a --delete --exclude .git --exclude target --exclude .work "$vendor_dir/" "$base/"
        git -C "$base" add -A
        mkdir -p "$patch_dir"
        rm -f "$patch_dir"/*.patch
        n=1
        for group in $groups; do
            out=$patch_dir/$(printf '%04d' "$n")-$group.patch
            git -C "$base" diff --cached --binary --full-index --no-color -- "$(pathspec "$group")" > "$out"
            [ -s "$out" ] && n=$((n + 1)) || rm -f "$out"
        done
        echo "wrote $(ls "$patch_dir" | wc -l | tr -d ' ') patches to $patch_dir"
        ;;
    *) fail "usage: vendor-oxish.sh verify|export" ;;
esac
