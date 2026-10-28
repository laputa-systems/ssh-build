#!/bin/sh
# Bind built executables to the source and inputs that produced them.
#   sh scripts/build-record.sh write  <ssh|oxish> <bin_dir> <triple>   after a successful, qualified build
#   sh scripts/build-record.sh verify <ssh|oxish> <bin_dir> <triple>   before packaging
# The record is <bin_dir>/build-record.json. Packaging trusts only this record, never the checkout it
# runs in, so binaries built from another revision cannot be labelled with the current one.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
. "$script_dir/sha256.sh"
cd "$repo_root"

fail() { echo "build-record: $*" >&2; exit 1; }

mode=${1:-}
product=${2:-}
bin_dir=${3:-}
triple=${4:-}
[ -n "$triple" ] || fail "usage: build-record.sh write|verify ssh|oxish <bin_dir> <triple>"

case $product in
    ssh)
        bins="ssh ssh-keygen ssh-agent ssh-add sftp scp"
        inputs="scripts/fetch-sources.sh sources.lock.json Dockerfile Makefile scripts/build-macos.sh scripts/qualify-binaries.sh"
        ;;
    oxish)
        bins="oxish-server oxish-session"
        inputs="vendor/oxish vendor/graviola patches rust-toolchain.toml sources.lock.json Dockerfile.oxish Makefile scripts/build-oxish-macos.sh scripts/qualify-binaries.sh"
        ;;
    *) fail "unknown product $product" ;;
esac

inputs_sha256() {
    {
        # shellcheck disable=SC2086
        git ls-files -s -- $inputs
        # shellcheck disable=SC2086
        git diff HEAD -- $inputs
    } | sha256 | awk '{ print $1 }'
}

inputs_dirty() {
    # shellcheck disable=SC2086
    [ -n "$(git status --porcelain -- $inputs)" ] && echo true || echo false
}

toolchain() {
    case $product:$triple in
        ssh:*-apple-darwin) "$(xcrun --sdk macosx --find clang)" --version | sed -n '1p' ;;
        ssh:*) printf 'alpine apk: %s' "$(awk -F'[= ]+' '$2 ~ /^(binutils|gcc|musl-dev)$/ { printf "%s %s;", $2, $3 }' Dockerfile | sed 's/;$//')" ;;
        oxish:*-apple-darwin) rustc -vV | tr '\n' ';' ;;
        oxish:*) [ -f "$bin_dir/rustc-version.txt" ] || fail "$bin_dir/rustc-version.txt missing"; tr '\n' ';' < "$bin_dir/rustc-version.txt" ;;
    esac
}

executables() {
    for b in $bins; do
        [ -x "$bin_dir/$b" ] || fail "$bin_dir/$b missing; build $triple first"
        printf '%s %s\n' "$b" "$(sha256 "$bin_dir/$b" | awk '{ print $1 }')"
    done | jaq -R -s 'split("\n") | map(select(length > 0) | split(" ") | {key: .[0], value: .[1]}) | from_entries'
}

case $mode in
    write)
        case $triple in
            *-apple-darwin)
                QUALIFY_BINS="$bins" sh "$script_dir/qualify-binaries.sh" "$bin_dir" macos >/dev/null || fail "$bin_dir failed qualification"
                qualified=host
                ;;
            *) qualified=docker-build ;;
        esac
        jaq -n \
            --arg product "$product" --arg target "$triple" --arg commit "$(git rev-parse HEAD)" \
            --argjson dirty "$(inputs_dirty)" --arg inputs "$(inputs_sha256)" --arg toolchain "$(toolchain)" \
            --arg qualified "$qualified" --argjson executables "$(executables)" \
            '{product: $product, target: $target, commit: $commit, dirty: $dirty, inputs_sha256: $inputs,
              toolchain: $toolchain, qualified_by: $qualified, executables: $executables}' > "$bin_dir/build-record.json"
        echo "build-record: wrote $bin_dir/build-record.json"
        ;;
    verify)
        record=$bin_dir/build-record.json
        [ -f "$record" ] || fail "$record missing; the binaries were not built by this repository's build scripts"
        field() { jaq -r "$1" "$record"; }
        [ "$(field .product)" = "$product" ] && [ "$(field .target)" = "$triple" ] || fail "$record is for another product or target"
        [ "$(field .inputs_sha256)" = "$(inputs_sha256)" ] \
            || fail "$bin_dir was built from different sources than the current tree (commit $(field .commit)); rebuild before packaging"
        if [ "$(field .dirty)" = true ] && [ "${ALLOW_DIRTY:-0}" != 1 ]; then
            fail "$bin_dir was built from an uncommitted tree; commit and rebuild, or set ALLOW_DIRTY=1 for a local package"
        fi
        for b in $bins; do
            [ -x "$bin_dir/$b" ] || fail "$bin_dir/$b missing"
            want=$(field ".executables[\"$b\"]")
            got=$(sha256 "$bin_dir/$b" | awk '{ print $1 }')
            [ "$want" = "$got" ] || fail "$bin_dir/$b does not match its build record"
        done
        ;;
    *) fail "usage: build-record.sh write|verify ssh|oxish <bin_dir> <triple>" ;;
esac
