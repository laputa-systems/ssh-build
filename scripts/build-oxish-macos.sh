#!/bin/sh
# Build the Graviola-only OxiSH server for macOS arm64 into dist/oxish-macos/bin.
# Pinned nightly from rust-toolchain.toml, locked dependencies, no -march=native.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$root_dir"

test "$(uname -s)" = Darwin || { echo "build-oxish-macos: needs macOS" >&2; exit 1; }
test "$(uname -m)" = arm64 || { echo "build-oxish-macos: needs arm64" >&2; exit 1; }

sh scripts/check-crypto-graph.sh
sh scripts/vendor-oxish.sh verify
sh scripts/vendor-graviola.sh verify

export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-14.0}
export CARGO_TARGET_DIR=$root_dir/.work/target-oxish-release
cargo build --locked --release --manifest-path vendor/oxish/Cargo.toml -p oxish --bins

dest=$root_dir/dist/oxish-macos/bin
rm -rf "$dest"
mkdir -p "$dest"
for bin in oxish-server oxish-session; do
    cp "$CARGO_TARGET_DIR/release/$bin" "$dest/$bin"
    codesign --force -s - "$dest/$bin"
done
echo "oxish server ready in $dest"
