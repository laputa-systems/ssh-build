#!/bin/sh
# Build the Graviola-only OxiSH server and client tools for macOS arm64 into dist/oxish/aarch64-apple-darwin/bin.
# Pinned nightly from rust-toolchain.toml, locked dependencies, no -march=native.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cd "$root_dir"
. "$script_dir/oxish-bins.sh"

test "$(uname -s)" = Darwin || { echo "build-oxish-macos: needs macOS" >&2; exit 1; }
test "$(uname -m)" = arm64 || { echo "build-oxish-macos: needs arm64" >&2; exit 1; }

sh scripts/check-crypto-graph.sh
sh scripts/vendor-oxish.sh verify
sh scripts/vendor-graviola.sh verify

export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-14.0}
export CARGO_TARGET_DIR=$root_dir/.work/target-oxish-release
cargo build --locked --release --manifest-path vendor/oxish/Cargo.toml -p oxish --bins
export CARGO_TARGET_DIR=$root_dir/.work/target-oxish-client-release
cargo build --locked --release --manifest-path client/Cargo.toml --bins

dest=$root_dir/dist/oxish/aarch64-apple-darwin/bin
rm -rf "$dest"
mkdir -p "$dest"
server_target=$root_dir/.work/target-oxish-release/release
client_target=$root_dir/.work/target-oxish-client-release/release
cp "$server_target/oxish-server" "$server_target/oxish-session" "$client_target/oxish-keygen" \
    "$client_target/oxish" "$client_target/oxish-sftp" "$client_target/oxish-scp" "$dest/"
bins=$(oxish_bins "$dest")
for bin in $bins; do
    codesign --force -s - "$dest/$bin"
done
sh scripts/build-record.sh write oxish "$dest" aarch64-apple-darwin
echo "oxish archive executables ready in $dest"
