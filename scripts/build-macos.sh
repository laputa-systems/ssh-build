#!/bin/sh
# Configure + build the no-libcrypto OpenSSH client for macOS arm64.
# Out-of-tree build in .work/build-macos; installs to dist/macos/bin.
set -eu

OPENSSH_VERSION=$(sed -n 's/^OPENSSH_VERSION=//p' scripts/fetch-sources.sh)
test -n "$OPENSSH_VERSION"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)

sh "$script_dir/fetch-sources.sh" >/dev/null
src_dir=$root_dir/.work/sources/openssh-${OPENSSH_VERSION}
build_dir=$root_dir/.work/build-macos
dest_dir=$root_dir/dist/macos/bin
mkdir -p "$build_dir" "$dest_dir"

if [ ! -f "$build_dir/config.status" ]; then
    (cd "$build_dir" && "$src_dir/configure" --without-openssl \
        --with-mantype=doc --disable-strip)
fi
make -C "$build_dir" -j"$(sysctl -n hw.ncpu)" ssh ssh-keygen ssh-agent ssh-add sftp scp ssh-keyscan

for b in ssh ssh-keygen ssh-agent ssh-add sftp scp; do
    test -x "$build_dir/$b"
    cp -f "$build_dir/$b" "$dest_dir/$b"
done
strip_bin=$(xcrun --sdk macosx --find strip)
"$strip_bin" "$dest_dir"/ssh "$dest_dir"/ssh-keygen \
    "$dest_dir"/ssh-agent "$dest_dir"/ssh-add "$dest_dir"/sftp "$dest_dir"/scp
codesign -s - "$dest_dir"/ssh "$dest_dir"/ssh-keygen "$dest_dir"/ssh-agent \
    "$dest_dir"/ssh-add "$dest_dir"/sftp "$dest_dir"/scp

test "$("$dest_dir/ssh" -V 2>&1)" = "OpenSSH_${OPENSSH_VERSION}, without OpenSSL"
echo "macos client ready in $dest_dir"
