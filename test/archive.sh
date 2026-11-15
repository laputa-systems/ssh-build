#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$root/scripts/archive.sh"
stage=$(mktemp -d "${TMPDIR:-/tmp}/archive-test.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/input/bin"
printf 'executable\n' > "$stage/input/bin/tool"
printf 'license\n' > "$stage/input/LICENSE"
chmod 755 "$stage/input/bin/tool"
chmod 644 "$stage/input/LICENSE"
make_archive "$stage/one.tar.xz" "$stage/input" bin/tool LICENSE
touch "$stage/input/LICENSE" "$stage/input/bin/tool"
make_archive "$stage/two.tar.xz" "$stage/input" LICENSE bin/tool
cmp "$stage/one.tar.xz" "$stage/two.tar.xz"
tar -tJvf "$stage/one.tar.xz"
python3 - "$stage/one.tar.xz" <<'PY'
import sys
import tarfile
with tarfile.open(sys.argv[1], 'r:xz') as archive:
    members = archive.getmembers()
    assert [m.name for m in members] == ['LICENSE', 'bin/tool']
    assert all(m.uid == 0 and m.gid == 0 and m.mtime == 0 for m in members)
    assert [m.mode for m in members] == [0o644, 0o755]
PY
