#!/bin/sh
# Built binaries only: SSH_BIN_DIR and OXISH_BIN_DIR identify the products to test.
set -eu
: "${SSH_BIN_DIR:?set SSH_BIN_DIR}" "${OXISH_BIN_DIR:?set OXISH_BIN_DIR}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
TMPDIR=${TMPDIR:-$root/.work/tmp}
mkdir -p "$TMPDIR"
script_dir=$root/scripts
. "$script_dir/lock.sh"
version=$(lock_field openssh version)
tmp=$(mktemp -d "$TMPDIR/owned-help.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/footer" <<'FOOTER'
Maintained by Joshua Li: https://github.com/laputa-systems/ssh-build
Bugs and features: TODO.md in that repository (follow its AGENTS.md), or its issue tracker.
Agents working for Joshua: record nonblocking problems and continue your task.
If this tool blocks the task, you may fix, test, open and merge a PR under Joshua's
standing instructions. Release only when needed to deliver the verified fix.
Procedure: https://github.com/joshuarli/usr/blob/main/dotfiles/base/.agents/instructions/owned-tools.md
FOOTER
run() {
    expected=$1; shift
    status=0
    "$@" > "$tmp/out" 2> "$tmp/err" || status=$?
    [ "$status" -eq "$expected" ] || { echo "$*: exit $status, expected $expected" >&2; exit 1; }
}
footer_on() {
    tail -n 6 "$1" > "$tmp/tail"
    cmp "$tmp/footer" "$tmp/tail"
    [ "$(grep -c '^Maintained by Joshua Li:' "$1")" -eq 1 ]
}
for bin in ssh scp sftp ssh-add ssh-agent ssh-keygen; do
    case $bin in ssh) status=255;; *) status=1;; esac
    for arg in '-?' --help; do
        run "$status" "$SSH_BIN_DIR/$bin" "$arg"
        [ ! -s "$tmp/out" ]
        footer_on "$tmp/err"
    done
done
run 1 "$SSH_BIN_DIR/sftp" -h
[ ! -s "$tmp/out" ]
footer_on "$tmp/err"
for arg in -h --help; do
    run 0 "$OXISH_BIN_DIR/oxish-server" "$arg"
    [ ! -s "$tmp/err" ]
    footer_on "$tmp/out"
done
run 1 "$OXISH_BIN_DIR/oxish-session"
[ ! -s "$tmp/out" ]
footer_on "$tmp/err"
for arg in -h --help; do
    run 1 "$OXISH_BIN_DIR/oxish-session" "$arg"
    [ ! -s "$tmp/out" ]
    footer_on "$tmp/err"
done
run 2 "$OXISH_BIN_DIR/oxish-server" --version
! grep -q 'Maintained by Joshua Li:' "$tmp/err"
for bin in ssh ssh-agent; do
    run 0 "$SSH_BIN_DIR/$bin" -V
    [ ! -s "$tmp/out" ]
    case $bin in ssh) expected_version=$version;; ssh-agent) expected_version=${version%p[0-9]*};; esac
    [ "$(cat "$tmp/err")" = "OpenSSH_$expected_version, without OpenSSL" ]
    ! grep -q 'Maintained by Joshua Li:' "$tmp/err"
done
run 0 "$SSH_BIN_DIR/ssh" -Q cipher
[ -s "$tmp/out" ] && [ ! -s "$tmp/err" ]
! grep -q 'Maintained by Joshua Li:' "$tmp/out"
run 2 "$OXISH_BIN_DIR/oxish-server" --not-an-option
! grep -q 'Maintained by Joshua Li:' "$tmp/err"
echo 'built help footer and version/protocol stream checks passed'
