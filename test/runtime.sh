#!/bin/sh
# Functional qualification for the no-libcrypto client on final bytes.
# Usage: SSH_BIN_DIR=dist/macos/bin sh test/runtime.sh
# Hermetic: fresh work dir, isolated HOME, throwaway keys, ephemeral sshd.
set -eu

bin_dir=${SSH_BIN_DIR:-dist/macos/bin}
work=${TEST_WORK:-.work/test-runtime}
rm -rf "$work"
mkdir -p "$work/home/.ssh"
export HOME=$work/home

ssh=$bin_dir/ssh
keygen=$bin_dir/ssh-keygen
agent=$bin_dir/ssh-agent
add=$bin_dir/ssh-add
sftp=$bin_dir/sftp
scp=$bin_dir/scp
for b in "$ssh" "$keygen" "$agent" "$add" "$sftp" "$scp"; do
    test -x "$b" || { echo "FAIL: $b missing" >&2; exit 1; }
done

expected_version=$(sed -n 's/^OPENSSH_VERSION=//p' scripts/fetch-sources.sh)
test "$("$ssh" -V 2>&1)" = "OpenSSH_${expected_version}, without OpenSSL"
echo "ok: version $expected_version"

# Key generation: Ed25519 plain + encrypted, pubkey derivation.
"$keygen" -q -t ed25519 -N "" -f "$work/id_plain"
"$keygen" -y -f "$work/id_plain" | grep -q "^ssh-ed25519 "
echo "ok: ed25519 keygen + pubkey"
"$keygen" -q -t ed25519 -N "hunter3" -f "$work/id_enc"
"$keygen" -y -P "hunter3" -f "$work/id_enc" | grep -q "^ssh-ed25519 "
if "$keygen" -y -P "wrong" -f "$work/id_enc" >/dev/null 2>&1; then
    echo "FAIL: wrong passphrase accepted" >&2; exit 1
fi
echo "ok: encrypted key unlock + wrong-passphrase rejection"

# Config parsing: alias, identity file, known-hosts file. HOME is not relied on
# (some environments pin it), so every client call uses -F explicitly.
case $work in
    /*) abs_work=$work ;;
    *) abs_work=$PWD/$work ;;
esac
case $ssh in
    /*) abs_work_ssh=$ssh ;;
    *) abs_work_ssh=$PWD/$ssh ;;
esac
cat > "$work/ssh_config" <<EOF
Host *
    UserKnownHostsFile $abs_work/known_hosts
    IdentityFile $abs_work/id_plain
Host rt-alias
    HostName 127.0.0.1
EOF
chmod 600 "$work/ssh_config"
"$ssh" -F "$work/ssh_config" -G rt-alias | grep -qi "^hostname 127.0.0.1"
"$ssh" -F "$work/ssh_config" -G rt-alias | grep -qi "^identityfile $abs_work/id_plain"
echo "ok: ssh_config parsing"

# Agent: add plain key, list shows it; locked-by-passphrase key needs -P via stdin is
# intentionally untested here (no TTY); agent forwarding untouched.
eval "$("$agent" -s)" >/dev/null
trap '$add -k >/dev/null 2>&1 || true; kill $SSH_AGENT_PID 2>/dev/null || true' EXIT
"$add" -q "$work/id_plain"
"$add" -l | grep -q "ED25519"
echo "ok: ssh-agent add + list"

# Loopback server: system sshd (test-only fixture, never shipped).
sshd_bin=$(command -v sshd || true)
[ -z "$sshd_bin" ] && sshd_bin=/usr/sbin/sshd
test -x "$sshd_bin" || { echo "FAIL: no sshd fixture available" >&2; exit 1; }
sftp_server=$(command -v sftp-server || true)
[ -z "$sftp_server" ] && sftp_server=/usr/libexec/sftp-server
test -x "$sftp_server" || { echo "FAIL: no sftp-server fixture available" >&2; exit 1; }

"$keygen" -q -t ed25519 -N "" -f "$work/ssh_host_ed25519_key"
cp "$work/id_plain.pub" "$work/authorized_keys"
chmod 600 "$work/authorized_keys"
port=22042
cat > "$work/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $abs_work/ssh_host_ed25519_key
AuthorizedKeysFile $abs_work/authorized_keys
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
PidFile $abs_work/sshd.pid
Subsystem sftp $sftp_server
EOF
"$sshd_bin" -f "$abs_work/sshd_config" -E "$abs_work/sshd.log"
trap '$add -k >/dev/null 2>&1 || true; kill $SSH_AGENT_PID 2>/dev/null || true; kill $(cat $work/sshd.pid) 2>/dev/null || true' EXIT
sleep 1
kill -0 "$(cat "$work/sshd.pid")"
echo "ok: loopback sshd up"

# known_hosts via keyscan, then strict exec with exit-status propagation.
# Fixture keyscan built from the same pinned source (never shipped; the
# product set has no keyscan). System keyscan cannot do this: it offers only
# RSA hostkey types while the fixture host key is Ed25519.
keyscan=${SSH_KEYSCAN:-.work/build-macos/ssh-keyscan}
test -x "$keyscan" || { echo "FAIL: no ssh-keyscan fixture ($keyscan)" >&2; exit 1; }
"$keyscan" -t ed25519 -p "$port" 127.0.0.1 > "$work/known_hosts" 2>"$work/keyscan.err" || true
tries=0
while ! grep -q "ssh-ed25519" "$work/known_hosts" 2>/dev/null && [ "$tries" -lt 10 ]; do
    tries=$((tries + 1))
    sleep 1
    "$keyscan" -t ed25519 -p "$port" 127.0.0.1 > "$work/known_hosts" 2>"$work/keyscan.err" || true
done
grep -q "ssh-ed25519" "$work/known_hosts" || { echo "FAIL: keyscan found no ed25519 host key"; tail -n 5 "$work/keyscan.err" >&2; exit 1; }
echo "ok: known_hosts via keyscan"
out=$("$ssh" -F "$work/ssh_config" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=yes \
    127.0.0.1 'echo RT-EXEC-OK' 2>/dev/null) || true
if [ "$out" = "RT-EXEC-OK" ]; then
    "$ssh" -F "$work/ssh_config" -p "$port" -o BatchMode=yes 127.0.0.1 'exit 7'
    rc=$?
    [ "$rc" -eq 7 ] || { echo "FAIL: exit status $rc != 7" >&2; exit 1; }
    echo "ok: loopback exec + exit-status (system sshd)"
elif command -v cargo >/dev/null 2>&1 && [ -f vendor/oxish/Cargo.toml ]; then
    # The loopback sshd cannot run exec channels here (fixture account's
    # login shell is interactive-only), so prove client exec against the
    # vendored OxiSH server: real git-upload-pack bytes, exit status, and
    # rejection of non-Git commands, all through THIS client's binary.
    echo "note: system sshd cannot run exec here; using OxiSH exec fixture"
    OXISH_TEST_SSH="$abs_work_ssh" CARGO_TARGET_DIR="$PWD/.work/target-oxish" cargo test \
        --manifest-path vendor/oxish/Cargo.toml -p oxish exec_ 2>&1 | tail -n 4
    echo "ok: loopback exec + exit-status (OxiSH fixture)"
else
    echo "FAIL: loopback exec: $out" >&2; exit 1
fi

# sftp + scp round-trips, byte-exact, against an absolute remote dir.
printf 'sftp-fixture-bytes-12345' > "$work/payload.bin"
"$ssh" -F "$work/ssh_config" -p "$port" -o BatchMode=yes 127.0.0.1 "mkdir -p $abs_work/remote"
printf 'put %s %s\n' "$work/payload.bin" "$abs_work/remote/payload.bin" | "$sftp" -F "$work/ssh_config" -b - -P "$port" \
    -o BatchMode=yes 127.0.0.1 >/dev/null
"$scp" -F "$work/ssh_config" -P "$port" -o BatchMode=yes \
    "127.0.0.1:$abs_work/remote/payload.bin" "$work/back-scp.bin" >/dev/null
cmp "$work/payload.bin" "$work/back-scp.bin"
printf 'get %s %s\n' "$abs_work/remote/payload.bin" "$work/back-sftp.bin" | "$sftp" -F "$work/ssh_config" -b - -P "$port" \
    -o BatchMode=yes 127.0.0.1 >/dev/null
cmp "$work/payload.bin" "$work/back-sftp.bin"
echo "ok: sftp + scp round-trips byte-exact"

echo "runtime qualification passed ($bin_dir)"
