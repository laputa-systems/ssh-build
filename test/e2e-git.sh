#!/bin/sh
# End-to-end qualification of the OxiSH Git server on released-style bytes.
#
#   SSH_BIN_DIR=dist/macos/bin OXISH_BIN_DIR=dist/oxish-macos/bin sh test/e2e-git.sh
#
# Uses only: the OpenSSH client from SSH_BIN_DIR, the server from OXISH_BIN_DIR, and the git-build
# binaries from GIT_BUILD_DIR (default: the pinned prerelease, downloaded and checksum-verified).
# Never falls back to the system ssh or git. Throwaway keys, temporary repository root, loopback,
# ephemeral port, pinned host key (StrictHostKeyChecking=yes throughout).
set -eu

: "${SSH_BIN_DIR:?set SSH_BIN_DIR to the directory with the built ssh and ssh-keygen}"
: "${OXISH_BIN_DIR:?set OXISH_BIN_DIR to the directory with oxish-server and oxish-session}"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
abs() { (CDPATH= cd -- "$1" && pwd -P); }
ssh_dir=$(abs "$SSH_BIN_DIR")
oxish_dir=$(abs "$OXISH_BIN_DIR")
if [ -n "${GIT_BUILD_DIR:-}" ]; then
    git_dir=$(abs "$GIT_BUILD_DIR")
else
    git_dir=$(sh "$root/scripts/fetch-git-build.sh")
fi
for bin in "$ssh_dir/ssh" "$ssh_dir/ssh-keygen" "$oxish_dir/oxish-server" "$oxish_dir/oxish-session" \
    "$git_dir/git" "$git_dir/git-upload-pack" "$git_dir/git-receive-pack"; do
    [ -x "$bin" ] || { echo "FAIL: $bin is missing" >&2; exit 1; }
done
command -v nc >/dev/null || { echo "FAIL: nc is required for the malformed-packet case" >&2; exit 1; }

work=$root/.work/e2e
server_pid=
cleanup() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    jobs -p | xargs kill 2>/dev/null || true
}
trap cleanup EXIT
rm -rf "$work"
mkdir -p "$work/home" "$work/repos" "$work/keys" "$work/clients"
chmod 755 "$work" "$work/repos"
chmod 700 "$work/keys"

ok() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
must_fail() {
    description=$1
    shift
    if "$@" >"$work/last.out" 2>"$work/last.err"; then
        fail "$description was accepted"
    fi
    ok "$description rejected"
}

version=$("$git_dir/git" --version)
echo "git: $version ($git_dir)"
echo "ssh: $("$ssh_dir/ssh" -V 2>&1)"

# Keys: a pushing client, a fetch-only client, an unauthorized client, a decoy host key.
for name in rw ro stranger; do
    "$ssh_dir/ssh-keygen" -q -t ed25519 -N "" -C "e2e-$name" -f "$work/keys/$name"
done
for name in host decoy; do
    "$oxish_dir/oxish-server" --generate-host-key "$work/keys/$name" 2> "$work/genkey.err" \
        || { cat "$work/genkey.err" >&2; fail "oxish-server could not generate a host key"; }
done
if "$oxish_dir/oxish-server" --generate-host-key "$work/keys/host" 2>/dev/null; then
    fail "an existing host key was overwritten"
fi
ok "host key generation never overwrites"
{
    printf 'git-access="write" %s\n' "$(cat "$work/keys/rw.pub")"
    printf 'git-access="read" %s\n' "$(cat "$work/keys/ro.pub")"
} > "$work/keys/authorized_keys"
chmod 600 "$work/keys/authorized_keys"

RUST_LOG=info "$oxish_dir/oxish-server" --bind 127.0.0.1 --port 0 \
    --host-key-file "$work/keys/host" --repo-root "$work/repos" --git-dir "$git_dir" \
    --authorized-keys "$work/keys/authorized_keys" --user git > "$work/server.log" 2>&1 &
server_pid=$!
port=
tries=0
while [ -z "$port" ] && [ "$tries" -lt 50 ]; do
    sleep 0.2
    tries=$((tries + 1))
    port=$(sed 's/\x1b\[[0-9;]*m//g' "$work/server.log" | sed -n 's/.*addr=127\.0\.0\.1:\([0-9]*\).*/\1/p' | head -n 1)
done
[ -n "$port" ] || { cat "$work/server.log" >&2; fail "server did not start"; }
kill -0 "$server_pid" || fail "server exited"
ok "server listening on 127.0.0.1:$port"

host_pub=$("$ssh_dir/ssh-keygen" -y -f "$work/keys/host")
decoy_pub=$("$ssh_dir/ssh-keygen" -y -f "$work/keys/decoy")
printf '[127.0.0.1]:%s %s\n' "$port" "$host_pub" > "$work/known_hosts"
printf '[127.0.0.1]:%s %s\n' "$port" "$decoy_pub" > "$work/known_hosts.decoy"

ssh_opts() {
    key=$1
    hosts=${2:-$work/known_hosts}
    printf '%s -F /dev/null -i %s -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10' \
        "$ssh_dir/ssh" "$work/keys/$key" "$hosts"
}
# shellcheck disable=SC2086
rssh() { key=$1; shift; $(ssh_opts "$key") -p "$port" git@127.0.0.1 "$@"; }
# The product git as the client, with this repository's ssh and a closed environment.
g() {
    key=$1
    shift
    env -i HOME="$work/home" PATH="$git_dir:/usr/bin:/bin" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$(ssh_opts "$key")" ${TRACE:+GIT_TRACE_PACKET="$TRACE"} \
        "$git_dir/git" "$@"
}
# Local repository setup with the product git and a PATH that resolves its helpers first.
lg() {
    env -i HOME="$work/home" PATH="$git_dir:/usr/bin:/bin" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        "$git_dir/git" "$@"
}
url() { echo "ssh://git@127.0.0.1:$port/$1"; }

# --- Seed: product git creates a bare repository, a push over SSH fills it.
lg init -q --bare -b main "$work/repos/a.git"
lg init -q --bare -b main "$work/repos/big.git"
seed=$work/seed
mkdir "$seed"
g rw -C "$seed" init -q -b main
printf 'hello oxish\n' > "$seed/hello.txt"
head -c 24000000 /dev/urandom > "$seed/random.bin"
g rw -C "$seed" add .
g rw -C "$seed" -c user.name=e2e -c user.email=e2e@example.invalid commit -q -m seed
g rw -C "$seed" tag v1
g rw -C "$seed" push -q "$(url a.git)" main v1
g rw -C "$seed" push -q "$(url big.git)" main
seed_sha=$(g rw -C "$seed" rev-parse HEAD)
ok "push of branches, tags and a 24 MB pack through the server"

# --- Negotiation: Ed25519 auth, hybrid post-quantum KEX, explicit cipher, via the client's own log.
$(ssh_opts rw) -v -p "$port" -o KexAlgorithms=mlkem768x25519-sha256 -o Ciphers=chacha20-poly1305@openssh.com \
    git@127.0.0.1 "git-upload-pack 'a.git'" < /dev/null > /dev/null 2> "$work/negotiation.log" || true
grep -q 'kex: algorithm: mlkem768x25519-sha256' "$work/negotiation.log" || fail "hybrid post-quantum key exchange was not negotiated"
grep -q 'cipher: chacha20-poly1305@openssh.com' "$work/negotiation.log" || fail "chacha20-poly1305@openssh.com was not negotiated"
grep -q 'Authenticated to 127.0.0.1.*publickey\|Authentication succeeded (publickey)' "$work/negotiation.log" || fail "public-key authentication did not succeed"
grep -q 'host key.*ssh-ed25519' "$work/negotiation.log" || fail "host key was not ssh-ed25519"
ok "ed25519 auth, mlkem768x25519-sha256 kex, chacha20-poly1305@openssh.com cipher"

# --- Protocol v2 is really negotiated (packet trace), and v0 still works.
rm -f "$work/trace-v2.txt" "$work/trace-v0.txt"
TRACE=$work/trace-v2.txt g ro -c protocol.version=2 clone -q "$(url a.git)" "$work/clients/v2"
grep -q '< version 2' "$work/trace-v2.txt" || fail "protocol v2 was requested but the server did not answer with version 2"
TRACE=$work/trace-v0.txt g ro -c protocol.version=0 clone -q "$(url a.git)" "$work/clients/v0"
if grep -q '< version 2' "$work/trace-v0.txt"; then fail "protocol v0 client was answered with version 2"; fi
ok "protocol v2 negotiated (packet trace); protocol v0 still interoperates"
[ "$(g ro -C "$work/clients/v2" rev-parse HEAD)" = "$seed_sha" ] || fail "clone head differs"
cmp "$seed/hello.txt" "$work/clients/v2/hello.txt"
cmp "$seed/random.bin" "$work/clients/v2/random.bin" || fail "large file differs"
ok "clone is byte-exact including the 24 MB file"
g ro -C "$work/clients/v2" fsck --strict
g ro ls-remote "$(url a.git)" > "$work/lsremote.txt"
grep -q 'refs/tags/v1' "$work/lsremote.txt" && grep -q 'refs/heads/main' "$work/lsremote.txt"
ok "ls-remote lists branches and tags; fsck is clean"

# --- Fetch and push round trip with a new commit and a new branch.
printf 'second\n' > "$seed/second.txt"
g rw -C "$seed" add second.txt
g rw -C "$seed" -c user.name=e2e -c user.email=e2e@example.invalid commit -q -m second
g rw -C "$seed" checkout -q -b feature
g rw -C "$seed" push -q "$(url a.git)" main feature
g ro -C "$work/clients/v2" fetch -q origin
[ "$(g ro -C "$work/clients/v2" rev-parse origin/main)" = "$(g rw -C "$seed" rev-parse main)" ] || fail "fetch did not bring the new commit"
g ro -C "$work/clients/v2" rev-parse origin/feature >/dev/null
ok "fetch sees pushed commits and branches"

# --- Failed commands: meaningful stderr and nonzero exit status.
must_fail "push with a fetch-only key" g ro -C "$work/clients/v2" push "$(url a.git)" main:ro-attempt
grep -q 'access denied' "$work/last.err" || fail "denied push did not say why"
ok "denied push explains itself on stderr"
git_status=0
rssh ro "git-upload-pack 'missing.git'" < /dev/null > "$work/last.out" 2> "$work/last.err" || git_status=$?
[ "$git_status" -eq 1 ] || fail "missing repository exit status was $git_status, wanted 1"
grep -q 'not found' "$work/last.err" || fail "missing repository did not say so"
ok "missing repository: stderr diagnostic and exit status 1"
lg clone -q "$work/repos/a.git" "$work/clients/diverge"
(cd "$work/clients/diverge" && lg -c user.name=e2e -c user.email=e2e@example.invalid commit -q --allow-empty -m diverge)
g rw -C "$work/clients/diverge" remote set-url origin "$(url a.git)"
g rw -C "$seed" checkout -q main
g rw -C "$seed" -c user.name=e2e -c user.email=e2e@example.invalid commit -q --allow-empty -m "moves main on"
g rw -C "$seed" push -q "$(url a.git)" main
must_fail "non-fast-forward push" g rw -C "$work/clients/diverge" push origin HEAD:main
grep -q 'rejected\|non-fast-forward\|fetch first' "$work/last.err" || fail "rejected push gave no diagnostic"
ok "rejected push relays git's diagnostic and exit status"

# --- Negative cases.
ls "$work/repos" > "$work/repos.before"
mkdir -p "$work/outside"
lg init -q --bare "$work/outside/escape.git"
ln -s "$work/outside/escape.git" "$work/repos/link.git"
for command in \
    "rm -rf $work/repos" \
    "sh -c 'touch $work/pwned'" \
    "/bin/sh" \
    "$git_dir/git-upload-pack 'a.git'" \
    "git-upload-pack 'a.git'; touch $work/pwned" \
    "git-upload-pack \$(touch $work/pwned)" \
    "git-upload-pack '../outside/escape.git'" \
    "git-upload-pack '$work/outside/escape.git'" \
    "git-upload-pack '/etc/passwd'" \
    "git-upload-pack 'link.git'" \
    "git-upload-pack --help" \
    "git-upload-pack -- 'a.git'" \
    "git-upload-archive 'a.git'" \
    "git-shell -c id"; do
    code=0
    rssh rw "$command" < /dev/null > "$work/last.out" 2> "$work/last.err" || code=$?
    [ "$code" -ne 0 ] || fail "command was accepted: $command"
    [ ! -e "$work/pwned" ] || fail "command executed: $command"
done
[ "$(ls "$work/repos" | tr '\n' ' ')" = "$(tr '\n' ' ' < "$work/repos.before") link.git " ] || [ -d "$work/repos/a.git" ] || fail "repositories were disturbed"
ok "executable paths, injection, traversal, absolute paths, symlink escape, options and unsupported services rejected"
must_fail "unauthorized key" rssh stranger "git-upload-pack 'a.git'"
grep -qi 'permission denied' "$work/last.err" || fail "stranger was not told permission denied"
code=0
$(ssh_opts rw "$work/known_hosts.decoy") -p "$port" git@127.0.0.1 "git-upload-pack 'a.git'" < /dev/null > /dev/null 2> "$work/last.err" || code=$?
[ "$code" -ne 0 ] && grep -q 'Host key verification failed\|REMOTE HOST IDENTIFICATION HAS CHANGED' "$work/last.err" || fail "client accepted an unexpected host key"
ok "unknown host key refused by the client"
for request in "-tt" "-N -L 0:127.0.0.1:1" "-W 127.0.0.1:22" "-A" "-X"; do
    code=0
    # shellcheck disable=SC2086
    rssh rw $request "git-upload-pack 'a.git'" < /dev/null > "$work/last.out" 2> "$work/last.err" || code=$?
    case $request in
        "-tt"|"-A"|"-X") grep -qi 'request failed\|not supported\|refused' "$work/last.err" || [ "$code" -ne 0 ] || fail "ssh $request was silently honored" ;;
        *) [ "$code" -ne 0 ] || fail "ssh $request succeeded" ;;
    esac
done
code=0
rssh rw < /dev/null > "$work/last.out" 2> "$work/last.err" || code=$?
[ "$code" -ne 0 ] || fail "an interactive shell was granted"
ok "pty, shell, port forwarding, stdio forwarding, agent and X11 requests refused"
printf 'SSH-2.0-evil\r\n\000\000\000\020garbagegarbage' | nc -w 2 127.0.0.1 "$port" > /dev/null 2>&1 || true
head -c 4000 /dev/urandom | nc -w 2 127.0.0.1 "$port" > /dev/null 2>&1 || true
kill -0 "$server_pid" || fail "the server died on malformed input"
g ro ls-remote "$(url a.git)" > /dev/null
ok "malformed packets dropped; server still serves"

# --- Disconnect during an active transfer leaves no child process or temporary state behind.
pack_objects_before=$(pgrep -f 'pack-objects' | wc -l | tr -d ' ')
mkfifo "$work/sink"
sleep 30 < "$work/sink" &
sink_pid=$!
{
    printf '%s' "$(printf '%04x' $((4 + 5 + 40 + 1)))want $seed_sha"
    printf '\n0000%s' "0009done"
    printf '\n'
} > "$work/request.bin"
$(ssh_opts ro) -p "$port" git@127.0.0.1 "git-upload-pack 'big.git'" < "$work/request.bin" > "$work/sink" 2>/dev/null &
client_pid=$!
tries=0
while ! pgrep -f "git-upload-pack --strict $work/repos/big.git" > /dev/null && [ "$tries" -lt 50 ]; do
    sleep 0.2
    tries=$((tries + 1))
done
pgrep -f "git-upload-pack --strict $work/repos/big.git" > /dev/null || fail "transfer never started"
sleep 1
kill -9 "$client_pid" 2>/dev/null || true
kill "$sink_pid" 2>/dev/null || true
tries=0
while { pgrep -f "git-upload-pack --strict $work/repos/big.git" > /dev/null || [ "$(pgrep -f 'pack-objects' | wc -l | tr -d ' ')" -gt "$pack_objects_before" ]; } && [ "$tries" -lt 100 ]; do
    sleep 0.2
    tries=$((tries + 1))
done
if pgrep -f "git-upload-pack --strict $work/repos/big.git" > /dev/null; then fail "git-upload-pack outlived its connection"; fi
[ "$(pgrep -f 'pack-objects' | wc -l | tr -d ' ')" -le "$pack_objects_before" ] || fail "pack-objects outlived its connection"
leftovers=$(find "$work/repos" \( -name 'tmp_*' -o -name 'incoming-*' -o -name '*.lock' \) | wc -l | tr -d ' ')
[ "$leftovers" -eq 0 ] || fail "temporary state left behind in the repositories"
ok "disconnect mid-transfer: no child processes, no temporary files"

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=
echo "end-to-end qualification passed (git $version)"
