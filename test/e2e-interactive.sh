#!/bin/sh
# Phase 4 (SSHB-5) integration test: an interactive, reconnecting tmux session through a broken and
# restored network path. See docs/interactive.md.
#
#   OXISH_BIN_DIR=dist/oxish/x86_64-unknown-linux-musl/bin sh test/e2e-interactive.sh
#   E2E_MODE=standin SSH_BIN_DIR=dist/ssh/x86_64-unknown-linux-musl/bin sh test/e2e-interactive.sh
#
# E2E_MODE=oxish (default) tests oxish, oxish-server in login mode and oxish-keygen. E2E_MODE=standin
# is a temporary stand-in that validates the harness with the OpenSSH client and Alpine's sshd.
# Other inputs: TARGET (Linux musl triple, default the host's), ISH_DIR (a directory holding `ish`;
# default scripts/fetch-ish.sh), DRIVER_ARGS (extra driver flags, e.g. --show-screen or the self-test
# --inject '1;2c' that must make the run fail), KEEP=1 (leave containers and the network for debugging).
#
# Needs Docker and jaq. Containers are the only place anything runs: the client container holds the
# client under test and a Python PTY driver; the server container holds the server under test, the
# pinned ish and the pinned static tmux. No ssh, git or tmux from the host is used.
set -eu

E2E_MODE=${E2E_MODE:-oxish}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
abs() { (CDPATH= cd -- "$1" && pwd -P); }
fail() { echo "FAIL: $1" >&2; exit 1; }
ok() { echo "ok: $1"; }

command -v docker >/dev/null || fail "docker is required"
command -v jaq >/dev/null || fail "jaq is required"

# shellcheck source=test/interactive-binaries.sh
. "$root/test/interactive-binaries.sh"

if [ -z "${TARGET:-}" ]; then
    case "$(uname -m)" in
        x86_64|amd64) TARGET=x86_64-unknown-linux-musl ;;
        aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
        *) fail "no Linux target for $(uname -m)" ;;
    esac
fi
case $TARGET in
    x86_64-unknown-linux-musl) platform=linux/amd64 ;;
    aarch64-unknown-linux-musl) platform=linux/arm64 ;;
    *) fail "TARGET must be a Linux musl triple" ;;
esac

client_dir=$(abs "$BIN_CLIENT_DIR")
if [ -n "${ISH_DIR:-}" ]; then ish_dir=$(abs "$ISH_DIR"); else ish_dir=$(sh "$root/scripts/fetch-ish.sh" "$TARGET"); fi
[ -x "$ish_dir/ish" ] || fail "$ish_dir/ish is missing"

work=$root/.work/e2e-interactive
id=$$
net=sshb-e2e-net-$id
server=sshb-e2e-server-$id
client_image=sshb-e2e-client:$E2E_MODE
server_image=sshb-e2e-server:$E2E_MODE
controller_pid=

cleanup() {
    status=$?
    [ -z "$controller_pid" ] || kill "$controller_pid" 2>/dev/null || true
    if [ "$status" -ne 0 ] && [ -n "${KEEP:-}" ]; then
        echo "KEEP set: leaving $server and $net (docker rm -f $server; docker network rm $net)" >&2
    else
        if [ "$status" -ne 0 ] && docker inspect "$server" >/dev/null 2>&1; then docker logs "$server" >&2 2>&1 || true; fi
        docker rm -f "$server" >/dev/null 2>&1 || true
        docker network rm "$net" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

rm -rf "$work"
mkdir -p "$work/ctx/ish" "$work/ctx/client" "$work/ctx/oxish" "$work/keys" "$work/ctl" "$work/server"
chmod 777 "$work/ctl" "$work/keys"

# ---- images: the pinned inputs come from tmux.lock.json and ish.lock.json -------------------------
cp "$ish_dir/ish" "$work/ctx/ish/ish"
cp -R "$client_dir"/. "$work/ctx/client/"
if [ "$BIN_SERVER_TARGET" = server-oxish ]; then cp -R "$client_dir"/. "$work/ctx/oxish/"; else : > "$work/ctx/oxish/.empty"; fi
cp "$root/test/interactive-driver.py" "$work/ctx/interactive-driver.py"
build_args=
for name in tmux libevent ncurses; do
    upper=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    url=$(jaq -r --arg n "$name" '.inputs[] | select(.name == $n) | .url' "$root/tmux.lock.json")
    sha=$(jaq -r --arg n "$name" '.inputs[] | select(.name == $n) | .sha256' "$root/tmux.lock.json")
    [ -n "$url" ] && [ -n "$sha" ] || fail "tmux.lock.json has no $name"
    build_args="$build_args --build-arg ${upper}_URL=$url --build-arg ${upper}_SHA256=$sha"
done
build() {
    # shellcheck disable=SC2086
    docker buildx build --platform "$platform" --progress=plain $build_args -f "$root/test/interactive.Dockerfile" \
        --target "$1" --load -t "$2" "$work/ctx" > "$work/build-$1.log" 2>&1 \
        || { tail -n 40 "$work/build-$1.log" >&2; fail "docker build of $1 failed (log: $work/build-$1.log)"; }
}
build "$BIN_SERVER_TARGET" "$server_image"
build client "$client_image"
ok "images built: server=$BIN_SERVER_TARGET client (tmux $(jaq -r '.inputs[] | select(.name=="tmux") | .version' "$root/tmux.lock.json"), ish $(jaq -r .tag "$root/ish.lock.json" | cut -c1-20))"

in_client() { docker run --rm --platform "$platform" "$@"; }

# ---- keys ---------------------------------------------------------------------------------------------
uid=$(id -u)
gid=$(id -g)
bin_keygen_script > "$work/keygen.sh"
in_client -v "$work/keys:/keys" -v "$work/keygen.sh:/keygen.sh:ro" "$client_image" \
    sh -c "sh /keygen.sh && chown -R $uid:$gid /keys && chmod 644 /keys/* && chmod 600 /keys/host /keys/user" \
    || fail "key generation failed"
fingerprint=$(cat "$work/keys/host.fingerprint")
case $fingerprint in SHA256:*) ;; *) fail "unexpected host fingerprint '$fingerprint'" ;; esac
ok "keys generated; host key $fingerprint"

# ---- server -------------------------------------------------------------------------------------------
cp "$work/keys/host" "$work/keys/host.pub" "$work/keys/user.pub" "$work/server/"
bin_server_files "$work/server"
bin_server_entry > "$work/server/entry.sh"
docker network create "$net" >/dev/null
docker run -d --name "$server" --platform "$platform" --network "$net" --network-alias server \
    -v "$work/server:/srv/e2e:ro" "$server_image" >/dev/null
ready=0
tries=0
while [ "$tries" -lt 50 ]; do
    if in_client --network "$net" "$client_image" python3 -I -c '
import socket, sys
s = socket.create_connection(("server", 22), 2)
s.sendall(b"SSH-2.0-e2e-probe\r\n")  # oxish-server speaks only after the client identification line
sys.exit(0 if s.recv(4).startswith(b"SSH-") else 1)' >/dev/null 2>&1; then ready=1; break; fi
    tries=$((tries + 1))
    sleep 0.5
done
[ "$ready" -eq 1 ] || fail "the server never answered with an SSH banner on port 22"
ok "server answers on server:22"

# ---- the host side of the scenario: break and restore the path, report tmux's own view --------------
ctl=$work/ctl
net_controller() {
    while :; do
        for req in "$ctl"/*.req; do
            [ -e "$req" ] || continue
            name=$(basename "$req" .req)
            rm -f "$req"
            case $name in
                break)
                    docker exec "$server" cat /tmp/e2e-counter > "$ctl/counter.break" 2>/dev/null || true
                    docker network disconnect "$net" "$server" ;;
                restore)
                    docker network connect --alias server "$net" "$server"
                    docker exec "$server" cat /tmp/e2e-counter > "$ctl/counter.restore" 2>/dev/null || true ;;
                capture)
                    docker exec -u work "$server" tmux capture-pane -p -J -t work:0.0 > "$ctl/capture.txt" ;;
            esac
            : > "$ctl/$name.done"
        done
        sleep 0.2
    done
}
net_controller &
controller_pid=$!

# ---- run the scenario -----------------------------------------------------------------------------------
loop_flag=
[ "$BIN_RECONNECT_LOOP" = 1 ] && loop_flag=--standin-reconnect
argv=$(bin_client_argv "$fingerprint")
echo "client: $argv"
[ "$BIN_RECONNECT_LOOP" = 1 ] && echo "STAND-IN: the driver restarts the client; the reconnect assertions of oxish --attach are not exercised"
# shellcheck disable=SC2086
in_client --network "$net" -v "$ctl:/ctl" -v "$work/keys:/keys:ro" "$client_image" \
    python3 -I /opt/driver/interactive-driver.py --ctl /ctl $loop_flag ${DRIVER_ARGS:-} -- $argv

# ---- host-side ground truth -------------------------------------------------------------------------------
before=$(cat "$ctl/counter.break")
after=$(cat "$ctl/counter.restore")
[ "$after" -gt "$before" ] || fail "the server-side counter did not advance during the outage ($before -> $after)"
ok "server-side counter kept running while disconnected ($before -> $after)"

# ---- file transfer: oxish-scp and oxish-sftp against the login-mode SFTP subsystem ----------------------
if [ "$E2E_MODE" = oxish ]; then
    in_client --network "$net" -v "$work/keys:/keys:ro" -e "FP=$fingerprint" "$client_image" sh -euc '
        flags="-P 22 -i /keys/user --host-key $FP"
        head -c 4194304 /dev/urandom > /tmp/up
        /opt/client/oxish-scp $flags /tmp/up work@server:e2e-up
        /opt/client/oxish-scp $flags work@server:e2e-up /tmp/down
        cmp /tmp/up /tmp/down
        printf "%s\n" "mkdir e2e-dir" "put /tmp/up e2e-dir/copy" "rename e2e-dir/copy e2e-dir/moved" "ls e2e-dir" "get e2e-dir/moved /tmp/again" > /tmp/batch
        /opt/client/oxish-sftp $flags -b /tmp/batch work@server > /tmp/batch.out
        grep -q moved /tmp/batch.out
        cmp /tmp/up /tmp/again
        sha256sum /tmp/up | cut -d" " -f1' > "$work/transfer.sha256" || fail "oxish-scp/oxish-sftp transfer failed"
    remote=$(docker exec -u work "$server" sh -c 'sha256sum ~/e2e-up ~/e2e-dir/moved | cut -d" " -f1 | sort -u')
    [ "$remote" = "$(cat "$work/transfer.sha256")" ] || fail "server-side copies differ from the uploaded file"
    owner=$(docker exec "$server" stat -c %U /home/work/e2e-up /home/work/e2e-dir | sort -u)
    [ "$owner" = work ] || fail "transferred files are owned by '$owner', not the account"
    ok "oxish-scp and oxish-sftp round-tripped 4 MiB through the login-mode server as the account"
fi
echo "interactive end-to-end passed ($E2E_MODE)"
