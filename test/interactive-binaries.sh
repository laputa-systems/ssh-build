# shellcheck shell=sh
# Sourced by test/e2e-interactive.sh. THE ONLY PLACE that spells out how the binaries under test are
# invoked. When the oxish client, login-mode server or oxish-keygen change a flag, edit this file.
#
# Provides, per $E2E_MODE (standin | oxish):
#   BIN_CLIENT_DIR     host directory copied to /opt/client in the client image
#   BIN_SERVER_TARGET  Dockerfile target for the server image
#   BIN_RECONNECT_LOOP 1 only when the client cannot reconnect itself (the stand-in); the driver
#                      then supplies the reconnect loop. Must be 0 for oxish.
#   bin_keygen_script            sh script run in the client image, cwd /keys, creating host, host.pub,
#                                user, user.pub, host.fingerprint (SHA256:...) and known_hosts
#   bin_server_files             write extra server-side files into $1 (the server's /srv/e2e)
#   bin_server_entry             sh script printed to /srv/e2e/entry.sh, run as root in the server
#                                container; must exec the server in the foreground on port 22
#   bin_client_argv              the client command line (words, no spaces inside a word) as run in the
#                                client container; it must attach to tmux session "work" as account
#                                "work" on host "server"

case $E2E_MODE in
standin)
    # ===================== STAND-IN: OpenSSH client + sshd until oxish qualifies =====================
    : "${SSH_BIN_DIR:?set SSH_BIN_DIR to a directory with ssh and ssh-keygen (make binaries PRODUCT=ssh)}"
    BIN_CLIENT_DIR=$SSH_BIN_DIR
    BIN_SERVER_TARGET=server-standin
    BIN_RECONNECT_LOOP=1
    bin_keygen_script() {
        cat <<'SCRIPT'
set -eu
K=/opt/client/ssh-keygen
$K -q -t ed25519 -N '' -C e2e-host -f /keys/host
$K -q -t ed25519 -N '' -C e2e-user -f /keys/user
$K -lf /keys/host.pub | awk '{ print $2 }' > /keys/host.fingerprint
printf 'server %s\n' "$(cut -d' ' -f1,2 /keys/host.pub)" > /keys/known_hosts
SCRIPT
    }
    bin_server_files() { :; }
    bin_server_entry() {
        cat <<'SCRIPT'
set -eu
install -d -m 755 /etc/ssh
install -m 600 /srv/e2e/host /etc/ssh/e2e_host_key
install -m 644 /srv/e2e/user.pub /etc/ssh/authorized_keys_work
cat > /etc/ssh/sshd_e2e_config <<'CFG'
Port 22
HostKey /etc/ssh/e2e_host_key
AuthorizedKeysFile /etc/ssh/authorized_keys_%u
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers work
ClientAliveInterval 2
ClientAliveCountMax 2
CFG
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_e2e_config
SCRIPT
    }
    bin_client_argv() {
        # -D on the remote tmux detaches the stale pre-outage client; oxish --attach does not need it.
        echo /opt/client/ssh -t -F /dev/null -i /keys/user -o IdentitiesOnly=yes -o BatchMode=yes \
            -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/keys/known_hosts \
            -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=2 \
            -o ServerAliveInterval=1 -o ServerAliveCountMax=3 -p 22 work@server \
            tmux new-session -A -D -s work
    }
    ;;
oxish)
    # ===================== oxish: the real client, login-mode server and keygen =====================
    : "${OXISH_BIN_DIR:?set OXISH_BIN_DIR to the directory with oxish, oxish-server, oxish-session, oxish-keygen}"
    BIN_CLIENT_DIR=$OXISH_BIN_DIR
    BIN_SERVER_TARGET=server-oxish
    BIN_RECONNECT_LOOP=0
    bin_keygen_script() {
        # oxish-keygen: host and user keys, public halves, SHA256 fingerprint.
        cat <<'SCRIPT'
set -eu
K=/opt/client/oxish-keygen
$K -f /keys/host -C e2e-host
$K -f /keys/user -C e2e-user
$K -l -f /keys/host.pub | cut -d' ' -f2 > /keys/host.fingerprint
SCRIPT
    }
    bin_server_files() {
        # The login-mode accounts file: `name ssh-ed25519 KEY` per line, no options.
        printf 'work %s\n' "$(cut -d' ' -f1,2 "$1/user.pub")" > "$1/accounts"
    }
    bin_server_entry() {
        # The server runs as root so that oxish-session can drop each session to the `work` account
        # (login shell ish, from /etc/passwd). The accounts file, its directory and the host key must
        # be root-owned and not writable by others, so they are installed from the read-only mount.
        # oxish-session is found as a sibling of oxish-server in /usr/local/bin.
        cat <<'SCRIPT'
set -eu
install -d -m 755 -o root -g root /etc/oxish
install -m 600 -o root -g root /srv/e2e/host /etc/oxish/host_key
install -m 644 -o root -g root /srv/e2e/accounts /etc/oxish/accounts
exec /usr/local/bin/oxish-server --mode login --bind 0.0.0.0 --port 22 \
    --host-key-file /etc/oxish/host_key --accounts /etc/oxish/accounts \
    --passwd-file /etc/passwd --group-file /etc/group
SCRIPT
    }
    bin_client_argv() {
        # $1 is the pinned host key fingerprint (SHA256:...). --attach implies a PTY and runs
        # `tmux new-session -A -s work`; keepalives are tightened so the outage is noticed quickly.
        echo /opt/client/oxish -p 22 -i /keys/user --host-key "$1" \
            --keepalive-interval 1 --keepalive-timeout 4 --attach work work@server
    }
    ;;
*)
    echo "E2E_MODE must be standin or oxish" >&2
    exit 1
    ;;
esac
