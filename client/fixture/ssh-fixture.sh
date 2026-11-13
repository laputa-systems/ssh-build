#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=oxish-client-fixture:alpine-3.22-openssh-tmux
user=xinfra
[ "${1:-}" = exec ] && [ $# -ge 2 ] || { echo "usage: $0 exec COMMAND [ARG...]" >&2; exit 2; }
shift

work="$root/.work/tmp"
mkdir -p "$work"
scratch=$(mktemp -d "$work/ssh-fixture.XXXXXX")
containers=""
cleanup() {
  for id in $containers; do docker rm -f "$id" >/dev/null 2>&1 || true; done
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" "$here" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C oxish-client-fixture -f "$scratch/key"
passphrase=fixture-passphrase
ssh-keygen -q -t ed25519 -N "$passphrase" -C oxish-client-fixture-agent -f "$scratch/agent-key"
cat "$scratch/key.pub" "$scratch/agent-key.pub" > "$scratch/authorized"

start() {
  suffix=$1
  mkdir -p "$scratch/auth-$suffix"
  cp "$scratch/authorized" "$scratch/auth-$suffix/$user"
  chmod 755 "$scratch/auth-$suffix"
  chmod 644 "$scratch/auth-$suffix/$user"
  id=$(docker run -d -p 127.0.0.1::22 -v "$scratch/auth-$suffix:/etc/ssh/authorized_keys:ro" "$image")
  containers="$containers $id"
  port=$(docker port "$id" 22/tcp | sed -n 's/.*://p' | head -n 1)
  tries=0
  until docker exec "$id" test -s /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null &&
        docker exec "$id" sh -c 'pgrep sshd >/dev/null'; do
    tries=$((tries + 1))
    [ $tries -lt 100 ] || { docker logs "$id" >&2; echo "sshd did not start" >&2; exit 1; }
    sleep 0.1
  done
  pub=$(docker exec "$id" cat /etc/ssh/ssh_host_ed25519_key.pub)
  fingerprint=$(printf '%s\n' "$pub" | ssh-keygen -lf - | awk '{print $2}')
  eval "XINFRA_FIXTURE_${suffix}_HOST=127.0.0.1"
  eval "XINFRA_FIXTURE_${suffix}_PORT=$port"
  eval "XINFRA_FIXTURE_${suffix}_HOST_KEY=$fingerprint"
  eval "XINFRA_FIXTURE_${suffix}_HOST_KEY_PUB=\$pub"
  eval "XINFRA_FIXTURE_${suffix}_CONTAINER=$id"
  export "XINFRA_FIXTURE_${suffix}_HOST" "XINFRA_FIXTURE_${suffix}_PORT" \
    "XINFRA_FIXTURE_${suffix}_HOST_KEY" "XINFRA_FIXTURE_${suffix}_HOST_KEY_PUB" \
    "XINFRA_FIXTURE_${suffix}_CONTAINER"
}

start A
start B
XINFRA_FIXTURE_USER=$user
XINFRA_FIXTURE_KEY="$scratch/key"
XINFRA_FIXTURE_AGENT_KEY="$scratch/agent-key"
XINFRA_FIXTURE_AGENT_PASSPHRASE=$passphrase
export XINFRA_FIXTURE_USER XINFRA_FIXTURE_KEY XINFRA_FIXTURE_AGENT_KEY XINFRA_FIXTURE_AGENT_PASSPHRASE
"$@"
