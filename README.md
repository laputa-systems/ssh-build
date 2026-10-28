# ssh-build

OpenSSH 10.6p1 client built `--without-openssl`: `ssh`, `ssh-keygen`,
`ssh-agent`, `ssh-add`, `sftp`, `scp`. Targets: macOS arm64 and static-musl
Linux x86_64 and aarch64. No libcrypto or libssl in any artifact.

## What the client supports

Without libcrypto OpenSSH offers only `aes128-ctr`, `aes192-ctr`,
`aes256-ctr`, and `chacha20-poly1305@openssh.com` for packet encryption, and
only Ed25519 keys (libsodium-style fallback code in the source tree). There is
no GCM, RSA, or ECDSA. Hosts that insist on those will not negotiate with this
client.

## Build and verify

```sh
sh scripts/fetch-sources.sh                     # download + verify pins
make macos                                      # dist/macos/bin
make linux DOCKER_PLATFORM=linux/arm64          # dist/linux-aarch64/bin
make linux DOCKER_PLATFORM=linux/amd64          # dist/linux-x86_64/bin
sh scripts/qualify-binaries.sh dist/macos/bin   # linkage/hardening gates
SSH_BIN_DIR=dist/macos/bin sh test/runtime.sh   # functional qualification
sh scripts/package.sh                           # dist/release: 3 ZIPs + SHA256SUMS
```

The Linux gates run inside the Docker build with `readelf`; bytes that fail
them are never exported. `scripts/package.sh` refuses missing, wrong-arch, or
non-static directories and ZIPs over the sizes in `release-budgets.json`.

`test/runtime.sh` runs keygen, encrypted-key unlock, config parsing, agent,
and sftp/scp transfers against a loopback system `sshd` with throwaway keys,
plus `exec` against the vendored OxiSH server.

## OxiSH interop

`vendor/oxish` is OxiSH pinned in `sources.lock.json`, built with the
Graviola crypto provider only. It adds two things for Git hosting:

- `chacha20-poly1305@openssh.com` packet encryption using OpenSSH's own
  construction (two ChaCha20 keys, Poly1305 over length plus payload), so the
  no-libcrypto client can negotiate it.
- Non-PTY `exec` with stdin/stdout/stderr forwarding and exit-status
  propagation, restricted to `git-upload-pack` and `git-receive-pack`
  (or an authorized key's forced command).

```sh
sh test/oxish-chacha-interop.sh   # handshake with only chacha negotiated
sh test/oxish-exec.sh             # git clone over exec, non-Git rejection
```

OxiSH is not qualified as a public Git server.

## Upgrading OpenSSH

Change `OPENSSH_VERSION=` and `OPENSSH_SHA256=` in `scripts/fetch-sources.sh`
and `sources.lock.json`; the Makefile, Dockerfile, and tests derive from them.

## Install

After a release is published, `dl ssh` installs the bundle atomically under
`~/.local/share/ssh/releases/<tag>-<triple>` with a `current` symlink.

## Not verified here

Live GitHub (`ssh -T git@github.com`, private-repo clone/push) is an
owner-run check with a throwaway key. Published-release verification
(`sha256sum -c SHA256SUMS` on downloaded assets) needs the release workflow.
