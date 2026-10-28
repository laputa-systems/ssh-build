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

## OxiSH Git server (experimental)

A separate, optional distribution: `oxish-<triple>.zip` holds `bin/oxish-server` and
`bin/oxish-session` for macOS arm64 and static-PIE musl Linux (x86_64, aarch64). It is a
Rust SSH server whose only job is `git-upload-pack` and `git-receive-pack`, with Graviola as its
only cryptography. It is not a general SSH server: no shell, no PTY, no SFTP, no forwarding,
no agent or X11, no password authentication, no forced commands. It does not include Git; it
runs the `git`, `git-upload-pack` and `git-receive-pack` of a [git-build] install that you point
it at, and never looks them up on `PATH` or takes a program from a client.

[git-build]: https://github.com/laputa-systems/git-build

```sh
oxish-server --generate-host-key host_key          # refuses to overwrite; rotate by adding a second key
oxish-server --port 2222 \
    --host-key-file host_key \
    --repo-root /srv/git \
    --git-dir ~/.local/share/git/current \
    --authorized-keys authorized_keys
```

Run it as a dedicated unprivileged account (it refuses root). It binds `127.0.0.1` unless you
pass `--bind`; it can also take a socket from `LISTEN_FDS`, so an existing supervisor or socket
activation works. There is no service unit, no firewall change, and no key installation.

`authorized_keys` uses OpenSSH syntax with one required option per key: `git-access="read"`
(clone and fetch) or `git-access="write"` (also push). Any other option, a missing option, a
duplicate, or a bad line stops the server at startup. The file, its directory, and each host key
must be owned by the server user and not writable by others (host keys: mode 0600).

Clients name repositories relative to `--repo-root` (`git@host:team/app.git` or
`ssh://git@host/team/app.git`). Names are plain words, at most 8 components; `..`, hidden
components, symlinks, and anything that is not a bare repository are refused, and the repository
is opened by its canonical path under the root. Repositories are trusted code (their config and
hooks run as the server user); keep `--repo-root` and `--git-dir` writable only by that user.
Git protocol v2 is supported (`GIT_PROTOCOL=version=2` is the only value accepted); v0 still
works.

Limits: 32 unauthenticated connections (4 per source address), 32 authenticated sessions (8 per
address; `max-sessions` and friends in `--config`), 8 channels and 4 commands per connection,
15 s to key exchange, 30 s to authenticate, 5 min idle with no running command (1 h when one is
running), 60 s for a peer that stops reading, TCP keepalive 60/15/4 s, 1 MiB of buffered input per
channel.

Hardware: Graviola needs x86-64 Broadwell-class cores (AES-NI, PCLMULQDQ, BMI1, ADX, AVX2) or
aarch64 with NEON, AES, PMULL and SHA2. Both executables check this at startup and exit with a
message instead of crashing later.

Security status: **experimental**, not reviewed for production. See `SECURITY.md`.

```sh
make oxish-macos                                    # dist/oxish-macos/bin
make oxish-linux DOCKER_PLATFORM=linux/arm64        # dist/oxish-linux-aarch64/bin
sh scripts/package-oxish.sh                         # server ZIPs into dist/release
SSH_BIN_DIR=dist/macos/bin OXISH_BIN_DIR=dist/oxish-macos/bin sh test/e2e-git.sh
sh scripts/check-crypto-graph.sh                    # Graviola is the only provider
sh scripts/vendor-oxish.sh verify                   # vendor tree == pinned upstream + patches
sh scripts/vendor-graviola.sh verify
```

`test/e2e-git.sh` uses only this repository's `ssh`, the server under test, and the pinned
git-build prerelease (`git-build.lock.json`, downloaded read-only and checksum-verified); it never
falls back to the system `ssh` or `git`.

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
