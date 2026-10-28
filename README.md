# ssh-build

Two optional downloads, built without OpenSSL:

- **OpenSSH 10.6p1 client** (`ssh`, `ssh-keygen`, `ssh-agent`, `ssh-add`, `sftp`, `scp`) built
  `--without-openssl`, as `ssh-<triple>.zip`.
- **OxiSH Git server** (experimental), a small SSH server that only serves `git-upload-pack` and
  `git-receive-pack`, as `oxish-<triple>.zip`.

Targets: macOS arm64, and static musl Linux on x86_64 and aarch64. Neither contains libcrypto or
libssl. Release assets come with one `SHA256SUMS`; check it before unpacking
(`sha256sum -c SHA256SUMS` or `shasum -a 256 -c SHA256SUMS`). The `dl` installer's `dl ssh` and
`dl oxish` install them under `~/.local/share/{ssh,oxish}/releases/<tag>-<triple>`
with a `current` link. `dl oxish` is opt-in and not in the default set.

## Client

Without libcrypto OpenSSH offers only `aes128-ctr`, `aes192-ctr`, `aes256-ctr` and
`chacha20-poly1305@openssh.com` for packet encryption, and only Ed25519 keys. There is no GCM, RSA
or ECDSA, so hosts that insist on those will not negotiate with this client. `sftp` and `scp` run
the `ssh` found on `PATH`.

## Server

It runs the `git`, `git-upload-pack` and `git-receive-pack` of a
[git-build](https://github.com/laputa-systems/git-build) install that you point it at, never one
found on `PATH` and never one named by a client. Graviola is its only cryptography. There is no
shell, PTY, SFTP, forwarding, agent, X11, password login or forced command.

```sh
oxish-server --generate-host-key host_key          # never overwrites an existing file
oxish-server --port 2222 \
    --host-key-file host_key \
    --repo-root /srv/git \
    --git-dir ~/.local/share/git/current \
    --authorized-keys authorized_keys
```

Run it as a dedicated unprivileged account; it refuses root. It binds `127.0.0.1` unless you pass
`--bind`, and on Linux it also accepts a socket from `LISTEN_FDS`, so an existing supervisor or
socket activation works. It installs no service unit, opens no firewall port and creates no keys on
its own. Run `oxish-server --help` for every option.

**Keys.** `authorized_keys` uses OpenSSH syntax with one required option per key,
`git-access="read"` (clone and fetch) or `git-access="write"` (also push). Any other option, a
missing or duplicate option, a duplicate key or a bad line stops startup. The file, its directory
and each host key must be owned by the server user and not writable by others (host keys: mode
0600). `--host-key-file` may repeat; the first key of each algorithm is the one presented, so to
rotate, list the new key first, give clients its public key, and restart. An unreadable, malformed
or loosely permissioned key file stops startup instead of being skipped.

**Repositories.** Clients name them relative to `--repo-root` (`git@host:team/app.git` or
`ssh://git@host/team/app.git`). A name is plain words, at most 8 components. `..`, hidden
components, symlinks, directories inside a repository, and anything that is not a bare repository
owned by the server user are refused. Repositories are trusted code, because their config and hooks
run as the server user, so keep `--repo-root` and `--git-dir` writable only by that user. Git
protocol v2 works (`GIT_PROTOCOL=version=2` is the only value passed through) and v0 still does.

**Limits.** 32 unauthenticated connections (4 per source address), 32 sessions (8 per address),
8 channels and 4 commands per connection, 15 s to key exchange, 30 s to authenticate, 5 min idle
with no running command (1 h with one), 60 s for a peer that stops reading, TCP keepalive
60/15/4 s, 1 MiB of buffered input per channel. A TOML file passed with `--config` sets
`max-sessions`, `max-unauthenticated-per-ip` and `max-sessions-per-ip`.

**Hardware.** Graviola needs x86-64 Broadwell-class cores (AES-NI, PCLMULQDQ, BMI1, ADX, AVX2) or
aarch64 with NEON, AES, PMULL and SHA2. Both executables check this at startup and exit with a
message.

The server is **experimental**; read `SECURITY.md` before exposing it.
