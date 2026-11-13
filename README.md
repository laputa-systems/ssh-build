# ssh-build

Two optional downloads, built without OpenSSL:

- **OpenSSH 10.6p1 client** (`ssh`, `ssh-keygen`, `ssh-agent`, `ssh-add`, `sftp`, `scp`) built
  `--without-openssl`, as `ssh-<version>-<triple>.tar.xz`.
- **OxiSH** (experimental), Graviola-only SSH tools, as `oxish-<version>-<triple>.tar.xz`:
  `oxish-server`, which by default only serves `git-upload-pack` and `git-receive-pack` and with
  `--mode login` gives configured accounts a shell or command; its `oxish-session` helper; the
  interactive `oxish` client; and `oxish-keygen` (see [Key generation](#key-generation) and
  `docs/interactive.md`).

Targets (`<triple>`): `aarch64-apple-darwin`, `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`. Neither product contains libcrypto or libssl. Each archive has a
`<product>-<version>-<triple>.manifest.json` beside it (`product`, `version`, `target`,
`source_revision`, `sources_lock_sha256`, and the pinned inputs). Release assets come with one
`SHA256SUMS`; check it before unpacking (`sha256sum -c SHA256SUMS` or
`shasum -a 256 -c SHA256SUMS`). The `dl` installer's `dl ssh` and `dl oxish` consume the
`.tar.xz` assets and install them under `~/.local/share/{ssh,oxish}/releases/<tag>-<triple>`
with a `current` link. `dl oxish` is opt-in and not in the default set.

## Client

Without libcrypto OpenSSH offers only `aes128-ctr`, `aes192-ctr`, `aes256-ctr` and
`chacha20-poly1305@openssh.com` for packet encryption, and only Ed25519 keys. There is no GCM, RSA
or ECDSA, so hosts that insist on those will not negotiate with this client. `sftp` and `scp` run
the `ssh` found on `PATH`.

## Key generation

`oxish-keygen` makes the Ed25519 keys the OxiSH tools read, in the OpenSSH private key format that
OpenSSH accepts. It needs no OpenSSH, never overwrites a file and never writes through a symbolic
link.

```sh
oxish-keygen -f host_key -C "git@example.org"   # host_key (mode 0600, unencrypted) and host_key.pub
oxish-keygen -y -f host_key                      # print the public key
oxish-keygen -l -f host_key.pub                  # print the SHA256 fingerprint (a private key works too)
```

`oxish-server --generate-host-key` makes the same format. Private keys that are group- or
world-accessible are refused by `-y` and `-l`.

## Server

`oxish-server` has two modes, chosen with `--mode git|login` (default `git`). Git mode is
described first; login mode follows it.

### Git mode

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

Run it as a dedicated unprivileged account; it refuses root. It listens on loopback only, on
`127.0.0.1` and `::1` (the IPv6 one is skipped with a warning on a host without IPv6), unless you
pass `--bind ADDRESS`, which replaces that default and may repeat. `--bind ::` accepts IPv6 and IPv4
on every interface (one dual-stack socket, or a second IPv4 socket where the platform has no
dual-stack), `--bind 0.0.0.0` only IPv4. With `--port 0` every listener shares the port the first
one got. On Linux it instead serves every socket from `LISTEN_FDS` (for example separate IPv4 and
IPv6 `ListenStream=` lines), so an existing supervisor or socket activation works; `--port` or
`--bind` together with `LISTEN_FDS` is an error. IPv4 peers that arrive on an IPv6 socket are logged
and limited as their IPv4 address. When `accept()` fails because the process or system is out of
descriptors or memory, it logs and retries after 1 s. It installs no service unit, opens no firewall
port and creates no keys on its own. Run `oxish-server --help` for every option.

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
`max-sessions`, `max-unauthenticated-per-ip`, `max-sessions-per-ip` and, in login mode,
`max-sessions-per-account` (default 8).

**Hardware.** Graviola needs x86-64 Broadwell-class cores (AES-NI, PCLMULQDQ, BMI1, ADX, AVX2) or
aarch64 with NEON, AES, PMULL and SHA2. Both executables check this at startup and exit with a
message.

### Login mode

```sh
oxish-server --mode login --port 2222 \
    --host-key-file host_key \
    --accounts /etc/oxish/accounts
```

`--accounts` is a server-owned file with one `name key` pair per line, the key in OpenSSH
`authorized_keys` syntax without options and only `ssh-ed25519`; an account may have several lines:

```
# account  key
alice      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop
alice      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@phone
bob        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... bob@desk
```

The server never reads `~/.ssh`. The accounts file and its directory must be owned by the server
user (root, when it runs as root) and not writable by others; a symlink, a bad line, an option, a
duplicate key or a missing `passwd` entry stops startup. Each account is resolved at login in the
flat files `--passwd-file` (default `/etc/passwd`) and `--group-file` (default `/etc/group`); there
is no NSS. The account's own login shell from `passwd` runs the session: `shell` and `pty-req` start
it as a login shell (`argv[0]` begins with `-`), `exec` runs `shell -c COMMAND` exactly as OpenSSH
does, with or without a terminal. `window-change`, `exit-status`, `exit-signal` and EOF work as in
OpenSSH. Port forwarding, agent and X11 forwarding, subsystems (SFTP) and other `env` requests are
refused. The environment is `TERM` (only with a terminal, plain terminfo names only), `HOME`,
`USER`, `LOGNAME`, `SHELL` and `PATH` (`--login-path`, default `/usr/local/bin:/usr/bin:/bin`);
`--accept-locale` also passes the client's `LANG` and `LC_*`.

Run as root, the listener only accepts and authenticates. Each authenticated connection is handed to
`oxish-session`, which sets supplementary groups, group and user to the account, proves that root
cannot be regained, and only then opens the terminal and runs the shell. Accounts with user ID 0 or
in group 0 are refused unless `--allow-root-login` is given. Run unprivileged, the server can serve
only the account it runs as. Login mode is Linux-only for switching users. The `oxish-session` binary
and its directory must be owned by the server user (root, when it runs as root) and not writable by
others; the server refuses to start or to log in otherwise.

The server is **experimental**; read `SECURITY.md` before exposing it.
