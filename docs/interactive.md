# Interactive SSH plan

ssh-build becomes the only SSH implementation Laputa ships. It replaces
Dropbear (server, `dbclient`, `dropbearkey`) on Laputa hosts and the OpenSSH
client for daily interactive use. Laputa consumes ssh-build release archives the
way it consumes `llvm-prebuilt-musl`: a pinned URL and SHA-256 per
architecture in a package definition.

Status: plan. Each phase below is a TODO item; a phase is done when its
acceptance check passes in this repository's verification.

## What exists

| Piece | Today | Gap |
|---|---|---|
| `client/` (`oxish-client`, from XSH's `xsh-ssh`) | Host-key verification, Ed25519 key and agent authentication, `exec`, streaming, cancellation. Tested against OpenSSH. | No PTY, shell, window changes, terminal frontend, CLI, reconnection. |
| `vendor/oxish` server | Git-only (`git-upload-pack`, `git-receive-pack`); patch 0005 removed upstream's PTY code. | No login accounts, shell, PTY or general `exec`. |
| Upstream OxiSH server | PTY, shell and window-change requests; no general `exec`. | Not privilege separated for arbitrary login users; MVP. |
| OpenSSH 10.6p1 client archive | Built without OpenSSL. | Retired after the OxiSH client qualifies. |

## Product shape

One archive per target, `oxish-<version>-<triple>.tar.xz`, with:

- `oxish` — the interactive client and `ssh`-compatible command runner.
- `oxish-server` — Git mode (today's behavior) and login mode, chosen by
  configuration; Git mode keeps every current restriction.
- `oxish-session` — the per-session helper that drops to the account before it
  runs a shell or command.
- `oxish-keygen` — host and user Ed25519 keys (replaces `dropbearkey` and
  `ssh-keygen -t ed25519` for these products).

The OpenSSH archive keeps shipping until phase 6.

## Phases

### 1. Interactive client (SSHB-2)

`oxish [-p port] [-i key | -A agent] [-o host-key=SHA256:… | known_hosts] user@host [command]`:

- `pty-req` with the local `TERM`, size and the RFC 4254 terminal modes, then
  `shell` or `exec`; forward `window-change` on SIGWINCH.
- A terminal frontend that owns raw mode and restores the exact `termios` on
  every exit path (normal, signal, transport loss, panic), forwards EOF and the
  remote exit status or signal, and supports the `~.` escape.
- No PTY when stdin is not a terminal or a command is given without `-t`.
- Host keys must verify before authentication, as now; no trust on first use
  without an explicit flag that writes known_hosts.

Acceptance: a PTY-driven test against the OpenSSH fixture and against the
login-mode server runs an interactive shell, resizes, and exits with the remote
status, and leaves the local terminal attributes byte-identical.

### 2. Reconnecting terminal (SSHB-3)

`oxish --attach NAME user@host` runs `tmux new-session -A -s NAME` on the
remote and keeps it attached across transport loss:

- Detect loss with bounded keepalives; on loss restore the local terminal
  first, show a status line, and retry with bounded backoff.
- Each attempt is a fresh, fully host-verified connection that only re-runs the
  attach; it never replays a command.
- Input typed while disconnected is discarded, not replayed, because the
  foreground application may have changed.
- After reattach, request a redraw (tmux does so on attach).

This is reattachment, not Mosh-style roaming: the remote tmux server keeps the
programs; the transport is new. Acceptance is the integration test below.

Implemented behavior:

- `NAME` is 1 to 64 ASCII letters, digits, `_` or `-`, not starting with `-`;
  it is checked before any connection, so nothing else reaches the remote
  command line. `--attach` needs a terminal on stdin and excludes a command
  and `-T`. The remote command is exactly `tmux new-session -A -s NAME`.
- Keepalives: after `--keepalive-interval` (default 10 s) without any byte from
  the server the client sends a `keepalive@openssh.com` global request, and
  repeats it every further interval of silence. The peer is dead after
  `--keepalive-timeout` (default 30 s) of silence, so a vanished peer is
  noticed within 30 s of its last byte. Socket errors, resets and EOF are
  detected at once. The timers use the monotonic clock, which does not advance
  while the host sleeps; after a wake the bound counts awake time, so a dead
  connection is replaced within 30 s of the wake, and a connection that
  survived the sleep carries on. A process stopped with SIGSTOP and continued
  may reconnect spuriously; that is harmless because attach is idempotent.
- On loss the terminal is restored to its original cooked attributes, mouse,
  bracketed-paste, focus and alternate-screen modes the remote application set
  are reset, and `oxish: connection lost; reconnecting to HOST (attempt N)…` is
  printed. Attempt 1 follows at once; later attempts wait 1 s, doubling to 30 s.
  A connection that stayed attached for 10 s or more restarts the sequence with
  an immediate attempt. Attempts continue until the user interrupts with
  Ctrl-C, which exits 255 (other signals exit `128+n`).
- Every attempt is a new connection that verifies the host key before
  authenticating. Transport failures retry; host-key, authentication and
  protocol failures end the program with status 255. The first connection
  never retries: a failure before the session started is reported as usual.
- Input typed while disconnected is read and dropped while waiting, and flushed
  again, including any partly typed line, just before raw mode returns.
- On reconnect the local terminal re-enters raw mode, `pty-req` carries the
  current size, and tmux redraws on attach. A normal exit, including a tmux
  detach or session end, exits with the remote status without reconnecting; `~.`
  disconnects with status 255 and does not reconnect. A channel that closes
  with no exit status counts as loss.
- A client that vanished without closing its connection stays attached to the
  tmux session until sshd notices, because `-D` is not used: it would also
  detach a second terminal that attached on purpose.

### 3. Login-mode server (SSHB-4)

Status: implemented in `vendor/oxish` (`--mode login`); see `README.md` for the configuration and
`SECURITY.md` for the privilege model and what is not verified. Not yet run on Asterinas.

Restore upstream's PTY, shell and window-change handling as login mode, add
`exec` for login accounts, and keep Git mode unchanged:

- Accounts come from a server-owned configuration (account name, authorized
  Ed25519 keys); the server never reads `~/.ssh`.
- Privilege model: the listener runs as root only to accept and authenticate;
  each authenticated session runs in `oxish-session`, which sets groups, gid
  and uid to the account before it opens the PTY slave and executes the
  account's shell from the passwd database. Refuse root unless explicitly
  allowed.
- Environment: only `TERM`, `LANG`/`LC_*` (if allowed), `HOME`, `USER`,
  `LOGNAME`, `SHELL`, `PATH` from configuration.
- No port forwarding, agent forwarding or X11. SFTP (and so OpenSSH `sftp` and `scp`) is the only
  subsystem, served in-process after the privilege drop.
- Runs on Linux musl and on the Asterinas kernel (PTY, `setgroups`, `setuid`).

Acceptance: server tests for authentication refusal, privilege drop
(`id` inside the session), PTY allocation, window changes, `exec` exit
statuses and signals, and Git mode's existing tests unchanged.

### 4. Integration test (SSHB-5)

`test/e2e-interactive.sh` (no system `ssh`, `git` or `tmux` from the host):

- Server container: `oxish-server` in login mode, an account whose login shell
  is ish from a pinned [ish release](https://github.com/joshuarli/ish/releases)
  (`release-<sha>` asset, SHA-256 pinned in a lock file like
  `git-build.lock.json`), and a pinned static tmux.
- Client: `oxish --attach work` driven under a PTY by a small Rust or Python
  harness.
- Scenario: attach; at the ish prompt run a command that prints a marker and
  keeps a counter running in tmux; break the TCP connection (stop the network
  between containers, then restore it); assert the client reconnects, the same
  tmux session is attached, the counter kept running, the marker is still on
  screen, and the ish prompt contains no terminal-reply garbage; resize and
  assert `tput cols` follows; exit and assert the local terminal attributes
  are restored.

### 5. Release (SSHB-6)

Package the client, server, session helper and keygen in the `oxish` archive
for all three targets, with manifests, budgets and `SHA256SUMS`, and qualify
the client on macOS arm64 natively.

### 6. Laputa consumes ssh-build; Dropbear removed (SSHB-7)

In Laputa: an `oxish` package pinned to the release archive (as
`llvm-toolchain` pins `llvm-prebuilt-musl`); an xinit service for
`oxish-server` login mode replacing `dropbear`; first boot generates the host
key with `oxish-keygen`; backup, restore, health, firewall and remote
administration use the new key and service; every Dropbear test moves to the
new server; then the `dropbear` package and its docs are removed. XSH keeps its
native client and later vendors `client/` from this repository instead of its
own copy. The OpenSSH client archive is retired once the OxiSH client
qualifies on macOS and Linux for daily use.

## Out of scope

Mosh-style roaming and local echo prediction, Tailscale SSH (`none`)
authentication, an SFTP or scp client in `oxish`, forwarding, RSA/ECDSA keys.
