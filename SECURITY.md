# Security status

**The OxiSH server is experimental.** Its Git mode has had one independent code review and one
author review; login mode (below) has had neither. Do not expose it to the internet on the strength
of this document. The OpenSSH client is upstream OpenSSH 10.6p1 built without libcrypto; its security
posture is OpenSSH's.

## Scope of the server

Git mode (the default). Public-key authentication for one configured account, then `git-upload-pack` and
`git-receive-pack` on repositories under one configured root, executed from one configured
trusted Git directory. Everything else (shell, PTY, subsystems, forwarding, agent, X11, password
login, forced commands, `git-upload-archive`) is refused, and the code for it is deleted rather
than switched off.

## Trust boundary of Git mode

- The operator trusts: the Git binaries in `--git-dir`, the repositories under `--repo-root`
  (their config and hooks run as the server user), `authorized_keys`, and the host keys.
- Those paths must be owned by the server user and not writable by others; the server checks the
  ones it can (root, Git directory and binaries, repository directories, `authorized_keys` and its
  directory, host key files) and refuses to start or refuses the repository otherwise.
- A client is trusted with nothing: it can pick a service word and a repository name made of plain
  words, and set `GIT_PROTOCOL=version=2`. It never picks a program, path, option, or environment.
- Repository names are resolved component by component without following symlinks, then compared
  with the canonical path. A local attacker who can replace directories under the root between
  that check and Git opening the repository is outside the model.
- The server refuses to run as root. The session process runs as the same user as the server and
  **holds the host private key**: the server serializes it into the handoff so the session can
  sign key re-exchanges. The two-process split gives the server a place to authenticate and cap
  connections before any Git command runs; it is not a host-key isolation boundary. A Git
  command's own process never sees the key, but anyone who can run code as the server user can
  read the host key file.

## Login mode

`oxish-server --mode login` is a second, separate mode. It authenticates Ed25519 keys from a
server-owned accounts file (account name and key per line; never `~/.ssh`) and gives the account its
own login shell: `pty-req`, `shell`, `exec` (`shell -c COMMAND`, with or without a terminal),
`window-change`, a fixed environment and exit status or signal. Forwarding, agent, X11, subsystems
and any other request are refused. Git mode keeps every restriction above.

- **Privilege model.** The listener may run as root, only to accept, key-exchange and authenticate.
  It then starts `oxish-session` with an empty environment and the account's user, group and
  supplementary group IDs (resolved from the flat `passwd` and `group` files) as arguments. The
  session process becomes the account before the runtime has a second thread: `setgroups`, then
  group, then user (all of real, effective and saved), then it checks the IDs and the group list and
  that `setuid(0)` and `setgid(0)` now fail, sets `umask` 022 and marks itself non-dumpable. Only
  then does it open the terminal and execute the shell. A failure at any step ends the session
  before anything runs. A server that is not root can serve only the account it runs as. Accounts
  with user ID 0 or in group 0 are refused at startup and again in the session unless
  `--allow-root-login` is given; `nologin` and `false` shells are refused.
- **What the account can reach.** The session process holds the host private key (it signs
  re-exchanges) and runs as the account, next to the account's shell. The only barrier between them
  is that the process is non-dumpable (a test fails if `/proc/$PPID/mem` or `environ` is readable by
  the shell); any other local flaw that exposes a same-user process's memory exposes the host key. A
  user can also kill their own session process, which ends only their own connection.
- **Pre-authentication code runs as root** in the listener when it is started as root: key
  exchange, packet parsing and authentication are not isolated from root. That is the main reason
  to treat login mode as experimental; an unprivileged pre-authentication process is future work.
- **Client-supplied commands.** An `exec` string reaches the account's own shell as `-c COMMAND`
  with the account's rights, exactly as in OpenSSH; there is no forced command and no restriction.
  The environment is `TERM` (with a terminal, plain terminfo characters only, at most 64),
  `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH` from `--login-path`, and with `--accept-locale`
  `LANG` and `LC_*` (at most 16, 64 plain characters each). Everything else a client sends is dropped.
- **Terminals.** The terminal is opened after the drop, so its slave belongs to the account. The
  shell starts through `oxish-session launch`, which makes it a session leader with the terminal as
  its controlling terminal and then executes it; this avoids `unsafe` pre-exec hooks. Disconnection
  hangs the terminal up and escalates through `SIGTERM` to `SIGKILL` on the process group.
- **Limits.** Same connection limits as Git mode; 8 channels and 4 live commands per connection.
  A connection with a running command is not cut off for silence (dead peers are found by TCP
  keepalive and the 60 s write deadline); one without is closed after 5 minutes.
- **Not done:** no `utmp`/`wtmp`/`lastlog`, no PAM, no NSS (only flat files), no resource limits, no
  per-key options (`command=`, `from=`), no revocation without a restart, no `signal` requests.
  Switching users is implemented for Linux only; it has not been run on the Asterinas kernel.

## Review record

The table and passes below describe Git mode.

An independent expert review (read-only, with live experiments against a running server) and the
author's own pass covered: SSH transport parsing and packet limits, KEX and rekey transitions,
the chacha20-poly1305@openssh.com construction and nonce handling, host key and public-key
authentication, authorization option parsing, Git command dispatch and filesystem confinement,
environment handling, PTY and shell escape paths, process lifecycle and signals, the handoff to the
session process, concurrency limits and backpressure, and the build supply chain.

No exploitable (P1) defect was found. Findings and their resolution:

| # | Severity | Finding | Resolution | Regression test |
|---|----------|---------|------------|-----------------|
| 1 | P2 | 32 idle TCP connections held every pre-auth slot for up to 90 s, locking out logins repeatedly | per-address pre-auth cap (4), 15 s key-exchange and 30 s auth deadlines, per-address session cap (8) | `idle_connections_from_one_address_cannot_lock_out_logins`, `per_address_limit_releases_on_drop` |
| 2 | P3 | A signature that verifies against the timing-equalizing dummy key would have completed authentication with no key options | dummy verification can never succeed a login | covered by `authorized_keys_*` and the e2e unauthorized-key case; the dummy path is unreachable without its private half |
| 3 | P3 | Refs named `x/HEAD`, `x/objects/y`, `x/refs/z` inside a repository made a look-alike nested repository addressable by name | a directory inside a repository, or one not owned by the server user and writable by others, is not a repository | `directories_inside_a_repository_are_not_repositories`, `repositories_writable_by_others_are_refused` |
| 4 | P3 | A peer that stops reading could pin a session slot; busy sessions had no inactivity bound; keepalive was the OS default | 60 s write deadline, 1 h bound for silent busy sessions, keepalive 60/15/4 s | `sessions_beyond_the_limit_are_refused` (cap) |
| 5 | P3 | Clients that send their first key exchange packet in the same segment as the identification string were dropped | only the identification line must be text | `binary_data_may_follow_the_identification_line` |
| 6 | P3 | Duplicate authorized keys with different `git-access` were accepted | duplicates are a startup error | `authorized_keys_require_an_explicit_git_access` |
| 7 | P3 | `WINDOW_ADJUST` after channel close; non-strict-KEX clients accepted (Terrapin exposure with this cipher) | no adjust after close; strict key exchange required | e2e (OpenSSH 10.6 negotiates strict KEX) |

A second review pass (after the table above) found four more, all fixed:

| # | Finding | Resolution | Regression test |
|---|---------|------------|-----------------|
| 8 | The per-address pre-auth slot was held for the whole session, so four live sessions blocked a fifth login | released when authentication succeeds | `established_sessions_do_not_use_up_the_pre_auth_allowance` |
| 9 | Commands being stopped no longer counted toward the 4-command limit, and shutdown did not wait for them | a permit per live process, held until it is reaped; shutdown waits for all | `closed_channels_keep_their_slot_until_the_command_is_reaped` |
| 10 | A client's maximum packet size below 512 was rounded up, so the server could send bigger packets than the client allowed | sizes below 128 are refused, others honored exactly | `channels_are_never_given_a_bigger_packet_size_than_the_peer_allows` |
| 11 | The Linux hardening gate missed an executable stack (multi-line `readelf` output) and did not require RELRO | parses `readelf -lW`, requires `GNU_STACK` without X, `GNU_RELRO`, no W+X load segment, no TEXTREL | `test/qualify-elf.Dockerfile` builds good and bad ELF fixtures |

Packaging also no longer trusts the checkout it runs in: each build writes `build-record.json`
(commit, input hash, toolchain, executable hashes) and `package*.sh` refuse binaries whose record
does not match the current inputs, and promote output only when every target passes.

Other fixes made while building this, each with a test: the exec path ran a client-supplied
program path (closed by `git::tests::executable_is_never_client_supplied` and the e2e hostile
command list); stderr was discarded (extended data now forwarded, `channel_stderr_*`); stdin writes
could block the session (queue bounded by the SSH window); stopping a command with a signal on
disconnect left push quarantine directories, so it now ends the command's stdin first and signals
it only if it lingers (`channel_disconnect_ends_stdin_before_any_signal` and the e2e interrupted
push);
unreadable or malformed host key files were skipped with a warning (`host_keys::tests`).

## Cryptography

Graviola is the only provider in the release graph (`sh scripts/check-crypto-graph.sh`, which
also scans `Cargo.lock` and rejects primitive crates). The SSH packet construction lives in a
patched, checksum-pinned Graviola (`patches/graviola`), not in a second hand-written ChaCha20 or
Poly1305. It is checked against 440 packets sealed by OpenSSH's own `chachapoly_crypt`, every
single-bit modification of a packet and tag, sequence-number binding, and the per-key nonce limit;
libFuzzer ran the open and round-trip targets for 4 minutes each (14.7 M and 8.1 M executions)
without a finding.

## Known limitations and accepted risks

- Key and policy files are read at startup; revoking a key needs a restart.
- Pre-auth capacity is bounded per address and globally, not per network; a distributed attacker
  can still fill the 32 global slots for 15-45 s at a time.
- Only the immediate directory of `authorized_keys` (and of the accounts, `passwd` and `group`
  files) is permission-checked.
- A failed ECDSA P-256 host-key signature returns an empty signature (the client rejects it);
  Ed25519, the default host key type, cannot fail this way.
- The server does not initiate rekeying; the per-key packet limit (2^32-1) ends the connection
  before a nonce could repeat.
- Hooks and Git config in repositories are trusted code. A push cannot change them, but anyone
  who can write the repository directory on disk can run code as the server user.
- Fuzzing covers packet decoding (6.4 M executions in 4 minutes), the chacha construction, the
  authorized_keys line parser (12 M in 2 minutes), the Git command policy (5.8 M in 2
  minutes, asserting the program and repository stay inside the trusted directories), and the
  channel open/request/data/window/eof/close state machine (asserting the channel cap, exact
  packet-size honoring, unknown-ID rejection, close removal, and no permit leak).
  `.github/workflows/fuzz.yml` runs all six targets on pull requests, pushes, and nightly.
- No sanitizer run: the server crates contain no `unsafe` (`#![forbid(unsafe_code)]`); all
  `unsafe` is in Graviola, which is upstream's to test. An AddressSanitizer build on macOS arm64
  failed to link under the local toolchain.

## Blockers before calling it production-ready

1. A deployment guide for supervision, log handling, and key rotation, tested on a real host.
2. A first run of `release.yml` on GitHub (the workflow is written and checked locally but has
   never run), and signed releases; nothing has been published.

## Evidence

Not verified: a live GitHub session with the built client (`ssh -T git@github.com`, then a clone and
push of a private repository with a throwaway key) is an owner-run check, and no published release
has been downloaded and checked.

- The end-to-end suite (`test/e2e-git.sh`, 19 checks) passed on macOS arm64, on Linux arm64 and,
  on a native host with BMI1/AVX2, on Linux x86-64; on an emulated x86-64 CPU without BMI1/AVX2 the
  server refuses to start with a clear message.
- Two clean `--no-cache` builds of the Linux arm64 server are bit-for-bit identical.
