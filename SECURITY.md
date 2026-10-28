# Security status

**The OxiSH Git server is experimental.** It has had one independent code review and one
author review, not an external audit. Do not expose it to the internet on the strength of this
document. The OpenSSH client is upstream OpenSSH 10.6p1 built without libcrypto; its security
posture is OpenSSH's.

## Scope of the server

Public-key authentication for one configured account, then `git-upload-pack` and
`git-receive-pack` on repositories under one configured root, executed from one configured
trusted Git directory. Everything else (shell, PTY, subsystems, forwarding, agent, X11, password
login, forced commands, `git-upload-archive`) is refused, and the code for it is deleted rather
than switched off.

## Trust boundary

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

## Review record

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
could block the session (queue bounded by the SSH window); `SIGKILL` on disconnect left push
quarantine directories (`channel_disconnect_asks_the_command_to_stop_before_killing_it`);
unreadable or malformed host key files were skipped with a warning (`host_keys::tests`).

## Cryptography

Graviola is the only provider in the release graph (`sh scripts/check-crypto-graph.sh`, which
also scans `Cargo.lock` and rejects primitive crates). The SSH packet construction lives in a
patched, checksum-pinned Graviola (`patches/graviola`), not in a second hand-written ChaCha20 or
Poly1305. It is checked against 440 packets sealed by OpenSSH's own `chachapoly_crypt`, every
single-bit modification of a packet and tag, sequence-number binding, and the per-key nonce limit;
libFuzzer ran the open and round-trip targets for 4 minutes each (14.7 M and 8.1 M executions)
without a finding. The patch is not yet reviewed by Graviola's
maintainers.

## Known limitations and accepted risks

- Key and policy files are read at startup; revoking a key needs a restart.
- Pre-auth capacity is bounded per address and globally, not per network; a distributed attacker
  can still fill the 32 global slots for 15-45 s at a time.
- Only the immediate directory of `authorized_keys` is permission-checked.
- A failed ECDSA P-256 host-key signature returns an empty signature (the client rejects it);
  Ed25519, the default host key type, cannot fail this way.
- The server does not initiate rekeying; the per-key packet limit (2^32-1) ends the connection
  before a nonce could repeat.
- Hooks and Git config in repositories are trusted code. A push cannot change them, but anyone
  who can write the repository directory on disk can run code as the server user.
- Fuzzing covers packet decoding (6.4 M executions in 4 minutes), the chacha construction, the
  authorized_keys line parser (12 M in 2 minutes), and the Git command policy (5.8 M in 2
  minutes, asserting the program and repository stay inside the trusted directories). The channel
  state machine is covered by tests, not fuzzing.
- No sanitizer run: the server crates contain no `unsafe` (`#![forbid(unsafe_code)]`); all
  `unsafe` is in Graviola, which is upstream's to test. An AddressSanitizer build on macOS arm64
  failed to link under the local toolchain.

## Blockers before calling it production-ready

1. External review of the server and of the Graviola patch.
2. Continuous fuzzing, including the channel state machine, in CI.
3. A deployment guide for supervision, log handling, and key rotation, tested on a real host.
4. Release workflow and signed releases; nothing has been published.

## Evidence

Not verified: a live GitHub session with the built client (`ssh -T git@github.com`, then a clone and
push of a private repository with a throwaway key) is an owner-run check, and no published release
has been downloaded and checked.

- The end-to-end suite (`test/e2e-git.sh`, 19 checks) passed on macOS arm64, on Linux arm64 and,
  on a native host with BMI1/AVX2, on Linux x86-64; on an emulated x86-64 CPU without BMI1/AVX2 the
  server refuses to start with a clear message.
- Two clean `--no-cache` builds of the Linux arm64 server are bit-for-bit identical.
