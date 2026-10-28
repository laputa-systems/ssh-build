# Campaign: OpenSSL-free SSH client + OxiSH interop

## Status

Goal: OpenSSH 10.6p1 client without libcrypto (ssh, ssh-keygen, ssh-agent,
ssh-add, sftp, scp) for macOS arm64 + static musl Linux (x86_64, aarch64),
plus OxiSH/Graviola chacha20-poly1305@openssh.com + non-PTY exec for Git.
Base: uncommitted `plan.md` only, branch `master`, tree otherwise empty.
Accepted: none yet (preflight). Red: none on the integration branch.
Next: S0. Resume: pick the next open item in **Sequence**, brief per the
orchestrate run-a-slice contract, steer after each accept.
Launch prompt: `Run the next open slice of plan.md in /Users/josh/d/ssh-build;
brief per orchestrate, land green only, steer after each accept.`

## Charter

- Decide and keep going. Record a decision only when a later slice depends on it.
- Proceed without waiting inside the grant. Park items needing outside authority.
- Hard stops park the item: irreversible/outside-repo action, a doc boundary,
  or a loop with nothing checkable. Pushing is always forbidden.
- Fix egregious breakage met on the way in its own commit to stated numeric
  thresholds; park anything estimated over 30 min.
- Parity and completeness before optimization; product-performance budgets are
  measured and logged, not gating, until S6.
- One writer by default. Parallel lanes only for the disjoint pairs named in
  **Sequence**, in worktrees at `.work/wt/<lane>`, never `/tmp` or `$TMPDIR`,
  following the orchestrate worktree lifecycle.
- A failing item gets 3 attempts, then parks on its branch with cause and a
  retry condition. Cause before retry; never requeue an unchanged failure.
- Every commit is a Conventional Commit with the workstream as scope
  (`ssh-client:`, `oxish:`, `dist:`); the item ID goes in the body.
  Code comments never cite this doc.

## Decisions

Owner-decided (2026-10-28):
- Combined campaign: OpenSSH client and OxiSH interop land here, not split.
- Full client set: ssh, ssh-keygen, ssh-agent, ssh-add, sftp, scp. sshd and
  server helpers are out (see non-goals).
- Platform matrix matches git-minimal: macOS arm64 + static-musl Linux x86_64
  and aarch64, distributed as versioned ZIPs installable via `usr/dl`.
- Draft cipher/KEX claims are not taken as given; S0 proves them from source.

Prescribed:
- OpenSSH pin is 10.6p1 (verified released 2026-10-06; `--without-openssl`
  unaffected per 10.5 notes; 10.6 uses a libsodium ed25519 fallback when
  libcrypto is disabled). S0 pins the tarball SHA-256 (hex, from a mirror)
  and the OxiSH + Graviola revs with the same rigor; every fetch fails closed.
- Canonical version source is `scripts/fetch-sources.sh` (`OPENSSH_VERSION=`
  plus archive SHA); Makefile, Dockerfile, and tests derive from it. Single
  editable version string, proven by grep.
- No-libcrypto proof is linkage + symbol evidence (`otool -L`, `readelf`,
  `nm`), never configure-log claims alone. Static-musl proof is
  `readelf`-based (no `PT_INTERP`/`DT_NEEDED`), as in git-minimal.
- SSH chacha work implements `chacha20-poly1305@openssh.com` packet
  construction, not raw RFC 7539; it needs test vectors plus a cross-impl
  handshake against the S1 client before it counts as interoperable.
- OxiSH exec means non-PTY `exec` with stdin/stdout/stderr forwarding,
  exit-status propagation, and command restriction suitable for
  `git-upload-pack` / `git-receive-pack`.
- `usr` lives at `~/usr` (not `~/d/usr`); `dl ssh` follows the `codex` bundle
  precedent: versioned dir, temp-link + atomic `mv`, `readlink` guard.
- Default branch is `master`. The executor never pushes, dispatches workflows,
  creates tags/releases, or enables the `dl` default set.

Delegated (bound in parentheses):
- Exact OpenSSH configure flags (must include `--without-openssl`, client-only
  selection, and hardened flags; never `-march=native`).
- Manifest and `release-budgets.json` fields (must include upstream version,
  archive SHA-256, target triple, build commit, toolchain versions).
- OxiSH patch shape: vendor subtree vs patch file (must keep provider
  abstraction intact; default remains Graviola-only via
  `--no-default-features --features graviola`).

## Baseline

- Greenfield: no Makefile, Dockerfile, tests, or sources yet. No known red;
  the integration branch has no commits and `plan.md` is staged uncommitted.
- Loop timings at preflight: `mdtool check --untracked plan.md` ≈0.2s;
  `rg` link scan instant. First clean builds are the long pole (minutes);
  S0 records real `make macos` / Docker timings. Docker daemon is up
  (OrbStack 27.3.1 at preflight).
- Unverified at preflight: every OxiSH/Graviola claim (no checkout in `~/d`;
  `mdtool` flags `oxish-graviola/src/lib.rs` as another repo) and the exact
  `--without-openssl` algorithm subset. S0 proves or corrects them from source
  before later slices build on them.

## Sequence

Serial within a workstream (shared files); parallel only across the pairs in
(PAR). Each item ends on its acceptance command on the integrated tree, then
the parent steering checkpoint; red work never lands.

- S0 — Pin sources, prove the foundation. Owns: `scripts/fetch-sources.sh`
  (new), `sources.lock.json` (new), `AGENTS.md` (new). Prereq: none. Accept:
  `sh scripts/fetch-sources.sh` verifies both pins fail-closed; `grep` shows
  `--without-openssl` in OpenSSH `configure.ac`, the no-libcrypto cipher/KEX
  subset in `cipher.c`/`kex.c`, and OxiSH's actual cipher list + exec-request
  handling; loop timings recorded in AGENTS.md. (PAR: none; all later slices
  read its pins.)
- S1 — OpenSSH macOS client, full set, no libcrypto. Owns: `Makefile`,
  `scripts/build-macos.sh` (new), `src/` pinned source. Prereq: S0. Accept:
  `make macos` green; `dist/macos/bin/ssh -V` reports 10.6p1;
  `otool -L` shows system-only dylibs and `nm` shows no libcrypto symbols.
  (PAR: S4)
- S2 — Static-musl Linux client via Docker. Owns: `Dockerfile` (new),
  `scripts/qualify-binaries.sh` (new). Prereq: S0. Accept:
  `make linux DOCKER_PLATFORM=linux/arm64` green (and amd64 when the lane can);
  qualify script green on `readelf` static/linkage evidence + no-libcrypto
  symbols. Daemon-down bytes park per **Needs environment**. (PAR: S5)
- S3 — Local functional qualification. Owns: `test/runtime.sh` (new).
  Prereq: S1, S2. Accept: `sh test/runtime.sh` green against final bytes:
  keygen (Ed25519), config/known_hosts parsing, encrypted-key unlock,
  agent add/list, loopback exec + sftp/scp transfer. Live-GitHub proof is
  **Needs environment**, not this gate. (PAR: S4, S5)
- S4 — OxiSH chacha20-poly1305@openssh.com via Graviola. Owns:
  `vendor/oxish/` or `patches/`, `oxish` test files. Prereq: S0. Accept:
  `cargo test -p oxish-graviola chacha` green on vectors + `sh
  test/oxish-chacha-interop.sh` (new, owned here) completes a handshake
  against the S1 client loopback. (PAR: S1, S3)
- S5 — OxiSH non-PTY exec for Git. Owns: OxiSH server exec files
  (under S4's tree), `test/oxish-exec.sh` (new). Prereq: S4. Accept:
  `sh test/oxish-exec.sh` green: `git-upload-pack`/`git-receive-pack` over
  the S1 client with correct stdio, exit status, and rejection of
  non-Git commands. (PAR: S2)
- S6 — Packaging, budgets, docs, `dl` bundle. Owns: `scripts/package.sh`
  (new), `release-budgets.json` (new), `README.md` (new), `AGENTS.md`,
  installer in `~/usr` (`dl`, `dotfiles/dl-test.sh`). Prereq: S3, S5.
  Accept: `sh scripts/package.sh` writes 3 ZIPs + manifest + verified
  `SHA256SUMS`; `sh test/runtime.sh` green against the extracted ZIP;
  `sh dotfiles/dl-test.sh` green with `HOME` under `.work/`. (PAR: none)
- S7 — Close: delete dead code, `ultrareview`, final report. Prereq: all.
  Accept: no dead vendored/patch paths unreferenced; `ultrareview` P1/P2
  findings fixed; full suite (`test/runtime.sh` + qualify + oxish tests)
  green on the integrated tree.

## Acceptance

- Three targets build: `make macos` + `make linux` per matrix triple green;
  `test/runtime.sh` green on final bytes (keygen, config, known_hosts,
  encrypted key, agent, sftp/scp, loopback exec).
- Every dependency pinned and verified: single version source in
  `scripts/fetch-sources.sh`; archive SHA-256 enforced fail-closed.
- No libcrypto/libssl in any artifact: `otool -L`/`nm` (macOS) and
  `readelf`/`nm` (Linux) evidence via `scripts/qualify-binaries.sh`.
- Linux ELF static-musl: correct arch, no `PT_INTERP`/`DT_NEEDED`,
  non-executable stack, no W+X, musl loader only, no glibc.
- macOS Mach-O: arch, PIE, deployment floor, system-only dylibs, valid
  signature after strip.
- OxiSH interop: chacha handshake against the S1 client + Git exec
  (`upload-pack`/`receive-pack`, stdio, exit status, command restriction).
- Release: 3 ZIPs + manifest + consolidated verified `SHA256SUMS`;
  `dl ssh` installs/updates atomically, failures preserve the prior install.
- Budgets in `release-budgets.json` measured and logged (gating only in S6).

## Needs environment

Not blocking local completion; each with the owner's command:
- Live GitHub: with a throwaway Ed25519 key, `ssh -T git@github.com` plus a
  private-test-repo clone/fetch/push over the S1/S2 binaries. Private keys
  never enter the repo; this proof stays owner-run.
- Linux bytes if the daemon stays down: `docker info && make linux` per
  platform, then `sh scripts/qualify-binaries.sh dist`.
- Publish: `gh workflow run release.yml --ref master`, download 3 ZIPs +
  `SHA256SUMS`, `sha256sum -c SHA256SUMS`, inspect arch/linkage. Native
  per-arch proof comes from CI runners.

## Execution boundary and non-goals

Authorized: edits in this repo (+ `~/usr` installer files in S6), worktrees
under `.work/wt/<lane>`, local builds, starting the local Docker daemon,
`cargo test`, loopback ssh fixtures with throwaway keys.
Forbidden: push, workflow dispatch, tag/release creation, enabling the `dl`
default set early, private keys or secrets in the repo, new dependencies
without a pinned version + SHA + license record + gate-impact note,
`-march=native`, generated binaries in the repo, `|| true` on gates,
weakening any check to pass. Contract changes for the owner: none yet beyond
the new `dl ssh` bundle member (after publish) and the OxiSH cipher/exec
surface (S4/S5 write-up due in S6).
Non-goals: sshd/server distribution, RSA/ECDSA compat beyond what
`--without-openssl` retains, HTTPS remotes, glibc/Intel/universal builds,
a Graviola-backed Rust client (future lane), production qualification of
OxiSH as a public Git server.

## Reference

- Precedent (`/Users/josh/d/git-minimal-musl-static`, `master`): `Makefile:5`
  version derivation, `scripts/download-git-source.sh:4` canonical version,
  `test/runtime.sh:11` version derivation, `Makefile:3` platform default.
  Matrix: macOS arm64, musl x86_64/aarch64; ZIP + manifest + `SHA256SUMS`
  convention and `readelf`-based qualify script shape (see its campaign doc).
- Locks (`/Users/josh/d/python-build`): `sources.lock.json`,
  `bootstrap.lock.json` pin-and-verify pattern for S0.
- Verified upstream: OpenSSH 10.6p1 released 2026-10-06
  (`https://www.openssh.com/releasenotes.html`); draft favicon/image links
  and the `cipher.c` / `oxish-graviola/src/lib.rs` path claims are
  superseded until S0 re-verifies them from pinned source.
