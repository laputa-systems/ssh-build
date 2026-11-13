# Development

Run everything from the repository root. `.work/` is scratch, `dist/` is build output; neither is
committed.

## Pins and versions

- `sources.lock.json` (`schema_version` 1, an `inputs` list) pins OpenSSH, OxiSH and Graviola by
  `name`, `version` and `sha256`. The Makefile, Dockerfile, scripts and tests read the OpenSSH
  version and checksum and the OxiSH revision from it through `scripts/lock.sh`. To upgrade
  OpenSSH, change the `openssh` input, then rebuild. The `oxish` input's `sha256` is that of the
  GitHub archive of `rev`; `scripts/vendor-oxish.sh` verifies the git revision itself.
- `release-budgets.json` has `targets.<triple>.<product>.max_archive_bytes`.
- Every fetch fails closed on a SHA-256 or git revision. `git-build.lock.json` pins the git-build
  prerelease the end-to-end test uses; `scripts/fetch-git-build.sh` downloads its
  `git-<git_version>-<triple>.tar.xz` asset and checks it against the pin and `SHA256SUMS`.
- `rust-toolchain.toml` pins `nightly-2026-09-15`. Run cargo from the repository root so rustup
  finds it, and do not change the pin without the owner.

## Make targets

`TARGET` is a Rust triple (`aarch64-apple-darwin`, `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl`) and defaults to the host. `PRODUCT` is `ssh`, `oxish` or both
(default).

```sh
make fetch                                         # download, verify, extract to .work/sources
make build TARGET=aarch64-apple-darwin             # binaries, then package; archives in dist/release
make binaries PRODUCT=ssh TARGET=...               # only the binaries, in dist/<product>/<triple>/bin
make package TARGET=...                            # archives from finished binaries
make verify TARGET=...                             # SHA256SUMS, manifests, runtime and e2e on the unpacked archives
make lint                                          # script syntax, crypto-graph self-test, release audit
make clean                                         # dist, .work and Cargo target directories
```

Linux targets build in Docker for the target's platform; the macOS target builds on the host.
`verify` needs a host that runs `TARGET` natively and needs both products packaged.

## Client

```sh
make binaries PRODUCT=ssh TARGET=aarch64-apple-darwin   # dist/ssh/aarch64-apple-darwin/bin, deployment floor 14.0
sh scripts/qualify-binaries.sh dist/ssh/aarch64-apple-darwin/bin   # linkage, PIE, signature, floor, no libcrypto
SSH_BIN_DIR=dist/ssh/aarch64-apple-darwin/bin sh test/runtime.sh   # keygen, agent, config, sftp/scp, exec
TARGET=aarch64-apple-darwin sh scripts/package.sh       # dist/release/ssh-<version>-<triple>.tar.xz + .manifest.json
```

The Linux gates (`readelf`, static, no `PT_INTERP`) run inside the Docker build, and bytes that
fail them are never exported. `test/runtime.sh` must keep `CARGO_HOME` and `RUSTUP_HOME` pointing
at the real home, because its isolated `HOME` would otherwise make cargo reinstall the toolchain.
Every build writes `<bin_dir>/build-record.json` (`scripts/build-record.sh`): commit, a hash of
the build inputs, toolchain and executable hashes. `scripts/package.sh` and
`scripts/package-oxish.sh` refuse binaries without a record, with a changed executable, or built
from different inputs than the current tree (`ALLOW_DIRTY=1` permits a local package from an
uncommitted tree). They also refuse wrong-arch or non-static input and archives over
`release-budgets.json`, and replace the target's `dist/release` assets and the shared `SHA256SUMS`
only after the target passes.

`docker buildx build -f test/qualify-elf.Dockerfile --platform linux/arm64 .` checks that the
Linux qualifier rejects an executable stack and a missing RELRO segment.

## Server and OxiSH client tools

The `oxish` archive holds `bin/oxish-server`, `bin/oxish-session` (when the server build makes it),
`bin/oxish-keygen` and, when `client/` builds it, `bin/oxish`. `scripts/oxish-bins.sh` is the one
owner of that list: it names what a bin directory must hold, and every script, the Dockerfile and
`release.yml` read it. While the client binary does not exist the archive simply omits it. To make
a missing client fail the build record, packaging and the release job, set
`OXISH_CLIENT_REQUIRED=1` in `scripts/oxish-bins.sh` (the only edit needed). Also re-measure the
archive and update `release-budgets.json`; the client adds to every target.

`Dockerfile.oxish` and `scripts/build-oxish-macos.sh` build `vendor/oxish` and `client/` with the
same flags (static PIE on Linux, deployment floor 14.0 and ad-hoc signing on macOS) and qualify
every executable. `client/Cargo.toml` carries the release profile (fat LTO, one codegen unit,
stripped); the client keeps `panic = "unwind"` so terminal restoration can run in destructors.
`build-record.json` names the exact executable set, so a binary dropped into the directory later is
refused. The manifest lists the `executables`, and `make verify` checks they match the archive.

```sh
cargo test --locked --manifest-path client/Cargo.toml --test keygen   # oxish-keygen vs OpenSSH's ssh-keygen
SSH_BIN_DIR=... OXISH_BIN_DIR=... sh test/oxish-keygen.sh             # the same on the unpacked archives
sh scripts/check-crypto-graph.sh [--selftest]      # Graviola is the only provider (server and client: graph and Cargo.lock)
sh scripts/vendor-oxish.sh verify                  # vendor/oxish == pinned upstream + patches/oxish
sh scripts/vendor-graviola.sh verify               # vendor/graviola == pinned crate + patches/graviola
cargo test --locked --manifest-path vendor/oxish/Cargo.toml
make binaries PRODUCT=oxish TARGET=aarch64-apple-darwin   # dist/oxish/aarch64-apple-darwin/bin
TARGET=aarch64-apple-darwin sh scripts/package-oxish.sh    # dist/release/oxish-<version>-<triple>.tar.xz + .manifest.json
SSH_BIN_DIR=dist/ssh/aarch64-apple-darwin/bin OXISH_BIN_DIR=dist/oxish/aarch64-apple-darwin/bin sh test/e2e-git.sh
```

Login-mode tests (`login_`) drive the built OpenSSH client from `PATH` (or `OXISH_TEST_SSH`), so put
`dist/ssh/<triple>/bin` first on `PATH`; the one ECDSA test of Git mode needs an ECDSA-capable client
and `ssh-keygen`, which the OpenSSL-free build does not have. Run as an ordinary user, the privilege
test is skipped and the non-root refusal test runs. The privilege-drop test needs root: build the test
executable and `oxish-session`, copy them with the client to a world-readable directory, and run it
in a container (`OXISH_TEST_SESSION_BIN` names the session binary):

```sh
EXE=$(cargo test --locked --manifest-path vendor/oxish/Cargo.toml -p oxish --lib --no-run 2>&1 | sed -n 's/.*lib.rs (\(.*\))/\1/p')
mkdir -p /tmp/rt/bin && cp "$EXE" /tmp/rt/oxish-tests && cp vendor/oxish/target/debug/oxish-session /tmp/rt/ \
    && cp dist/ssh/<triple>/bin/ssh /tmp/rt/bin/ && chmod -R a+rX /tmp/rt
docker run --rm -v /tmp/rt:/rt:ro -e OXISH_TEST_SESSION_BIN=/rt/oxish-session -e PATH=/rt/bin:/usr/bin:/bin \
    alpine:3.24 /rt/oxish-tests login_
```

`test/e2e-git.sh` uses only the client under test, the server under test and the pinned git-build
binaries (`scripts/fetch-git-build.sh`, read-only, checksum-verified). It never falls back to the
system `ssh` or `git`. `test/linux-e2e.Dockerfile` runs it on Linux bytes inside a BuildKit step,
because `docker run` hangs on the macOS development machine; its header shows the build arguments.

The keygen test runs the `ssh-keygen` in `SSH_BIN_DIR` when set (the repository's OpenSSH build)
and otherwise the one on `PATH`; it fails rather than skips when none runs.

### Interactive end-to-end test

Linux only; it needs Docker (with buildx), `jaq`, and a network to fetch the pinned tmux sources and
ish release on first use. It runs the real `oxish --attach` client, `oxish-server --mode login` (as
root, with `oxish-session`) and `oxish-keygen` from the bin directory, against the pinned ish
(`ish.lock.json`, through `scripts/fetch-ish.sh`) and a static tmux built from `tmux.lock.json`. No
`ssh`, `git` or `tmux` of the host is used.

```sh
make binaries PRODUCT=oxish TARGET=x86_64-unknown-linux-musl
OXISH_BIN_DIR=dist/oxish/x86_64-unknown-linux-musl/bin sh test/e2e-interactive.sh
E2E_MODE=standin SSH_BIN_DIR=dist/ssh/x86_64-unknown-linux-musl/bin sh test/e2e-interactive.sh   # harness check with OpenSSH
```

`KEEP=1` leaves the server container and network after a failure; `DRIVER_ARGS` passes flags to
`test/interactive-driver.py` (`--show-screen`, and `--inject '1;2c'`, a self-test that must make the
run fail). `make verify` runs it on the unpacked archive of Linux targets. The scenario is in
`docs/interactive.md` phase 4; the one place that spells out the binaries' command lines is
`test/interactive-binaries.sh`.

It proves, with the screen of a terminal emulator inside the driver and tmux's own view as ground
truth: the client attaches tmux session `work` as the `work` account (ish login shell) over a
host-key-pinned Ed25519 connection and owns raw mode; after the TCP path between the containers is
cut for 8 s and restored, the same `oxish` process (same pid) reattaches the same tmux session on the
same server, the marker is still on screen and a counter that kept running server-side has advanced;
input typed during the outage is not replayed; no terminal-reply garbage is left at the prompt; typed
input works; a window resize reaches `tput cols`; when the tmux session ends the client exits with
the remote status 0 and the local terminal attributes are byte-identical to before the run. The
stand-in mode shares the harness but restarts the OpenSSH client itself, so it does not exercise the
reconnect assertions that are specific to `oxish --attach`.

`Dockerfile.oxish` links Rust with Alpine's gcc and musl rather than Rust's bundled start files:
the bundled ones crash static-PIE binaries at startup. Two clean builds of the Linux arm64 server
are byte-identical.

## Vendored sources

`vendor/oxish` is `https://github.com/djc/oxish` at the `oxish` input's `rev` plus `patches/oxish`, and
`vendor/graviola` is the `graviola` crate from crates.io (SHA-256 pinned) plus `patches/graviola`.
Both are `Apache-2.0 OR MIT` or `Apache-2.0 OR ISC OR MIT-0` (SPDX headers and `Cargo.toml`);
`vendor/oxish/LICENSE-*` are upstream's.

- From OxiSH we carry the workspace, the crates, `fuzz/`, `deny.toml`, `README.md` and
  `openssh-vulnerabilities.md`; `.github`, `codecov.yml`, `dist-workspace.toml` and
  `CONTRIBUTING.md` are dropped.
- Edit `vendor/` freely, then run both `export` scripts. The patches are what reviewers read and
  `verify` is the gate. Never change `vendor/graviola` beyond the SSH packet module
  (`vendor/graviola/src/mid/ssh_chacha20poly1305.rs`) and its manifest.
- Moving to a new revision is an explicit edit of the pin followed by a reviewed `export`.
- `vendor/oxish/oxish-graviola/tests/openssh-chachapoly.vectors` holds packets sealed by OpenSSH's
  own `chachapoly_crypt`; `sh scripts/gen-chachapoly-vectors.sh` regenerates them from the pinned
  OpenSSH build (`make binaries PRODUCT=ssh` on macOS first).
- Fuzz targets live in `vendor/oxish/fuzz` (`cargo fuzz run <target>`); `channel_state`
  drives the channel state machine via the hidden `oxish::fuzz_channel_state` entry.
  `.github/workflows/fuzz.yml` runs all six targets on pull requests, pushes, and nightly.

## CI and releases

`.github/workflows/lint.yml` (`make lint`: script syntax, the crypto-graph self-test, and
`scripts/audit-release.sh`) and `test.yml` (vendor and crypto-graph checks plus the server tests on
macOS arm64 and Linux arm64/x86-64) run on pull requests and pushes to `master`. Those tests skip
the hybrid post-quantum handshake when the runner's `ssh` cannot offer it; `test/e2e-git.sh` in the
release job requires it.

`release.yml` is a manual dispatch that refuses non-default branches. Each of three native jobs
runs `make build TARGET=<triple>` (client and server, packaged as `.tar.xz` plus
`.manifest.json`) and `make verify TARGET=<triple>`, which unpacks the archives and runs
`test/runtime.sh` and `test/e2e-git.sh` on those bytes. The release job then requires exactly the
twelve expected assets, every manifest to name `GITHUB_SHA` and the `sources.lock.json` digest with
`build_dirty` false, fully static and hardened Linux ELFs, and a verified consolidated
`SHA256SUMS`, and only then creates the tag `release-<sha>` through the API and a pre-release
with `--verify-tag` and generated release notes. Actions are pinned to the SHAs approved in
repomod's `actions.toml`; `scripts/install-jaq.sh` installs the pinned `jaq` the scripts need.
`sh scripts/audit-release.sh` checks the workflow's contract locally. The `dl` installer
consumes the assets and has to follow their names.

The workflows were checked with actionlint. The full workflow has not run on GitHub in the
`.tar.xz` layout.
