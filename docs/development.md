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
  prerelease the end-to-end test uses; it points at a release in git-build's earlier ZIP layout
  (`git-<triple>.zip`) and `scripts/fetch-git-build.sh` still expects those names.
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

## Server

```sh
sh scripts/check-crypto-graph.sh [--selftest]      # Graviola is the only provider (graph and Cargo.lock)
sh scripts/vendor-oxish.sh verify                  # vendor/oxish == pinned upstream + patches/oxish
sh scripts/vendor-graviola.sh verify               # vendor/graviola == pinned crate + patches/graviola
cargo test --locked --manifest-path vendor/oxish/Cargo.toml
make binaries PRODUCT=oxish TARGET=aarch64-apple-darwin   # dist/oxish/aarch64-apple-darwin/bin
TARGET=aarch64-apple-darwin sh scripts/package-oxish.sh    # dist/release/oxish-<version>-<triple>.tar.xz + .manifest.json
SSH_BIN_DIR=dist/ssh/aarch64-apple-darwin/bin OXISH_BIN_DIR=dist/oxish/aarch64-apple-darwin/bin sh test/e2e-git.sh
```

`test/e2e-git.sh` uses only the client under test, the server under test and the pinned git-build
binaries (`scripts/fetch-git-build.sh`, read-only, checksum-verified). It never falls back to the
system `ssh` or `git`. `test/linux-e2e.Dockerfile` runs it on Linux bytes inside a BuildKit step,
because `docker run` hangs on the macOS development machine; its header shows the build arguments.

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
