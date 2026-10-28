# ssh-build

OpenSSL-free SSH distribution: OpenSSH 10.6p1 client built
`--without-openssl` (ssh, ssh-keygen, ssh-agent, ssh-add, sftp, scp) for
macOS arm64 + static-musl Linux (x86_64, aarch64), plus OxiSH/Graviola
`chacha20-poly1305@openssh.com` interop and non-PTY `exec` for Git hosting.

## Commands

```sh
sh scripts/fetch-sources.sh   # download + verify pins, extract to .work/sources
make macos                    # macOS client -> dist/macos/bin
make linux DOCKER_PLATFORM=linux/arm64   # dist/linux-aarch64/bin (linux/amd64 -> linux-x86_64)
SSH_BIN_DIR=dist/macos/bin sh test/runtime.sh  # functional qualification on final bytes
sh scripts/qualify-binaries.sh dist/<target>/bin  # linkage/static/hardening gates
sh scripts/package.sh         # dist/release: 3 ZIPs + manifests + verified SHA256SUMS
```

## Conventions

- Canonical version source is `scripts/fetch-sources.sh:4` (`OPENSSH_VERSION=`)
  plus `OPENSSH_SHA256`; Makefile, Dockerfile, and tests derive from it.
  Exactly one editable version string (`grep -rn` proves it).
- Every fetch fails closed on SHA-256 / git rev. Pins live in
  `sources.lock.json`. Never commit `src/`, `dist/`, `.work/`, or keys.
- `usr` lives at `~/usr`, not `~/d/usr`. No pushes, no releases from lanes.

## Rust

`rust-toolchain.toml` pins `nightly-2026-09-15` (rust-src, clippy) for all
OxiSH builds; run cargo from the repo root so rustup finds it. Do not change
the pin unless the owner asks. The server is Graviola-only:
`sh scripts/check-crypto-graph.sh` fails on any other provider in the release
graph or `Cargo.lock`; `vendor/oxish` is reproducible with
`sh scripts/vendor-oxish.sh verify`.

## Verified foundation (S0, from pinned source)

- OpenSSH `configure.ac:130`: `--without-openssl` exists (experimental).
- Without libcrypto, `cipher.c` offers only `aes128/192/256-ctr`
  (`CFLAG_AESCTR`) plus `chacha20-poly1305@openssh.com`; no GCM/RSA/ECDSA.
  OpenSSH 10.6 uses a libsodium ed25519 fallback when libcrypto is disabled.
- OxiSH rev `d81b20b7` graviola provider offers only
  `EncryptionAlgorithm::Aes128Gcm` (`oxish-graviola/src/lib.rs:153`):
  no shared packet cipher with the no-libcrypto client — S4 must add
  `chacha20-poly1305@openssh.com` using OpenSSH's raw ChaCha20+Poly1305
  packet construction (`cipher-chachapoly.c`), not RFC 7539 AEAD.
- OxiSH parses `exec` (`oxish-proto/src/channels.rs:230`) but the server
  drops it in the catch-all (`oxish/src/session/connections.rs:144`)
  — S5 must implement non-PTY exec.

## Loop timings (S0)

- `sh scripts/fetch-sources.sh` warm (reuse + verify): ≈0.1s.
- Cold fetch + extract: network-bound, one-time per machine.
- `test/runtime.sh` must keep `CARGO_HOME`/`RUSTUP_HOME` pointing at the real
  home: its isolated `HOME` otherwise makes cargo reinstall the toolchain.
- ZIP size budgets live in `release-budgets.json` and gate `package.sh`.
