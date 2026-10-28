# ssh-build

OpenSSH 10.6p1 client built `--without-openssl` (macOS arm64, static-musl Linux x86_64/aarch64) plus
an experimental Graviola-only OxiSH Git server, shipped as separate ZIPs. Users read `README.md`.

## Commands

```sh
make macos | make linux DOCKER_PLATFORM=linux/arm64|amd64          # client
make oxish-macos | make oxish-linux DOCKER_PLATFORM=linux/arm64|amd64   # server
SSH_BIN_DIR=dist/macos/bin sh test/runtime.sh                       # client qualification
SSH_BIN_DIR=... OXISH_BIN_DIR=... sh test/e2e-git.sh                # server end to end
sh scripts/package.sh && sh scripts/package-oxish.sh                # dist/release
```

## Invariants

- One editable OpenSSH version string: `OPENSSH_VERSION=` in `scripts/fetch-sources.sh`.
- Every fetch fails closed on a SHA-256 or git revision; pins live in `sources.lock.json` and
  `git-build.lock.json`.
- Never commit `src/`, `dist/`, `.work/` or keys.
- Graviola is the only crypto provider in the server: `sh scripts/check-crypto-graph.sh`.
- `vendor/oxish` and `vendor/graviola` are reproducible: `sh scripts/vendor-oxish.sh verify` and
  `sh scripts/vendor-graviola.sh verify`. Edit `vendor/`, then run both `export` scripts.
- The server never executes a client-supplied program, path or environment variable, and every
  server crate forbids `unsafe`.
- Release qualification never uses the system `ssh` or `git`.
- Do not change the pinned nightly in `rust-toolchain.toml` unless the owner asks.

## Where things are

| Topic | Doc |
|---|---|
| Build, test, pins, packaging, vendoring, fuzzing | `docs/development.md` |
| Server trust boundary, review findings, limits of the claims | `SECURITY.md` |
| Running the client or server | `README.md` |
