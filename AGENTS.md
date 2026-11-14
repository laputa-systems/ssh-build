# ssh-build

OpenSSH 10.6p1 client built `--without-openssl` (macOS arm64, static-musl Linux x86_64/aarch64) plus
Graviola-only OxiSH tools (a server with Git and login modes, the interactive `oxish` client, the
`oxish-sftp` and `oxish-scp` SFTP clients and `oxish-keygen`), shipped as separate `.zip` archives. Users read `README.md`.

## Commands

```sh
make build TARGET=<triple> [PRODUCT=ssh|oxish]   # build and package into dist/release
make verify TARGET=<triple>                       # unpack the archives, run runtime and e2e tests
make fetch | package | lint | clean
SSH_BIN_DIR=dist/ssh/<triple>/bin sh test/runtime.sh                # client qualification
SSH_BIN_DIR=... OXISH_BIN_DIR=... sh test/e2e-git.sh                # server end to end
```

## Invariants

- One editable OpenSSH version: the `openssh` input in `sources.lock.json`.
- Every fetch fails closed on a SHA-256 or git revision; pins live in `sources.lock.json` and
  `git-build.lock.json`. `git-build.lock.json` pins a git-build release (tar.xz layout) fetched
  for the Git end-to-end tests; ssh-build itself ships `.zip` archives.
- Never commit `src/`, `dist/`, `.work/` or keys.
- Graviola is the only crypto provider in the server and client: `sh scripts/check-crypto-graph.sh`.
- `scripts/oxish-bins.sh` owns the `oxish` archive's executable list and `OXISH_CLIENT_REQUIRED`.
- `vendor/oxish` and `vendor/graviola` are reproducible: `sh scripts/vendor-oxish.sh verify` and
  `sh scripts/vendor-graviola.sh verify`. Edit `vendor/`, then run both `export` scripts.
- Git mode never executes a client-supplied program, path or environment variable. Login mode
  runs a client-supplied command string only through the authenticated account's own shell
  (`shell -c`) after the session process has dropped to that account, with the fixed environment
  in `SECURITY.md`. Every server crate forbids `unsafe`.
- Release qualification never uses the system `ssh` or `git`.
- Do not change the pinned nightly in `rust-toolchain.toml` unless the owner asks.

## Where things are

| Topic | Doc |
|---|---|
| Build, test, pins, packaging, vendoring, fuzzing | `docs/development.md` |
| Server trust boundary, review findings, limits of the claims | `SECURITY.md` |
| Running the client or server | `README.md` |
