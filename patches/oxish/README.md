# OxiSH vendor provenance

`vendor/oxish` is `https://github.com/djc/oxish` at the revision pinned by
`OXISH_REV` in `scripts/fetch-sources.sh` (mirrored in `sources.lock.json`),
plus the patches in this directory. Upstream is licensed `MIT OR Apache-2.0`;
`vendor/oxish/LICENSE-MIT` and `LICENSE-APACHE` are carried unchanged.

Carried from upstream: workspace manifests and lockfile, the four crates, the
`fuzz/` harness, `deny.toml`, `openssh-vulnerabilities.md`, and `README.md`.
Dropped: `.github`, `codecov.yml`, `dist-workspace.toml`, `CONTRIBUTING.md`.

Patches are grouped by component and apply in filename order with
`patch -p1`. `sh scripts/vendor-oxish.sh verify` rebuilds the tree from the
pinned upstream plus these patches and fails on any difference.
`sh scripts/vendor-oxish.sh export` regenerates them after an intentional edit
to `vendor/oxish`. Moving to a new upstream revision is an explicit edit of
`OXISH_REV` and `sources.lock.json` followed by a reviewed `export`.

## Graviola

`vendor/graviola` is the `graviola` 0.4.1 crate from crates.io (SHA-256 pinned in
`sources.lock.json`; licensed `Apache-2.0 OR ISC OR MIT-0`, per the SPDX headers and
`Cargo.toml`) plus `patches/graviola`. The patch adds `graviola::aead::SshChaCha20Poly1305`, the
OpenSSH `chacha20-poly1305@openssh.com` packet construction built on Graviola's own ChaCha20 and
Poly1305, drops the unvendored test targets and the `aws-lc-rs` dev-dependency, and changes
nothing else. `sh scripts/vendor-graviola.sh verify` reproduces the tree from the pinned crate.
The vendor workspace selects it with `[patch.crates-io]`.

`vendor/oxish/oxish-graviola/tests/openssh-chachapoly.vectors` holds packets sealed by OpenSSH's
own `chachapoly_crypt`, regenerated with `sh scripts/gen-chachapoly-vectors.sh` from the pinned
OpenSSH build.
