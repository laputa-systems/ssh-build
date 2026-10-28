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
