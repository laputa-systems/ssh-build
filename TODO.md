Prefix: SSHB
Next: 2

### SSHB-1 · P2 · The fuzz workflow fails before fuzzing because its runner has no jaq

- **Area:** Build
- **Where:** `.github/workflows/fuzz.yml:34`, `scripts/vendor-oxish.sh:20`, `.github/workflows/test.yml:33`
- **Problem:** The "Vendored sources match their pins and patches" step runs `sh scripts/vendor-oxish.sh verify`, which reads `sources.lock.json` with `jaq`. Unlike `test.yml`, `lint.yml` and `release.yml`, `fuzz.yml` has no "Install jaq" step, so the script stops with `jaq: not found` (exit 127) and no fuzz target runs. Every fuzz run since `bc2a9fb` has failed this way, including the nightly schedule, the pull request for #2 and the push of `c6e8e61`.
- **Recommendation:** Add the same "Install jaq" step (`sh scripts/install-jaq.sh "$RUNNER_TEMP/bin"` and its `PATH` entry) before the vendor check in `fuzz.yml`.
- **Fix with:** none
- **Effort:** S
