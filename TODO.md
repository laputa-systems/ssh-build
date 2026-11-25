Prefix: SSHB
Next: 8

### SSHB-2 · P1 · Interactive client with PTY, shell and terminal frontend

- **Area:** interactive client
- **Where:** `client/`
- **Problem:** The client lacks PTY, shell, window-change handling and a terminal frontend.
- **Recommendation:** Implement the interactive client and qualify its terminal behavior as described in the design.
- **Fix with:** none
- **Effort:** L
- **Design:** [Interactive SSH plan, phase 1](docs/interactive.md#1-interactive-client-sshb-2)

### SSHB-3 · P1 · Reconnecting tmux attachment in the client

- **Area:** interactive client
- **Where:** `client/`
- **Problem:** Reconnecting tmux attachment needs integration qualification.
- **Recommendation:** Implement reconnecting tmux attachment as described in the design. Depends on SSHB-2.
- **Fix with:** none
- **Effort:** L
- **Design:** [phase 2](docs/interactive.md#2-reconnecting-terminal-sshb-3)

### SSHB-4 · P1 · Login-mode OxiSH server with privilege-separated sessions

- **Area:** server
- **Where:** `vendor/oxish` through `patches/oxish`
- **Problem:** Login mode needs privilege-separated sessions and qualification on Asterinas.
- **Recommendation:** Complete and qualify the login-mode server as described in the design while preserving Git mode.
- **Fix with:** none
- **Effort:** L
- **Design:** [phase 3](docs/interactive.md#3-login-mode-server-sshb-4)

### SSHB-5 · P1 · Interactive end-to-end test with ish and tmux

- **Area:** interactive testing
- **Where:** `test/e2e-interactive.sh`
- **Problem:** Interactive client and server behavior needs end-to-end qualification with ish and tmux.
- **Recommendation:** Implement the integration test described in the design. Depends on SSHB-2, SSHB-3, SSHB-4.
- **Fix with:** none
- **Effort:** L
- **Design:** [phase 4](docs/interactive.md#4-integration-test-sshb-5)

### SSHB-6 · P2 · Ship client, server, session helper and keygen in the oxish archive

- **Area:** release
- **Where:** oxish archive
- **Problem:** The oxish archive needs to ship the client, server, session helper and keygen.
- **Recommendation:** Package and qualify the archive for all three targets as described in the design.
- **Fix with:** none
- **Effort:** M
- **Design:** [phase 5](docs/interactive.md#5-release-sshb-6)

### SSHB-7 · P2 · Laputa consumes the oxish archive and removes Dropbear

- **Area:** Laputa integration
- **Where:** Laputa
- **Problem:** Laputa needs to consume the oxish archive and replace Dropbear.
- **Recommendation:** Migrate Laputa as described in the design. Depends on SSHB-4, SSHB-6.
- **Fix with:** none
- **Effort:** L
- **Design:** [phase 6](docs/interactive.md#6-laputa-consumes-ssh-build-dropbear-removed-sshb-7)
