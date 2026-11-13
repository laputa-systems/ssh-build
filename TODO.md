Prefix: SSHB
Next: 8

### SSHB-2 · P1 · Interactive client with PTY, shell and terminal frontend
- **Design:** [Interactive SSH plan, phase 1](docs/interactive.md#1-interactive-client-sshb-2)
- **Where:** `client/`

### SSHB-3 · P1 · Reconnecting tmux attachment in the client
- **Design:** [phase 2](docs/interactive.md#2-reconnecting-terminal-sshb-3)
- **Depends on:** SSHB-2

### SSHB-4 · P1 · Login-mode OxiSH server with privilege-separated sessions
- **Design:** [phase 3](docs/interactive.md#3-login-mode-server-sshb-4)
- **Where:** `vendor/oxish` through `patches/oxish`

### SSHB-5 · P1 · Interactive end-to-end test with ish and tmux
- **Design:** [phase 4](docs/interactive.md#4-integration-test-sshb-5)
- **Depends on:** SSHB-2, SSHB-3, SSHB-4

### SSHB-6 · P2 · Ship client, server, session helper and keygen in the oxish archive
- **Design:** [phase 5](docs/interactive.md#5-release-sshb-6)

### SSHB-7 · P2 · Laputa consumes the oxish archive and removes Dropbear
- **Design:** [phase 6](docs/interactive.md#6-laputa-consumes-ssh-build-dropbear-removed-sshb-7)
- **Depends on:** SSHB-4, SSHB-6
