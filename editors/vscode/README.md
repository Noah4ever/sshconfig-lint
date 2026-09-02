# sshconfig-lint for VS Code

Semantic diagnostics for OpenSSH client configs. The extension uses the same Rust engine as the CLI and GitHub Action.

## What it checks

- invalid ports, counters, time values, masks, and documented option values
- duplicate `Host` blocks, directives, and wildcard ordering
- missing identity, certificate, and revoked-host-key files
- weak algorithms, unsafe options, and unsafe `ControlPath` values
- nested `Include` files, unreadable includes, bad globs, and cycles
- proxy conflicts, ineffective local commands, and invalid percent tokens

The matching release binary is downloaded once, verified with SHA256, and reused offline. No telemetry is collected. Set `sshconfigLint.binaryPath` when you prefer a system installation.

The extension recognizes `.ssh/config`, `ssh_config`, and `dot_ssh/config`. Add repository-specific paths with `sshconfigLint.additionalFilePatterns`.

Use **sshconfig-lint: Open Rule Guide** from the Command Palette to open the
focused guide for any public diagnostic. **Restart Language Server** and
**Show Version** are available there as well.
