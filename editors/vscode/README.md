# sshconfig-lint for VS Code

Semantic diagnostics for OpenSSH client configs. The extension uses the same Rust engine as the CLI and GitHub Action.

## What it checks

- duplicate `Host` blocks and directives
- `Host *` ordering
- missing `IdentityFile` paths
- weak algorithms and unsafe options
- nested `Include` files and cycles
- unsafe `ControlPath` values

The matching release binary is downloaded once, verified with SHA256, and reused offline. No telemetry is collected. Set `sshconfigLint.binaryPath` when you prefer a system installation.

The extension recognizes `.ssh/config`, `ssh_config`, and `dot_ssh/config`. Add repository-specific paths with `sshconfigLint.additionalFilePatterns`.
