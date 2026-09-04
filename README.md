# sshconfig-lint

[![Tests](https://github.com/Noah4ever/sshconfig-lint/actions/workflows/tests.yml/badge.svg)](https://github.com/Noah4ever/sshconfig-lint/actions/workflows/tests.yml)
[![crates.io](https://img.shields.io/crates/v/sshconfig-lint.svg)](https://crates.io/crates/sshconfig-lint)
[![License: MIT](https://img.shields.io/badge/license-MIT-black.svg)](LICENSE)

**One engine for every place your SSH config changes.**

sshconfig-lint finds semantic mistakes in OpenSSH client configs: duplicate hosts, broken identity paths, unsafe options, weak algorithms, wildcard ordering, and tangled `Include` chains. Use the same rule codes locally, in Git hooks, GitHub Actions, and editors.

[Try the private browser playground](https://sshconfig-lint.apps.thiering.org/en) · [Learn with interactive examples](https://sshconfig-lint.apps.thiering.org/en/learn) · [Read every rule](https://sshconfig-lint.apps.thiering.org/en/rules)

The browser checker runs on your device. Config contents are not uploaded and no telemetry is collected.

## Quick start

```bash
# check ~/.ssh/config
sshconfig-lint

# check one or more repository configs
sshconfig-lint .ssh/config infrastructure/ssh_config

# fail on warnings and errors
sshconfig-lint .ssh/config --strict
```

## Install

### Homebrew

```bash
brew tap Noah4ever/tap
brew install sshconfig-lint
```

### Cargo

```bash
cargo install sshconfig-lint
```

### Arch Linux

```bash
yay -S sshconfig-lint-bin
```

The [release page](https://github.com/Noah4ever/sshconfig-lint/releases) provides verified binaries for Linux, macOS, and Windows. The convenience installer verifies the release checksum before installing:

```bash
curl -fsSL https://raw.githubusercontent.com/Noah4ever/sshconfig-lint/main/install.sh | bash
```

Set `VERSION=v0.5.0` or `INSTALL_DIR=~/.local/bin` to override the defaults.

## GitHub Actions

The official Action is available in the
[GitHub Marketplace](https://github.com/marketplace/actions/sshconfig-lint).

```yaml
name: SSH config
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Noah4ever/sshconfig-lint@v1.0.0
        with:
          paths: |
            .ssh/config
            infrastructure/ssh_config
          strict: true
```

Findings appear as annotations on the exact file and line. The Action downloads the release matching its tag and verifies `SHA256SUMS` before execution.

For repositories with GitHub Code Scanning enabled, SARIF can be uploaded separately:

```yaml
- run: sshconfig-lint .ssh/config --format sarif > sshconfig-lint.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sshconfig-lint.sarif
```

## Pre-Commit

```yaml
repos:
  - repo: https://github.com/Noah4ever/sshconfig-lint
    rev: v1.0.0
    hooks:
      - id: sshconfig-lint-strict
```

Use `id: sshconfig-lint` when warnings should not block a commit. Override `files:` in your project when configs use another naming convention.

## Editors

### VS Code

Install the [VS Code extension](https://marketplace.visualstudio.com/items?itemName=NoahThiering.sshconfig-lint) from the Marketplace or run:

```bash
code --install-extension NoahThiering.sshconfig-lint
```

The extension starts `sshconfig-lint lsp`, downloads a matching verified binary once, and then works offline. It recognizes `.ssh/config`, `ssh_config`, and chezmoi's `dot_ssh/config`. No telemetry is collected. Its source is available in [`editors/vscode`](editors/vscode).

### Neovim

The tested [`editors/neovim`](editors/neovim) example uses Neovim's built-in
LSP client. Copy its small Lua module into your configuration and start it with:

```lua
require("sshconfig_lint").setup()
```

It uses the same `sshconfig-lint lsp` server as VS Code and supports a custom
binary path.

Any editor with LSP support can start:

```bash
sshconfig-lint lsp
```

The v0.5 language server publishes full-line diagnostics on open, change, and save. Untitled buffers run content-only rules; saved files additionally resolve `Include` and filesystem paths. Findings from nested Includes are attached to the included file and cleared with the root document.

## Output formats

```bash
sshconfig-lint --format text
sshconfig-lint --format json
sshconfig-lint --format github
sshconfig-lint --format sarif
```

JSON findings contain `severity`, `code`, `rule`, `line`, `file`, `message`, `hint`, and `documentation`. Rule codes and exit codes are stable automation interfaces.

| Exit | Meaning |
|---:|---|
| `0` | No error-level finding, and no warnings with `--strict` |
| `1` | At least one blocking finding |
| `2` | At least one requested config could not be read |

## Rules

| Code | Rule | Severity |
|---|---|---|
| `INVALID_VALUE` | [Invalid directive value](https://sshconfig-lint.apps.thiering.org/en/rules/invalid-directive-value) | error |
| `DUP_HOST` | [Duplicate Host block](https://sshconfig-lint.apps.thiering.org/en/rules/duplicate-host) | warning |
| `MISSING_IDENTITY` | [IdentityFile not found](https://sshconfig-lint.apps.thiering.org/en/rules/identity-file-exists) | error |
| `WILDCARD_ORDER` | [Host wildcard order](https://sshconfig-lint.apps.thiering.org/en/rules/wildcard-host-order) | warning |
| `WEAK_ALGO` | [Weak algorithm](https://sshconfig-lint.apps.thiering.org/en/rules/deprecated-weak-algorithms) | warning |
| `DUP_DIRECTIVE` | [Duplicate directive](https://sshconfig-lint.apps.thiering.org/en/rules/duplicate-directives) | warning |
| `INSECURE_OPT` | [Insecure option](https://sshconfig-lint.apps.thiering.org/en/rules/insecure-option) | warning |
| `UNSAFE_CTRL_PATH` | [Unsafe ControlPath](https://sshconfig-lint.apps.thiering.org/en/rules/unsafe-control-path) | warning |
| `INCLUDE_CYCLE` | [Include cycle](https://sshconfig-lint.apps.thiering.org/en/rules/include-cycle) | error |
| `INCLUDE_DEPTH` | [Include nesting too deep](https://sshconfig-lint.apps.thiering.org/en/rules/include-depth) | error |
| `INCLUDE_READ` | [Include cannot be read](https://sshconfig-lint.apps.thiering.org/en/rules/include-read) | error |
| `INCLUDE_GLOB` | [Invalid Include pattern](https://sshconfig-lint.apps.thiering.org/en/rules/include-glob) | error |
| `INCLUDE_NO_MATCH` | [Include matches no files](https://sshconfig-lint.apps.thiering.org/en/rules/include-no-match) | info |
| `NEGATED_HOST` | [Host has only negated patterns](https://sshconfig-lint.apps.thiering.org/en/rules/negated-only-host) | warning |
| `PROXY_CONFLICT` | [ProxyCommand and ProxyJump conflict](https://sshconfig-lint.apps.thiering.org/en/rules/proxy-command-jump-conflict) | warning |
| `REVOKED_HOST_KEYS_UNREADABLE` | [RevokedHostKeys file is unreadable](https://sshconfig-lint.apps.thiering.org/en/rules/revoked-host-keys-readable) | error |
| `MISSING_CERTIFICATE` | [CertificateFile not found](https://sshconfig-lint.apps.thiering.org/en/rules/certificate-file-exists) | error |
| `LOCAL_COMMAND_DISABLED` | [LocalCommand is not enabled](https://sshconfig-lint.apps.thiering.org/en/rules/local-command-enabled) | warning |
| `INVALID_TOKEN` | [Invalid percent token](https://sshconfig-lint.apps.thiering.org/en/rules/invalid-percent-token) | error |
| `INVALID_SYNTAX` | [Invalid syntax](https://sshconfig-lint.apps.thiering.org/en/rules/invalid-syntax) | error |
| `UNKNOWN_DIRECTIVE` | [Unknown directive](https://sshconfig-lint.apps.thiering.org/en/rules/unknown-directive) | error |
| `DEPRECATED_OPTION` | [Deprecated option](https://sshconfig-lint.apps.thiering.org/en/rules/deprecated-option) | warning |
| `INVALID_MATCH` | [Invalid Match condition](https://sshconfig-lint.apps.thiering.org/en/rules/invalid-match-condition) | error |
| `CONTROL_PERSIST_UNUSED` | [ControlPersist without ControlMaster](https://sshconfig-lint.apps.thiering.org/en/rules/control-persist-requires-master) | warning |
| `UPDATE_HOSTKEYS_ASK_PERSIST` | [UpdateHostKeys ask with ControlPersist](https://sshconfig-lint.apps.thiering.org/en/rules/update-hostkeys-control-persist) | warning |

The rule guides show the exact broken fragment, a corrected config, why it matters, and how to verify the result with OpenSSH.

`INVALID_VALUE` checks ports, retry and prompt counters, alive settings, `ForwardX11Timeout`, `RequiredRSASize`, `ControlPersist`, boolean switches, `ObscureKeystrokeTiming`, OpenSSH time values, `StreamLocalBindMask`, `IPQoS`, and documented value sets such as `AddressFamily`, `ControlMaster`, `StrictHostKeyChecking`, `LogLevel`, and `PubkeyAuthentication`. Quoted and case-insensitive values accepted by OpenSSH remain valid. The linter accepts modern syntax without trying to infer the version of the SSH client that will consume the config.

Filesystem checks skip paths containing percent tokens or environment variables because their final value depends on the connection context. `LOCAL_COMMAND_DISABLED` is similarly conservative: it is suppressed when an unresolved `Include` or any possible `PermitLocalCommand yes` could make the command effective. Resolve Includes through the normal CLI or a saved editor document for the most precise result.

## Development

Requires Rust 1.85 or newer.

```bash
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt -- --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md), the public [roadmap](ROADMAP.md), the
[v1 stability contract](STABILITY.md), and [security policy](SECURITY.md).

## License

MIT
