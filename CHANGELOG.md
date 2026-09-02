# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project follows semantic versioning.

## [Unreleased]

### Added

- Validate `Port` values as integers from 1 through 65535 in root, `Host`, and `Match` scopes
- Add the stable `INVALID_VALUE` diagnostic for table-driven directive value validation
- Validate numeric values for `ConnectionAttempts`, `NumberOfPasswordPrompts`, `ServerAliveCountMax`, and `CanonicalizeMaxDots`
- Validate OpenSSH duration syntax for `ConnectTimeout` and `ServerAliveInterval`
- Validate complete octal `StreamLocalBindMask` values and one or two `IPQoS` arguments
- Validate documented enumerated values for address selection, TTY and session behavior, connection sharing, hostname canonicalization, host-key handling, tunnels, logging, and public-key authentication
- Warn about Host blocks made entirely from negated patterns
- Detect competing ProxyCommand and ProxyJump directives in the same scope
- Check explicit RevokedHostKeys and CertificateFile paths
- Report LocalCommand directives that are certainly disabled
- Validate directive-specific percent tokens, including Match exec commands
- Publish LSP diagnostics from nested Includes on the included file URI
- Snapshot every new semantic diagnostic in text, JSON, SARIF, and GitHub formats
- Add a tested Neovim configuration for the built-in LSP client
- Exercise both official Pre-Commit hooks against clean, warning, and error fixtures
- Run the repository Action itself on Linux, macOS, and Windows in CI
- Test verified VS Code binary downloads, checksum rejection, custom paths, and offline reuse
- Bound Include expansion to OpenSSH's maximum nesting depth of 16
- Add OpenSSH differential fixtures and adversarial no-panic coverage

### Changed

- Document the test-first checkpoint plan from v0.5 to v1.0
- Prepare a macOS-friendly release workflow that does not publish checkpoint tags
- Accept OpenSSH-compatible quoted numeric values and explicit positive signs
- Keep modern and platform-specific valid OpenSSH enum values accepted without guessing the locally installed client version
- Split built-in rule implementations into one file per rule while preserving the pre-v1 `rules::basic` exports
- Explain all filesystem-dependent checks in unsaved editor buffers
- Keep the VS Code rule-guide picker synchronized with every public diagnostic
- Match OpenSSH argument splitting for single and double quotes, adjacent quoted segments, and supported backslash escapes
- Treat Host patterns case-insensitively when finding duplicates

### Fixed

- Accept OpenSSH's `IdentityFile none` sentinel instead of reporting it as a missing file
- Do not print `No issues found` when every requested config file is missing or unreadable
- Avoid a panic for the valid bare-tilde form `Include ~`
- Preserve hashes inside OpenSSH tokens instead of treating every unquoted hash as a comment
- Resolve quoted and escaped IdentityFile and Include paths containing spaces
- Detect insecure values and weak algorithm lists when their arguments are quoted
- Percent-encode reserved and non-ASCII characters in SARIF artifact URIs
- Recognize filesystem-dependent `Key=Value` directives in untitled LSP buffers

## [0.5.0] - 2026-08-28

### Added

- Multiple positional config paths while preserving `--config`
- SARIF 2.1.0 and native GitHub annotation output
- Stable documentation links and source files on CLI findings
- Language Server Protocol support through `sshconfig-lint lsp`
- VS Code extension with verified managed binary downloads
- GitHub Marketplace Action for Linux, macOS, and Windows
- Standard and strict pre-commit hooks
- SHA256 checksums and release provenance attestations
- Linux musl and Windows ARM64 release targets

### Changed

- Cargo homepage now points to the browser playground and documentation
- Release notes are generated automatically
- Minimum supported Rust version is documented as 1.85

### Security

- Installers verify release binaries against `SHA256SUMS`
- Editor and Action downloads are version-pinned and checksum-verified

## [0.4.0] - 2026-03-16

### Added

- `unsafe-control-path` rule for connection socket collisions

## [0.3.0] - 2026-03-07

### Added

- `insecure-option` rule for disabled host verification and broadly enabled forwarding

## [0.2.0] - 2026-03-05

### Added

- `deprecated-weak-algorithms` rule
- `duplicate-directives` rule
- Homebrew, AUR, release installer, security policy, code of conduct, and issue templates

## [0.1.0] - 2026-03-04

### Added

- Lexer with quote-aware tokenization and inline comment stripping
- Parser for Host, Match, directives, and Include statements
- Include resolver with glob expansion and cycle detection
- Text and JSON output
- Duplicate Host, missing IdentityFile, and wildcard ordering rules
- Initial CLI, tests, and multi-platform release workflow

[Unreleased]: https://github.com/Noah4ever/sshconfig-lint/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Noah4ever/sshconfig-lint/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Noah4ever/sshconfig-lint/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Noah4ever/sshconfig-lint/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Noah4ever/sshconfig-lint/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Noah4ever/sshconfig-lint/releases/tag/v0.1.0
