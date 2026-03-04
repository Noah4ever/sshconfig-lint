# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] - 2026-03-04

### Added

- Lexer with quote-aware tokenization and inline comment stripping
- Parser that builds an AST from tokenized lines
- Include resolver with glob expansion and cycle detection
- Text and JSON output formats
- Rules:
  - `duplicate-host`: warn on duplicate Host patterns
  - `identity-file-exists`: error when IdentityFile path is missing
  - `wildcard-host-order`: warn when `Host *` shadows later entries
- CLI with `--config` and `--format` flags
- CI workflow (tests, clippy, fmt)
- Release workflow (builds for Linux, macOS, Windows on tag push)

[Unreleased]: https://github.com/Noah4ever/sshconfig-lint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Noah4ever/sshconfig-lint/releases/tag/v0.1.0
