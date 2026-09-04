# sshconfig-lint v1.0.0 release notes draft

sshconfig-lint v1 makes the same OpenSSH configuration checks available in the
terminal, editors, pre-commit, and GitHub Actions. It scans multiple root files,
follows nested Includes, and reports stable rule codes with source locations and
documentation links.

## Highlights since v0.5

- Validate documented numeric, duration, octal, DSCP, and enumerated directive
  values with the stable `INVALID_VALUE` rule code.
- Detect negated-only Host blocks, ProxyCommand and ProxyJump conflicts,
  disabled LocalCommand directives, invalid percent tokens, unreadable
  RevokedHostKeys files, and missing CertificateFile paths.
- Catch missing arguments, unbalanced quotes, unknown and deprecated options,
  and malformed Match conditions before they reach SSH.
- Validate current boolean switches, `RequiredRSASize`, connection-persistence
  settings, X11 timeouts, and keystroke-obscuring intervals.
- Explain ineffective `ControlPersist` and its conflict with
  `UpdateHostKeys ask` using dedicated stable rule codes.
- Publish diagnostics from nested Include files on the correct LSP document.
- Bound Include expansion at OpenSSH's depth limit and report `INCLUDE_DEPTH`
  instead of continuing recursively.
- Match OpenSSH argument handling for quotes, escaped spaces, hashes inside
  tokens, and case-insensitive Host matching.
- Keep text, JSON, SARIF, GitHub annotations, LSP, the VS Code rule guide, and
  the browser documentation aligned across 25 public diagnostic codes.

## Reliability work

The v1 candidate adds differential fixtures derived from the current OpenSSH
portable parser, adversarial no-panic tests, non-UTF-8 handling, Unicode LSP
ranges, output escaping, missing-file exit behavior, nested Include fixtures,
and cross-platform integration tests. The supported compatibility contracts are
documented in `STABILITY.md`, and the audit scope and explicit boundaries are in
`EDGE_CASE_AUDIT.md`.

Release artifacts are rehearsed for Linux x86_64 and ARM64 with glibc and musl,
macOS Intel and Apple Silicon, Windows x86_64 and ARM64, and the VS Code VSIX.

## Compatibility

Existing v0.5 CLI calls remain supported, including `--config`, positional
paths, `--strict`, `--no-includes`, and all four output formats. The v1 contract
freezes rule-code meaning, JSON field types, exit codes, SARIF rule IDs, and the
LSP diagnostic shape for the 1.x line.

Read `CHANGELOG.md` for the complete list of additions, changes, and fixes.
