# Roadmap to v1.0

sshconfig-lint is the same semantic rule engine everywhere an OpenSSH client
config changes. Development between v0.5 and v1.0 happens on `main` without
publishing every intermediate change to crates.io, AUR, Homebrew, or the VS
Code Marketplace.

## Development rhythm

Every item follows the same sequence:

1. Add a failing regression or acceptance test.
2. Implement the smallest correct change.
3. Run focused tests, then the full Rust and editor suites.
4. Update rule documentation and `CHANGELOG.md` when behavior changes.
5. Commit and push the completed item.
6. Optionally create an annotated `checkpoint/...` tag.

Checkpoint tags never start the release workflow. Only version tags beginning
with `v`, such as `v1.0.0`, build and publish a GitHub release.

## Completed: v0.5 Workflow Everywhere

- [x] Multiple config paths and source-aware diagnostics
- [x] JSON, SARIF, and GitHub output contracts
- [x] Language Server Protocol diagnostics
- [x] VS Code extension without telemetry
- [x] GitHub Action and pre-commit hooks
- [x] Verified cross-platform release artifacts
- [x] VS Code Marketplace publication

## Checkpoint 01: value-validation foundation

Suggested tag: `checkpoint/01-value-foundation`

- [x] Validate `Port` as an integer from 1 through 65535
- [x] Accept the OpenSSH sentinel value `IdentityFile none`
- [x] Introduce a table-driven value-validation rule with one stable public
      code and consistent messages, hints, and documentation links
- [x] Cover root, `Host`, and `Match` scopes
- [x] Add text and JSON snapshots for invalid values

## Checkpoint 02: numeric values

Suggested tag: `checkpoint/02-numeric-values`

- [x] `ConnectionAttempts` is an integer greater than or equal to 1
- [x] `ConnectTimeout` accepts non-negative OpenSSH time formats or `none`
- [x] `NumberOfPasswordPrompts` is an integer greater than or equal to 0
- [x] `ServerAliveInterval` accepts non-negative OpenSSH time formats or `none`
- [x] `ServerAliveCountMax` is an integer greater than or equal to 0
- [x] `CanonicalizeMaxDots` is an integer greater than or equal to 0
- [x] `StreamLocalBindMask` is a complete octal mask from `0000` to `0777`
- [x] `IPQoS` accepts one or two DSCP names or numeric values from 0 through 255
- [x] Test boundaries, signs, decimals, quotes, extra arguments, empty values, and overflow

## Checkpoint 03: enumerated values

Suggested tag: `checkpoint/03-enumerated-values`

- [x] Validate stable values for `AddressFamily`
- [x] Validate stable values for `RequestTTY` and `SessionType`
- [x] Validate stable values for `ControlMaster`
- [x] Validate stable values for `CanonicalizeHostname`
- [x] Validate stable values for `StrictHostKeyChecking`
- [x] Validate stable values for `UpdateHostKeys` and `VerifyHostKeyDNS`
- [x] Validate stable values for `Tunnel`
- [x] Validate stable values for `LogLevel` and `SyslogFacility`
- [x] Validate stable values for `PubkeyAuthentication`
- [x] Document version-sensitive values that are intentionally not validated

The validator follows the current portable OpenSSH parser and does not reject
valid syntax based on the OpenSSH version installed on the machine running the
linter. This intentionally accepts modern values such as
`StrictHostKeyChecking accept-new` and `PubkeyAuthentication unbound` or
`host-bound`, plus the platform-dependent `SyslogFacility AUTHPRIV`. Users of
older clients should check their local `ssh_config(5)` when sharing configs
across mixed OpenSSH versions.

## Checkpoint 04: small semantic traps

Suggested tag: `checkpoint/04-semantic-traps`

- [x] Warn when a `Host` block contains only negated patterns and can never
      match positively
- [x] Diagnose `ProxyCommand` and `ProxyJump` in the same scope because only
      the first obtained value takes effect
- [x] Diagnose a missing or unreadable `RevokedHostKeys` file
- [x] Check explicit `CertificateFile` paths while respecting tokens,
      environment variables, and the `none` sentinel where supported
- [x] Report `LocalCommand` as ineffective when `PermitLocalCommand` is not
      enabled in the effective scope
- [x] Validate percent tokens only for directives with stable token contracts
- [x] Defer forwarding syntax until IPv6, Unix sockets, wildcard ports, and
      remote port zero can be handled without false positives

Explicit filesystem paths are checked only when they can be resolved without
connection context. Paths containing percent tokens, environment variables,
or a named-user tilde remain untouched. `CertificateFile none` is treated as a
literal path because OpenSSH does not define a `none` sentinel for that
directive. LocalCommand diagnostics are suppressed when an unresolved
`Include` or any possible enabling scope prevents a certain conclusion.

## Checkpoint 05: output and LSP contracts

Suggested tag: `checkpoint/05-output-contracts`

- [x] Add nested Include fixtures to LSP end-to-end tests
- [x] Expand GitHub annotation escaping tests
- [x] Snapshot text, JSON, SARIF, and GitHub output for every new diagnostic
- [x] Verify file, line, severity, code, message, hint, and documentation URL
- [x] Test unsaved buffers and filesystem-dependent checks separately
- [x] Preserve existing exit-code behavior

LSP diagnostics originating in resolved Include files are published for the
included file URI, with ranges calculated from that file's contents. Closing
the root document also clears every diagnostic URI produced by its Include
tree. Untitled buffers keep content-only diagnostics and explain which checks
become available after saving.

## Checkpoint 06: integrations and documentation

Suggested tag: `checkpoint/06-integrations`

- [x] Add a tested Neovim LSP example
- [x] Run the official pre-commit hooks in a fixture repository
- [x] Run the GitHub Action smoke test on Linux, macOS, and Windows
- [x] Test VS Code binary download, checksum failure, custom binary path, and
      offline reuse
- [x] Add or update one rule guide for every public diagnostic
- [x] Keep README, playground, Action examples, and extension documentation in
      sync
- [x] Publish the GitHub Action in GitHub Marketplace

The Action smoke workflow exercises the repository's current composite Action
with the published version-matched binary on Linux, macOS, and Windows. The
documentation contract keeps all 25 public rule codes aligned across the core
README, VS Code picker, and the playground when both repositories are checked
out next to each other. The public Marketplace listing was verified on
September 2, 2026.

## Checkpoint 07: v1.0 release candidate

Suggested tag: `checkpoint/07-v1-release-candidate`

- [x] No known open critical or high-severity defects
- [x] Full Rust, CLI, Action, pre-commit, LSP, and extension suites pass
- [x] Release matrix passes for Linux glibc and musl, macOS Intel and Apple
      Silicon, and Windows x86_64 and ARM64
- [x] Rule codes, CLI output, JSON, SARIF, LSP, exit codes, support policy, and
      upgrade policy are documented as stable
- [x] `cargo publish --dry-run` and the VSIX package checks pass
- [x] The macOS release path has been rehearsed without publishing
- [x] Changelog and release notes are complete

The original engineering release-candidate gates were verified on September 2,
2026. A second upstream OpenSSH audit on September 3 added parser-level syntax,
unknown-option, deprecated-option, Match-condition, and connection-sharing
diagnostics plus broader value validation. On September 4, the complete suite
passed again on Linux, macOS, Windows, and the declared Rust 1.85 minimum in the
[full test workflow](https://github.com/Noah4ever/sshconfig-lint/actions/runs/33855628386).
An isolated version bump also built and tested the project as `1.0.0`, produced
a 10-file VSIX, and completed `cargo publish --dry-run`. That rehearsal exposed
and fixed hard-coded documentation and SARIF snapshot versions before release.
The earlier [full test workflow](https://github.com/Noah4ever/sshconfig-lint/actions/runs/33651102591),
the [Action smoke test](https://github.com/Noah4ever/sshconfig-lint/actions/runs/33651342137),
and the [eight-platform release rehearsal](https://github.com/Noah4ever/sshconfig-lint/actions/runs/33650554987)
passed. A final Linux smoke test on September 4 confirmed that a locally built
binary reports the same seven findings as the default playground example.
External adoption and longer-term feedback remain launch measurements rather
than blockers for the stable release.

## v1.0 publication

`v1.0.0` is the next public package release unless a critical v0.5 regression
requires an earlier patch. The final release publishes GitHub artifacts,
crates.io, AUR, Homebrew, and the VS Code extension together. See
[`RELEASING.md`](RELEASING.md) for the one-time macOS setup and release steps.

After publication:

- verify that the GitHub Marketplace listing offers v1.0
- submit the working playground to Show HN
- submit the tool to Console.dev and impl.rs
- use a suitable open issue for a This Week in Rust call for participation
- publish the technical case study on thiering.org
- measure GitHub, release, crates.io, Marketplace, and Search Console results
  after 7 and 30 days

## Later candidates

- safe, explicitly scoped editor code actions
- Winget packaging
- additional editors using the same LSP
- Debian and Ubuntu packages with a committed package maintainer

Ideas and real configs are welcome in
[GitHub Discussions](https://github.com/Noah4ever/sshconfig-lint/discussions).
Security reports belong in the private process described in
[`SECURITY.md`](SECURITY.md).
