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

- [ ] Validate stable values for `AddressFamily`
- [ ] Validate stable values for `RequestTTY` and `SessionType`
- [ ] Validate stable values for `ControlMaster`
- [ ] Validate stable values for `CanonicalizeHostname`
- [ ] Validate stable values for `StrictHostKeyChecking`
- [ ] Validate stable values for `UpdateHostKeys` and `VerifyHostKeyDNS`
- [ ] Validate stable values for `Tunnel`
- [ ] Validate stable values for `LogLevel` and `SyslogFacility`
- [ ] Validate stable values for `PubkeyAuthentication`
- [ ] Document version-sensitive values that are intentionally not validated

## Checkpoint 04: small semantic traps

Suggested tag: `checkpoint/04-semantic-traps`

- [ ] Warn when a `Host` block contains only negated patterns and can never
      match positively
- [ ] Diagnose `ProxyCommand` and `ProxyJump` in the same scope because only
      the first obtained value takes effect
- [ ] Diagnose a missing or unreadable `RevokedHostKeys` file
- [ ] Check explicit `CertificateFile` paths while respecting tokens,
      environment variables, and the `none` sentinel where supported
- [ ] Report `LocalCommand` as ineffective when `PermitLocalCommand` is not
      enabled in the effective scope
- [ ] Validate percent tokens only for directives with stable token contracts
- [ ] Defer forwarding syntax until IPv6, Unix sockets, wildcard ports, and
      remote port zero can be handled without false positives

## Checkpoint 05: output and LSP contracts

Suggested tag: `checkpoint/05-output-contracts`

- [ ] Add nested Include fixtures to LSP end-to-end tests
- [ ] Expand GitHub annotation escaping tests
- [ ] Snapshot text, JSON, SARIF, and GitHub output for every new diagnostic
- [ ] Verify file, line, severity, code, message, hint, and documentation URL
- [ ] Test unsaved buffers and filesystem-dependent checks separately
- [ ] Preserve existing exit-code behavior

## Checkpoint 06: integrations and documentation

Suggested tag: `checkpoint/06-integrations`

- [ ] Add a tested Neovim LSP example
- [ ] Run the official pre-commit hooks in a fixture repository
- [ ] Run the GitHub Action smoke test on Linux, macOS, and Windows
- [ ] Test VS Code binary download, checksum failure, custom binary path, and
      offline reuse
- [ ] Add or update one rule guide for every public diagnostic
- [ ] Keep README, playground, Action examples, and extension documentation in
      sync
- [ ] Publish the GitHub Action in GitHub Marketplace

## Checkpoint 07: v1.0 release candidate

Suggested tag: `checkpoint/07-v1-release-candidate`

- [ ] No open critical or high-severity defects
- [ ] Full Rust, CLI, Action, pre-commit, LSP, and extension suites pass
- [ ] Release matrix passes for Linux glibc and musl, macOS Intel and Apple
      Silicon, and Windows x86_64 and ARM64
- [ ] Rule codes, CLI output, JSON, SARIF, LSP, exit codes, support policy, and
      upgrade policy are documented as stable
- [ ] At least ten external users have used the Action, hook, LSP, or extension
      in a real workflow
- [ ] At least four weeks of v0.5 feedback have elapsed
- [ ] `cargo publish --dry-run` and the VSIX package checks pass
- [ ] The macOS release path has been rehearsed without publishing
- [ ] Changelog and release notes are complete

## v1.0 publication

`v1.0.0` is the next public package release unless a critical v0.5 regression
requires an earlier patch. The final release publishes GitHub artifacts,
crates.io, AUR, Homebrew, and the VS Code extension together. See
[`RELEASING.md`](RELEASING.md) for the one-time macOS setup and release steps.

After publication:

- publish the GitHub Action in Marketplace
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
