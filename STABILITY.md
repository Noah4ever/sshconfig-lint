# v1 stability contract

This document defines the public compatibility promises planned for the 1.x
release line. The guarantees take effect when v1.0.0 is published.

## Supported interfaces

The following commands remain supported throughout 1.x:

```text
sshconfig-lint [PATH...]
sshconfig-lint --config PATH
sshconfig-lint lsp
```

`--strict`, `--no-includes`, and the `text`, `json`, `github`, and `sarif`
output formats are stable. New optional flags may be added in a minor release.
Existing flags will not be removed or change meaning before 2.0.

Exit codes are stable:

- `0`: no blocking finding
- `1`: at least one error, or at least one warning with `--strict`
- `2`: at least one requested config could not be read

When more than one condition applies, unreadable input keeps precedence and
returns `2`.

## Diagnostics and output

Rule codes are identifiers for automation. A 1.x release will not reuse a code
for a different condition or silently change its severity. Rules may be added
in minor releases. A rule removal or a meaningfully broader existing rule
requires a major release unless it fixes a false negative for behavior already
documented by that rule.

Each JSON finding keeps these fields and types:

```json
{
  "severity": "error | warning | info",
  "code": "STABLE_CODE",
  "rule": "stable-rule-slug",
  "line": 1,
  "file": "path or null",
  "message": "human-readable explanation",
  "hint": "actionable fix or null",
  "documentation": "https URL"
}
```

Fields may be added in a minor release. Existing fields will not be removed or
change type during 1.x. Array order remains deterministic by file and line.

Text output keeps one finding per line with file, line, severity, code, rule,
message, and optional hint. Wording may be clarified without a major release,
so scripts should use JSON, SARIF, GitHub annotations, or rule codes instead of
parsing prose. ANSI colour is emitted only for text written to a terminal and
is disabled by `NO_COLOR`.

SARIF remains valid SARIF 2.1.0 and keeps rule IDs equal to the public rule
codes. GitHub output remains workflow-command compatible and escapes reserved
characters in properties and messages.

## Language server

`sshconfig-lint lsp` communicates over stdio using Language Server Protocol
3.x. It keeps full-document synchronization and publishes full-line
diagnostics with severity, public rule code, explanation, and documentation
URL. Saved files may publish diagnostics for resolved Include files. Untitled
documents do not run filesystem-dependent rules.

The server does not add telemetry. New non-destructive LSP capabilities may be
added in a minor release. Formatting or code actions that can change SSH
semantics will not be enabled without an explicit compatibility review.

## Platforms and support

Release artifacts target:

- Linux x86_64 and ARM64 with glibc
- Linux x86_64 and ARM64 with musl
- macOS Intel and Apple Silicon
- Windows x86_64 and ARM64

The minimum supported Rust version for building v1 is 1.85. Release binaries,
the GitHub Action, the pre-commit hooks, and the VS Code extension all use the
same engine and rule codes.

Bug reports belong in GitHub Issues. Security-sensitive reports follow
`SECURITY.md`. Critical correctness and security fixes may ship in a patch
release. Support for a platform is removed only in a major release unless its
toolchain can no longer build a supported Rust version.

## Upgrade policy

Before v1.0, read every entry under `Unreleased` in `CHANGELOG.md`. The v1.0
release freezes the contracts above. During 1.x:

- patch releases fix regressions, false positives, false negatives, and docs
- minor releases may add rules, optional fields, integrations, and safe LSP
  capabilities
- breaking CLI, schema, code, or exit-status changes wait for 2.0

New diagnostics can make `--strict` builds fail. Minor-release notes will call
out every new rule so CI users can review it before upgrading.
