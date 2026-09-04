# OpenSSH edge-case audit

This audit was performed on September 2 and extended on September 3, 2026 before the v1 release candidate.
It used OpenSSH portable source commit
`769728b835f19a2d5cb69062f21c8a30fbdca9a1` and the local OpenSSH 10.3 client.
The executable comparison uses `ssh -G -F` and never opens a network
connection.

Primary references:

- [OpenSSH client configuration manual](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5)
- [OpenSSH client parser](https://github.com/openssh/openssh-portable/blob/master/readconf.c)
- [OpenSSH argument-splitting tests](https://github.com/openssh/openssh-portable/blob/master/regress/unittests/misc/test_argv.c)
- [OpenSSH duration tests](https://github.com/openssh/openssh-portable/blob/master/regress/unittests/misc/test_convtime.c)
- [OpenSSH Include regression tests](https://github.com/openssh/openssh-portable/blob/master/regress/cfginclude.sh)

## Covered parser cases

- LF and CRLF input
- spaces, tabs, `Key Value`, `Key=Value`, and `Key = Value`
- single quotes, double quotes, adjacent quoted segments, and empty quoted
  arguments
- recognised OpenSSH backslash escapes
- hashes inside tokens and comments that begin after whitespace
- ASCII-insensitive directive names and Host matching
- Unicode content and UTF-16 LSP range calculation
- malformed and unbalanced quotes without panics
- missing and empty arguments as parser errors
- all 128 keywords in the current portable OpenSSH client parser
- unknown options, `IgnoreUnknown` ordering, wildcards, negation, and case folding
- supported `Match` criteria, required values, equals forms, and isolated `all`

`tests/edge_case_audit.rs` compares version-stable accepted and rejected values
against the installed OpenSSH client when it is available. The test skips only
the OpenSSH half when no `ssh` executable is installed; the linter assertions
still run. Current-upstream syntax that older clients reject, such as fractional
seconds, is tested against the linter separately and traced to the upstream
parser tests.

## Covered filesystem and Include cases

- absent root files, unreadable files, directories, and non-UTF-8 contents
- quoted and escaped paths containing spaces
- bare `~`, `~/path`, absolute paths, and relative paths
- missing globs, invalid globs, lexical glob ordering, and multiple patterns
- direct and indirect cycles, repeated non-cyclic includes, and symlink
  canonicalisation
- a maximum nesting depth of 16, matching OpenSSH's `READCONF_MAX_DEPTH`
- regular-file and readability checks for IdentityFile, CertificateFile, and
  RevokedHostKeys
- conservative handling of percent tokens, environment variables, and named
  user tildes that require runtime context

## Covered values and outputs

- integer boundaries, explicit positive signs, leading zeroes, negatives, and
  overflow
- OpenSSH time units, compound durations, fractional seconds, and overflow
- port, mask, DSCP, and enumerated-value boundaries
- all current boolean flags, `RequiredRSASize`, `ControlPersist`,
  `ForwardX11Timeout`, and `ObscureKeystrokeTiming` boundaries
- ineffective `ControlPersist` and its documented interaction with
  `UpdateHostKeys ask`
- quoted security values and quoted comma-separated algorithm lists
- JSON field types, deterministic ordering, SARIF 2.1.0, URI encoding, GitHub
  escaping, and text output
- exit codes for clean, warning, error, mixed-readable, and unreadable input
- untitled and saved LSP documents, `Key=Value`, Include URIs, stale
  diagnostics, and Unicode line ranges

OpenSSH currently accepts partially parsed octal masks such as
`StreamLocalBindMask 0788` and applies `07`. sshconfig-lint intentionally
rejects these values because silently truncating a likely typo is unsafe.

## Explicit boundaries

sshconfig-lint is a semantic linter, not a replacement implementation of the
entire OpenSSH parser. Every forwarding grammar and connection-dependent
expansion are not guessed. The known-option table targets the audited current
portable OpenSSH release and recognises common vendor extensions. Use
`ssh -G host -F path` when the exact installed OpenSSH version and a concrete
host must be evaluated.

No claim of “all possible input” is made. The test suite instead combines
upstream-derived cases, differential checks, boundary matrices, adversarial
no-panic inputs, integration fixtures, and cross-platform CI. Every reported
regression receives a permanent test before its fix.
