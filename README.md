# sshconfig-lint

Lint your `~/.ssh/config` for common mistakes.

Checks for duplicate host blocks, missing identity files, wildcard ordering problems, and more. Supports `Include` directives with cycle detection.

## Install

### Pre-built binaries

Grab a binary from the [releases page](https://github.com/Noah4ever/sshconfig-lint/releases).

### From source

```bash
cargo install --git https://github.com/Noah4ever/sshconfig-lint.git
```

## Usage

```bash
# lint the default ~/.ssh/config
sshconfig-lint

# lint a specific file
sshconfig-lint --config /path/to/config

# json output
sshconfig-lint --format json
```

### Example output

```
line 3: [error] (identity-file-exists) IdentityFile not found: ~/.ssh/id_missing
line 8: [warning] (duplicate-host) duplicate Host block 'github.com' (first seen at line 1)
line 5: [warning] (wildcard-host-order) Host 'github.com' appears after 'Host *' (line 5); it will never match because Host * already matched
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean, no errors found |
| 1 | At least one error-level finding |
| 2 | Config file not found |

## Rules

### `duplicate-host`

Warns when two `Host` blocks use the same pattern. OpenSSH uses first-match-wins, so duplicates are almost always a mistake.

### `identity-file-exists`

Errors when an `IdentityFile` points to a path that doesn't exist. Skips paths containing `%` tokens or `${}` variables since those are expanded at runtime.

### `wildcard-host-order`

Warns when `Host *` appears before more specific patterns. Since OpenSSH matches top-to-bottom, anything after `Host *` will never be reached.

## What it handles

- Multiple host patterns (`Host github.com gitlab.com`)
- Multiple include patterns (`Include conf.d/*.conf extra.conf`)
- Inline comments (`IdentityFile ~/.ssh/id # my key`)
- Quoted values (`ProxyCommand "ssh -W %h:%p bastion"`)
- Include resolution with cycle detection

## Development

```bash
cargo test          # run all tests
cargo test --lib    # unit tests only
cargo clippy        # lint
cargo fmt --check   # formatting
```

### Project layout

```
src/
  main.rs        CLI
  lib.rs         Public API (lint_file, lint_str)
  model.rs       AST types
  lexer.rs       Tokenizer
  parser.rs      Builds config AST from tokens
  resolve.rs     Include expansion + cycle detection
  report.rs      Text and JSON formatters
  rules/
    mod.rs       Rule trait and runner
    basic.rs     Built-in rules
tests/
  fixtures/      Sample config files
  cli.rs         CLI integration tests
  integration.rs Fixture-based tests
```

### Adding a rule

1. Implement the `Rule` trait in `src/rules/basic.rs`
2. Register it in `run_all()` in `src/rules/mod.rs`
3. Write tests first, then make them pass

See [CONTRIBUTING.md](CONTRIBUTING.md) for more detail.

## License

MIT
