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

# treat warnings as errors (useful in CI)
sshconfig-lint --strict

# skip Include resolution
sshconfig-lint --no-includes
```

### Example output

```
line 4: [warning] WILDCARD_ORDER (wildcard-host-order) Host 'github.com' appears after 'Host *' (line 1); it will never match because Host * already matched (hint: move Host * to the end of the file)
line 7: [warning] DUP_HOST (duplicate-host) duplicate Host block 'github.com' (first seen at line 4) (hint: remove one of the duplicate Host blocks)
line 3: [error] MISSING_IDENTITY (identity-file-exists) IdentityFile not found: ~/.ssh/id_missing (hint: check the path or remove the directive)
```

Output is sorted by file and line number so it's deterministic across runs (stable for CI diffs and snapshots).

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean, no errors found |
| 1 | At least one error-level finding (or warning with `--strict`) |
| 2 | Config file not found |

## Rules

Each finding has a stable code you can grep for or match on in scripts.

| Code | Rule | Severity | Description |
|------|------|----------|-------------|
| `DUP_HOST` | `duplicate-host` | warning | Two Host blocks with the same pattern |
| `MISSING_IDENTITY` | `identity-file-exists` | error | IdentityFile path doesn't exist |
| `WILDCARD_ORDER` | `wildcard-host-order` | warning | Host * appears before specific patterns |
| `INCLUDE_CYCLE` | `include-cycle` | error | Circular Include chain |
| `INCLUDE_READ` | `include-read` | error | Included file can't be read |
| `INCLUDE_GLOB` | `include-glob` | error | Invalid Include glob pattern |
| `INCLUDE_NO_MATCH` | `include-no-match` | info | Include pattern matched no files |

Findings include a hint when possible (e.g. "move Host * to the end of the file").

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
