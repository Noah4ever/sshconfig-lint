# Contributing

## Setup

```bash
git clone https://github.com/Noah4ever/sshconfig-lint.git
cd sshconfig-lint
cargo test
```

Requires Rust 1.85 or newer.

## Workflow

1. Fork and create a branch
2. Write a failing test for what you want to change
3. Implement until the test passes
4. Run the full suite: `cargo test --all --locked`
5. Check formatting and lints: `cargo fmt --all -- --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
6. Open a PR

## Adding a rule

Each built-in rule has its own file in `src/rules/implementations/`. Start by copying the closest existing rule, then rename the type, rule name, code, message, hint, and tests. Do not add new implementations to `src/rules/basic.rs`; that module only preserves the pre-v1 public import path.

For example, create `src/rules/implementations/my_rule.rs` and implement the `Rule` trait:

```rust
use crate::model::{Config, Finding};
use crate::rules::Rule;

pub struct MyRule;

impl Rule for MyRule {
    fn name(&self) -> &'static str {
        "my-rule"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        for item in &config.items {
            // your logic
        }
        findings
    }
}
```

Declare and export it from `src/rules/implementations/mod.rs`:

```rust
mod my_rule;
pub use my_rule::MyRule;
```

Register it in `src/rules/mod.rs` inside `run_all()`:

```rust
Box::new(implementations::MyRule),
```

Also register it in `run_portable()` when it only needs the current document contents. Filesystem-dependent checks, such as resolving `Include` or checking key files, belong in `run_all()` only so editors do not report misleading results for unsaved documents.

Put focused unit tests in the implementation file or in `src/rules/implementations/tests.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

#[test]
fn my_rule_catches_the_thing() {
    let config = Config { items: vec![/* ... */] };
    let findings = MyRule.check(&config);
    assert_eq!(findings.len(), 1);
}
}
```

Add integration tests in `tests/` for CLI output or public diagnostic contracts. Rule codes, severities, messages, hints, and documentation URLs are public interfaces, so update the README rule table, VS Code rule mapping, website rule guide, snapshots, and changelog when they change.

## Commit messages

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add duplicate-directive rule
fix: handle empty Host patterns
test: add edge case for quoted values
docs: update rule descriptions
```

## Editor extension

The VS Code client lives in `editors/vscode` and delegates all diagnostics to `sshconfig-lint lsp`. Do not duplicate lint rules in TypeScript.

```bash
cd editors/vscode
npm install
npm run check
```

## PR checklist

- [ ] Tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] New functionality has tests

## Architecture Overview

```
Input: ~/.ssh/config
  ↓
[Lexer] → tokenize & strip comments
  ↓
[Parser] → build AST (Host blocks, directives)
  ↓
[Resolver] → expand Includes, detect cycles
  ↓
[Rules] → check duplicate hosts, file exists, etc.
  ↓
[Reporter] → format findings (text/JSON)
  ↓
Output: findings (errors/warnings/info)
```

### Key Files

| File | Purpose |
|------|---------|
| `src/lexer.rs` | Tokenize raw SSH config lines |
| `src/parser.rs` | Parse tokens into Config AST |
| `src/resolve.rs` | Expand & resolve Include directives |
| `src/rules/mod.rs` | Rule trait and rule registries |
| `src/rules/implementations/` | One file per built-in rule |
| `src/rules/basic.rs` | Compatibility exports for the pre-v1 module path |
| `src/report.rs` | Format findings for output |
| `tests/` | Integration tests & fixtures |

## Questions?

- Check existing issues: https://github.com/Noah4ever/sshconfig-lint/issues
- Start a discussion: https://github.com/Noah4ever/sshconfig-lint/discussions
- Email: noah@thiering.org

## Thanks
