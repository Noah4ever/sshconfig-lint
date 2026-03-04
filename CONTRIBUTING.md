# Contributing

## Setup

```bash
git clone https://github.com/Noah4ever/sshconfig-lint.git
cd sshconfig-lint
cargo test
```

Requires Rust 1.70+.

## Workflow

1. Fork and create a branch
2. Write a failing test for what you want to change
3. Implement until the test passes
4. Run the full suite: `cargo test`
5. Check formatting and lints: `cargo fmt --check && cargo clippy -- -D warnings`
6. Open a PR

## Adding a rule

Implement the `Rule` trait in `src/rules/basic.rs`:

```rust
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

Register it in `src/rules/mod.rs` inside `run_all()`:

```rust
Box::new(MyRule),
```

Write tests in the same file:

```rust
#[test]
fn my_rule_catches_the_thing() {
    let config = Config { items: vec![/* ... */] };
    let findings = MyRule.check(&config);
    assert_eq!(findings.len(), 1);
}
```

## Commit messages

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add duplicate-directive rule
fix: handle empty Host patterns
test: add edge case for quoted values
docs: update rule descriptions
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
| `src/rules/` | Rule implementations |
| `src/report.rs` | Format findings for output |
| `tests/` | Integration tests & fixtures |

## Questions?

- Check existing issues: https://github.com/your-username/sshconfig-lint/issues
- Start a discussion: https://github.com/your-username/sshconfig-lint/discussions
- Email: noah@example.com

### Thank you for contributing! 🎉
