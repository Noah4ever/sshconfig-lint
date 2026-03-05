use sshconfig_lint::{lint_file, lint_str};
use std::path::Path;

#[test]
fn fixture_empty_config() {
    let path = Path::new("tests/fixtures/empty.config");
    let findings = lint_file(path).expect("should read empty fixture");
    assert!(
        findings.is_empty(),
        "empty config should produce no findings"
    );
}

#[test]
fn fixture_basic_config_clean() {
    let path = Path::new("tests/fixtures/basic.config");
    let findings = lint_file(path).expect("should read basic fixture");
    assert!(
        findings.is_empty(),
        "basic clean config should produce no findings, got: {:?}",
        findings
    );
}

#[test]
fn fixture_duplicate_host() {
    let path = Path::new("tests/fixtures/duplicate_host.config");
    let findings = lint_file(path).expect("should read fixture");
    assert!(
        findings.iter().any(|f| f.rule == "duplicate-host"),
        "should detect duplicate Host blocks, got: {:?}",
        findings
    );
}

#[test]
fn fixture_wildcard_first() {
    let path = Path::new("tests/fixtures/wildcard_first.config");
    let findings = lint_file(path).expect("should read fixture");
    assert!(
        findings.iter().any(|f| f.rule == "wildcard-host-order"),
        "should warn about Host * before specific hosts, got: {:?}",
        findings
    );
}

#[test]
fn fixture_missing_identity() {
    let path = Path::new("tests/fixtures/missing_identity.config");
    let findings = lint_file(path).expect("should read fixture");
    assert!(
        findings.iter().any(|f| f.rule == "identity-file-exists"),
        "should error about missing IdentityFile, got: {:?}",
        findings
    );
}

#[test]
fn snapshot_text_output() {
    let findings = lint_str(
        "\
Host *
  ServerAliveInterval 60

Host github.com
  User git

Host github.com
  User git2
",
    );
    let output = sshconfig_lint::report::emit_text(&findings, false);
    insta::assert_snapshot!(output);
}

#[test]
fn snapshot_json_output() {
    let findings = lint_str(
        "\
Host *
  ServerAliveInterval 60

Host github.com
  User git

Host github.com
  User git2
",
    );
    let output = sshconfig_lint::report::emit_json(&findings);
    insta::assert_snapshot!(output);
}

#[test]
fn fixture_multiple_patterns() {
    let path = Path::new("tests/fixtures/multiple_patterns.config");
    let findings = lint_file(path).expect("should read fixture");
    // Multiple patterns in a single Host block should not be flagged as duplicates
    // (only same full patterns in different blocks)
    assert!(
        !findings.iter().any(|f| f.rule == "duplicate-host"),
        "multiple patterns in same Host should not cause duplicate warnings, got: {:?}",
        findings
    );
}

#[test]
fn fixture_comments_after_directives() {
    let path = Path::new("tests/fixtures/comments_after_directives.config");
    let findings = lint_file(path).expect("should read fixture");
    // Comments after directives should be stripped, values should be clean
    println!("Findings: {:?}", findings);
    // The ProxyCommand with quotes should not be treated as multiple directives
    assert!(
        findings.is_empty(),
        "comments and quoted values should not cause issues, got: {:?}",
        findings
    );
}

#[test]
fn fixture_quoted_values() {
    let path = Path::new("tests/fixtures/quoted_values.config");
    let findings = lint_file(path).expect("should read fixture");
    // Quoted values with spaces should be parsed as single values
    println!("Findings: {:?}", findings);
    assert!(
        findings.is_empty(),
        "quoted values should be handled correctly, got: {:?}",
        findings
    );
}

#[test]
fn fixture_weak_algorithms() {
    let path = Path::new("tests/fixtures/weak_algorithms.config");
    let findings = lint_file(path).expect("should read fixture");
    assert!(
        findings
            .iter()
            .any(|f| f.rule == "deprecated-weak-algorithms"),
        "should warn about weak algorithms, got: {:?}",
        findings
    );
    let weak: Vec<_> = findings.iter().filter(|f| f.code == "WEAK_ALGO").collect();
    assert_eq!(
        weak.len(),
        3,
        "should find 3des-cbc, hmac-md5, and diffie-hellman-group1-sha1, got: {:?}",
        weak
    );
}

#[test]
fn fixture_duplicate_directives() {
    let path = Path::new("tests/fixtures/duplicate_directives.config");
    let findings = lint_file(path).expect("should read fixture");
    assert!(
        findings.iter().any(|f| f.rule == "duplicate-directives"),
        "should detect duplicate directives, got: {:?}",
        findings
    );
    let dup: Vec<_> = findings
        .iter()
        .filter(|f| f.code == "DUP_DIRECTIVE")
        .collect();
    assert_eq!(
        dup.len(),
        1,
        "should find one duplicate User, got: {:?}",
        dup
    );
    assert!(dup[0].message.contains("User"));
}
