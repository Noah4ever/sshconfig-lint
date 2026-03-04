use sshconfig_lint::{lint_file, lint_str};
use std::path::Path;

#[test]
fn fixture_empty_config() {
    let path = Path::new("tests/fixtures/empty.config");
    let findings = lint_file(path).expect("should read empty fixture");
    assert!(findings.is_empty(), "empty config should produce no findings");
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
    let output = sshconfig_lint::report::emit_text(&findings);
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
