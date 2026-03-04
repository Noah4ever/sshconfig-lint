use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

#[test]
fn cli_clean_config_exits_0() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/basic.config")
        .assert()
        .success()
        .stdout(predicate::str::contains("No issues found"));
}

#[test]
fn cli_missing_config_file_exits_2() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/does_not_exist.config")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn cli_error_severity_exits_1() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/missing_identity.config")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("identity-file-exists"));
}

#[test]
fn cli_json_format() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/duplicate_host.config")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"rule\":\"duplicate-host\""));
}
