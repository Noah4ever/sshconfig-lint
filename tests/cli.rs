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
        .stdout(predicate::str::contains("\"rule\":\"duplicate-host\""))
        .stdout(predicate::str::contains("\"code\":\"DUP_HOST\""));
}

#[test]
fn cli_strict_treats_warnings_as_errors() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/duplicate_host.config")
        .arg("--strict")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("duplicate-host"));
}

#[test]
fn cli_no_includes_skips_resolution() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/basic.config")
        .arg("--no-includes")
        .assert()
        .success();
}

#[test]
fn cli_accepts_multiple_positional_configs() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("tests/fixtures/basic.config")
        .arg("tests/fixtures/duplicate_host.config")
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"file\":\"tests/fixtures/duplicate_host.config\"",
        ))
        .stdout(predicate::str::contains("\"code\":\"DUP_HOST\""));
}

#[test]
fn cli_sarif_format_is_valid_sarif() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("tests/fixtures/duplicate_host.config")
        .arg("--format")
        .arg("sarif")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"version\": \"2.1.0\""))
        .stdout(predicate::str::contains("DUP_HOST"));
}

#[test]
fn cli_github_format_emits_annotations() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("tests/fixtures/duplicate_host.config")
        .arg("--format")
        .arg("github")
        .assert()
        .success()
        .stdout(predicate::str::contains("::warning file="))
        .stdout(predicate::str::contains("line=9,title=DUP_HOST"));
}

#[test]
fn cli_config_and_positional_path_are_mutually_exclusive() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("--config")
        .arg("tests/fixtures/basic.config")
        .arg("tests/fixtures/basic.config")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_new_error_diagnostics_exit_1_in_every_output_format() {
    for format in ["text", "json", "sarif", "github"] {
        cargo_bin_cmd!("sshconfig-lint")
            .arg("tests/fixtures/semantic_traps.config")
            .arg("--format")
            .arg(format)
            .assert()
            .code(1);
    }
}

#[test]
fn cli_new_warning_preserves_default_and_strict_exit_codes() {
    cargo_bin_cmd!("sshconfig-lint")
        .arg("tests/fixtures/negated_only_host.config")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("NEGATED_HOST"));

    cargo_bin_cmd!("sshconfig-lint")
        .arg("tests/fixtures/negated_only_host.config")
        .arg("--strict")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("NEGATED_HOST"));
}
