use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;

use sshconfig_lint::{lint_file, lint_str_portable, report};

fn openssh_accepts(config: &str) -> Option<bool> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ssh_config");
    fs::write(&path, config).unwrap();
    Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&path)
        .arg("example.invalid")
        .output()
        .ok()
        .map(|output| output.status.success())
}

#[test]
fn version_stable_openssh_syntax_is_accepted_by_openssh_and_the_linter() {
    let accepted = [
        "Port +22\n",
        "Port 00022\n",
        "ConnectTimeout 1m30\n",
        "StreamLocalBindMask +0777\n",
        "IPQoS +1 255\n",
        "Host \"quoted host\"\n  User alice\n",
        "Host 'single quoted host'\n  User alice\n",
        "Host escaped\\ host\n  User alice\n",
        "Host example#legacy\n  User alice # comment\n",
        "BatchMode true\n",
        "IdentitiesOnly no\n",
        "ControlPersist 10m\nControlMaster auto\n",
        "Match host example.invalid\n  User alice\n",
        "Match all\n  User alice\n",
    ];

    for config in accepted {
        if let Some(result) = openssh_accepts(config) {
            assert!(result, "local OpenSSH rejected audit fixture: {config:?}");
        }
        let findings = lint_str_portable(config);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != "INVALID_VALUE"),
            "sshconfig-lint rejected OpenSSH syntax {config:?}: {findings:?}"
        );
    }
}

#[test]
fn current_upstream_fractional_seconds_do_not_create_invalid_value_findings() {
    // Fractional seconds are supported by current OpenSSH through
    // convtime_double(), but older clients installed on CI runners reject
    // them. Keep these cases independent of the installed ssh version.
    for config in ["ConnectTimeout 1.5s\n", "ConnectTimeout .5s\n"] {
        let findings = lint_str_portable(config);
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != "INVALID_VALUE"),
            "sshconfig-lint rejected current OpenSSH syntax {config:?}: {findings:?}"
        );
    }
}

#[test]
fn stable_invalid_values_are_rejected_by_openssh_and_the_linter() {
    for config in [
        "Port 0\n",
        "Port 65536\n",
        "ConnectionAttempts 0\n",
        "ConnectTimeout -1\n",
        "ConnectTimeout 1.5m\n",
        "IPQoS 256\n",
        "AddressFamily ipv4\n",
        "StrictHostKeyChecking accept_new\n",
        "BatchMode enabled\n",
        "ObscureKeystrokeTiming interval:1001\n",
    ] {
        if let Some(result) = openssh_accepts(config) {
            assert!(
                !result,
                "local OpenSSH accepted invalid audit fixture: {config:?}"
            );
        }
        let findings = lint_str_portable(config);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "INVALID_VALUE"),
            "sshconfig-lint missed invalid OpenSSH value {config:?}: {findings:?}"
        );
    }
}

#[test]
fn parser_level_errors_are_rejected_by_openssh_and_the_linter() {
    let cases = [
        ("User\n", "INVALID_SYNTAX"),
        ("User \"unterminated\n", "INVALID_SYNTAX"),
        ("Host \"\"\n", "INVALID_SYNTAX"),
        ("Match host\n", "INVALID_MATCH"),
        ("Match all host example.invalid\n", "INVALID_MATCH"),
        ("Match imaginary value\n", "INVALID_MATCH"),
        ("HosName example.invalid\n", "UNKNOWN_DIRECTIVE"),
    ];

    for (config, code) in cases {
        if let Some(result) = openssh_accepts(config) {
            assert!(
                !result,
                "local OpenSSH accepted invalid parser fixture: {config:?}"
            );
        }
        let findings = lint_str_portable(config);
        assert!(
            findings.iter().any(|finding| finding.code == code),
            "sshconfig-lint missed {code} for {config:?}: {findings:?}"
        );
    }
}

#[test]
fn linter_rejects_partially_parsed_octal_masks_that_openssh_would_truncate() {
    for value in ["0788", "0888", "777junk", "0o177"] {
        let config = format!("StreamLocalBindMask {value}\n");
        let findings = lint_str_portable(&config);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "INVALID_VALUE"),
            "the linter must not silently accept OpenSSH's partial octal parse: {value}"
        );
    }
}

#[test]
fn malformed_and_adversarial_text_never_panics_the_engine_or_reporters() {
    let seeds = [
        "",
        "~",
        "Include ~",
        "Include [",
        "Include \"",
        "Host ''",
        "Host \"unterminated",
        "Host 😀\nHost 😀",
        "IdentityFile \\",
        "Port 999999999999999999999999999999999999999999",
        "#\0comment",
        "Host a\r\n\tUser b\r\n",
    ];

    for seed in seeds {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let findings = lint_str_portable(seed);
            let _ = report::emit_text(&findings, false);
            let _: serde_json::Value = serde_json::from_str(&report::emit_json(&findings)).unwrap();
            let _: serde_json::Value =
                serde_json::from_str(&report::emit_sarif(&findings)).unwrap();
            let _ = report::emit_github(&findings);
        }));
        assert!(result.is_ok(), "engine panicked for {seed:?}");
    }
}

#[test]
fn deterministic_generated_inputs_never_panic_or_break_machine_output() {
    const ALPHABET: &[char] = &[
        'H', 'o', 's', 't', 'M', 'a', 'c', 'h', 'I', 'n', 'c', 'l', 'u', 'd', 'e', 'P', 'r', 't',
        '2', '0', '6', '5', '5', '3', '5', ' ', '\t', '\r', '\n', '\\', '\'', '"', '#', '=', '%',
        '*', '!', '[', ']', '~', '/', '.', '-', '+', '\0', 'é', '中', '😀',
    ];

    let mut state = 0x5eed_5eed_u64;
    for case_index in 0..2_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let length = (state as usize % 128) + (case_index % 3);
        let mut input = String::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            input.push(ALPHABET[state as usize % ALPHABET.len()]);
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            let findings = lint_str_portable(&input);
            let _ = report::emit_text(&findings, false);
            let _: serde_json::Value = serde_json::from_str(&report::emit_json(&findings)).unwrap();
            let _: serde_json::Value =
                serde_json::from_str(&report::emit_sarif(&findings)).unwrap();
            let _ = report::emit_github(&findings);
        }));
        assert!(
            result.is_ok(),
            "generated case {case_index} panicked for {input:?}"
        );
    }
}

#[test]
fn non_utf8_config_is_a_read_error_instead_of_a_panic() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
    let error = lint_file(&path).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
