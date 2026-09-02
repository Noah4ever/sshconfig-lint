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
fn documented_openssh_syntax_does_not_create_invalid_value_findings() {
    let accepted = [
        "Port +22\n",
        "Port 00022\n",
        "ConnectTimeout 1m30\n",
        "ConnectTimeout 1.5s\n",
        "ConnectTimeout .5s\n",
        "StreamLocalBindMask +0777\n",
        "IPQoS +1 255\n",
        "Host \"quoted host\"\n  User alice\n",
        "Host 'single quoted host'\n  User alice\n",
        "Host escaped\\ host\n  User alice\n",
        "Host example#legacy\n  User alice # comment\n",
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
fn non_utf8_config_is_a_read_error_instead_of_a_panic() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
    let error = lint_file(&path).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
