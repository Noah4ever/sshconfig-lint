use sshconfig_lint::model::Severity;
use sshconfig_lint::{lint_str, lint_str_portable};

fn invalid_value_findings(input: &str) -> Vec<sshconfig_lint::model::Finding> {
    lint_str_portable(input)
        .into_iter()
        .filter(|finding| finding.code == "INVALID_VALUE")
        .collect()
}

fn directive_input(directive: &str, value: &str) -> String {
    if value.is_empty() {
        directive.to_string()
    } else {
        format!("{directive} {value}")
    }
}

fn assert_invalid(directive: &str, value: &str, expected: &str, hint: &str) {
    let findings = invalid_value_findings(&directive_input(directive, value));
    assert_eq!(
        findings.len(),
        1,
        "{directive} {value:?} should produce exactly one INVALID_VALUE finding, got: {findings:?}"
    );
    let finding = &findings[0];
    assert_eq!(finding.severity, Severity::Error);
    assert_eq!(finding.rule, "invalid-directive-value");
    assert_eq!(finding.span.line, 1);
    assert_eq!(
        finding.message,
        format!("invalid value '{value}' for {directive}; expected {expected}")
    );
    assert_eq!(finding.hint.as_deref(), Some(hint));
    assert_eq!(
        finding.documentation_url(),
        "https://sshconfig-lint.apps.thiering.org/en/rules/invalid-directive-value"
    );
}

#[test]
fn port_accepts_boundary_and_common_values() {
    for value in ["1", "22", "65535", "+22", "00022", "\"22\""] {
        let findings = invalid_value_findings(&format!("Port {value}"));
        assert!(
            findings.is_empty(),
            "Port {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn port_rejects_out_of_range_and_non_integer_values() {
    for value in [
        "0", "65536", "-1", "22.5", "ssh", "22 extra", "\"\"", "\"22", "",
    ] {
        assert_invalid(
            "Port",
            value,
            "an integer from 1 to 65535",
            "use a port number from 1 to 65535",
        );
    }
}

#[test]
fn integer_directives_accept_boundaries_signs_and_quotes() {
    let cases = [
        ("ConnectionAttempts", "1"),
        ("ConnectionAttempts", "+1"),
        ("ConnectionAttempts", "2147483647"),
        ("ConnectionAttempts", "\"1\""),
        ("NumberOfPasswordPrompts", "0"),
        ("NumberOfPasswordPrompts", "+0"),
        ("NumberOfPasswordPrompts", "2147483647"),
        ("ServerAliveCountMax", "0"),
        ("ServerAliveCountMax", "+0"),
        ("CanonicalizeMaxDots", "0"),
        ("CanonicalizeMaxDots", "0003"),
    ];

    for (directive, value) in cases {
        let findings = invalid_value_findings(&format!("{directive} {value}"));
        assert!(
            findings.is_empty(),
            "{directive} {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn integer_directives_reject_invalid_values_and_overflow() {
    let non_negative = [
        "NumberOfPasswordPrompts",
        "ServerAliveCountMax",
        "CanonicalizeMaxDots",
    ];

    for value in [
        "0",
        "-1",
        "1.5",
        "none",
        "1 2",
        "\"\"",
        "\"1",
        "",
        "2147483648",
        "999999999999999999999",
    ] {
        assert_invalid(
            "ConnectionAttempts",
            value,
            "an integer from 1 to 2147483647",
            "use at least 1 connection attempt",
        );
    }

    for directive in non_negative {
        for value in [
            "-1",
            "1.5",
            "none",
            "1 2",
            "\"\"",
            "\"1",
            "",
            "2147483648",
            "999999999999999999999",
        ] {
            assert_invalid(
                directive,
                value,
                "an integer from 0 to 2147483647",
                "use a non-negative integer no greater than 2147483647",
            );
        }
    }
}

#[test]
fn time_directives_accept_openssh_time_formats() {
    for directive in ["ConnectTimeout", "ServerAliveInterval"] {
        for value in [
            "0",
            "15",
            "2147483647",
            "none",
            "1m30s",
            "1M30S",
            "1.5s",
            ".5s",
            "1m30",
            "\"1m\"",
        ] {
            let findings = invalid_value_findings(&format!("{directive} {value}"));
            assert!(
                findings.is_empty(),
                "{directive} {value} should be valid, got: {findings:?}"
            );
        }
    }
}

#[test]
fn time_directives_reject_bad_syntax_negatives_and_overflow() {
    for directive in ["ConnectTimeout", "ServerAliveInterval"] {
        for value in [
            "-1",
            "+1",
            "NONE",
            "1.",
            "1.5m",
            "1e3",
            "1m30x",
            "1m 2m",
            "\"\"",
            "\"1m",
            "",
            "2147483648",
            "999999999999999999999w",
        ] {
            assert_invalid(
                directive,
                value,
                "a non-negative time value or none",
                "use seconds, a duration such as 1m30s, or none",
            );
        }
    }
}

#[test]
fn stream_local_bind_mask_accepts_complete_octal_values() {
    for value in ["0", "7", "0177", "777", "+0777", "0000", "\"0177\""] {
        let findings = invalid_value_findings(&format!("StreamLocalBindMask {value}"));
        assert!(
            findings.is_empty(),
            "StreamLocalBindMask {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn stream_local_bind_mask_rejects_partial_non_octal_and_large_values() {
    for value in [
        "-1",
        "0788",
        "888",
        "1000",
        "777junk",
        "0o177",
        "1.5",
        "0177 0777",
        "\"\"",
        "\"0177",
        "",
    ] {
        assert_invalid(
            "StreamLocalBindMask",
            value,
            "an octal mask from 0000 to 0777",
            "use a complete octal value from 0000 to 0777, for example 0177",
        );
    }
}

#[test]
fn ipqos_accepts_names_numbers_and_one_or_two_arguments() {
    let names = [
        "none",
        "af11",
        "af12",
        "af13",
        "af21",
        "af22",
        "af23",
        "af31",
        "af32",
        "af33",
        "af41",
        "af42",
        "af43",
        "cs0",
        "cs1",
        "cs2",
        "cs3",
        "cs4",
        "cs5",
        "cs6",
        "cs7",
        "ef",
        "le",
        "va",
        "lowdelay",
        "throughput",
        "reliability",
    ];

    for value in names {
        let findings = invalid_value_findings(&format!("IPQoS {value}"));
        assert!(findings.is_empty(), "IPQoS {value} should be accepted");
    }

    for value in [
        "0",
        "255",
        "+1",
        "01",
        "AF21",
        "af21 cs1",
        "0 255",
        "\"af21\" \"cs1\"",
    ] {
        let findings = invalid_value_findings(&format!("IPQoS {value}"));
        assert!(
            findings.is_empty(),
            "IPQoS {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn ipqos_rejects_bad_names_ranges_and_argument_counts() {
    for value in [
        "-1",
        "256",
        "1.5",
        "0xff",
        "bogus",
        "",
        "af21 bogus",
        "af21 cs1 ef",
        "999999999999999999999",
    ] {
        assert_invalid(
            "IPQoS",
            value,
            "one or two DSCP names or numbers from 0 to 255",
            "use a DSCP name such as af21, a number from 0 to 255, or none",
        );
    }
}

#[test]
fn numeric_validation_covers_root_host_and_match_scopes() {
    let findings = invalid_value_findings(
        "\
ConnectionAttempts 0
Host example.com
  ServerAliveCountMax -1
Match host internal.example.com
  StreamLocalBindMask 0788
  IPQoS af21 bogus
",
    );

    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.span.line, finding.message.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (
                1,
                "invalid value '0' for ConnectionAttempts; expected an integer from 1 to 2147483647"
            ),
            (
                3,
                "invalid value '-1' for ServerAliveCountMax; expected an integer from 0 to 2147483647"
            ),
            (
                5,
                "invalid value '0788' for StreamLocalBindMask; expected an octal mask from 0000 to 0777"
            ),
            (
                6,
                "invalid value 'af21 bogus' for IPQoS; expected one or two DSCP names or numbers from 0 to 255"
            ),
        ]
    );
}

#[test]
fn port_directive_name_is_case_insensitive() {
    let findings = invalid_value_findings("pOrT 70000");

    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("for Port"));
}

#[test]
fn port_validation_covers_root_host_and_match_scopes() {
    let findings = invalid_value_findings(
        "\
Port 0
Host example.com
  Port nope
Match host internal.example.com
  Port 65536
",
    );

    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.span.line)
            .collect::<Vec<_>>(),
        vec![1, 3, 5]
    );
}

#[test]
fn port_validation_runs_for_untitled_editor_buffers() {
    let findings = lint_str_portable("Host example.com\n  Port 0");

    assert!(findings.iter().any(|finding| {
        finding.code == "INVALID_VALUE"
            && finding.rule == "invalid-directive-value"
            && finding.span.line == 2
    }));
}

#[test]
fn identity_file_none_is_accepted_case_insensitively() {
    let findings = lint_str(
        "\
IdentityFile none
Host example.com
  IdentityFile NoNe
",
    );

    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "MISSING_IDENTITY"),
        "OpenSSH's IdentityFile none sentinel must not be treated as a path: {findings:?}"
    );
}
