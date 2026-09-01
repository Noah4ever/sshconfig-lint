use sshconfig_lint::model::Severity;
use sshconfig_lint::{lint_str, lint_str_portable};

fn invalid_value_findings(input: &str) -> Vec<sshconfig_lint::model::Finding> {
    lint_str_portable(input)
        .into_iter()
        .filter(|finding| finding.code == "INVALID_VALUE")
        .collect()
}

#[test]
fn port_accepts_boundary_and_common_values() {
    for value in ["1", "22", "65535"] {
        let findings = invalid_value_findings(&format!("Port {value}"));
        assert!(
            findings.is_empty(),
            "Port {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn port_rejects_out_of_range_and_non_integer_values() {
    for value in ["0", "65536", "-1", "22.5", "ssh", ""] {
        let input = if value.is_empty() {
            "Port".to_string()
        } else {
            format!("Port {value}")
        };
        let findings = invalid_value_findings(&input);

        assert_eq!(
            findings.len(),
            1,
            "Port {value:?} should produce exactly one INVALID_VALUE finding, got: {findings:?}"
        );
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].rule, "invalid-directive-value");
        assert_eq!(findings[0].span.line, 1);
        assert_eq!(
            findings[0].message,
            format!("invalid value '{value}' for Port; expected an integer from 1 to 65535")
        );
        assert_eq!(
            findings[0].hint.as_deref(),
            Some("use a port number from 1 to 65535")
        );
        assert_eq!(
            findings[0].documentation_url(),
            "https://sshconfig-lint.apps.thiering.org/en/rules/invalid-directive-value"
        );
    }
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
