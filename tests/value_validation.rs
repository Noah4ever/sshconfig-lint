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
    for value in ["0", "65536", "-1", "22.5", "ssh", "22 extra"] {
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
    for directive in ["ConnectTimeout", "ServerAliveInterval", "ForwardX11Timeout"] {
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
    for directive in ["ConnectTimeout", "ServerAliveInterval", "ForwardX11Timeout"] {
        for value in [
            "-1",
            "+1",
            "NONE",
            "1.",
            "1.5m",
            "1e3",
            "1m30x",
            "1m 2m",
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
fn control_persist_accepts_flags_and_time_values() {
    for value in ["yes", "true", "no", "false", "0", "10m", "1.5s", "\"1h\""] {
        let findings = invalid_value_findings(&format!("ControlPersist {value}"));
        assert!(
            findings.is_empty(),
            "ControlPersist {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn control_persist_rejects_invalid_flags_times_and_arguments() {
    for value in ["none", "-1", "+1", "1.5m", "maybe", "1m 2m"] {
        assert_invalid(
            "ControlPersist",
            value,
            "yes, no, or a non-negative time value",
            "use yes, no, seconds, or a duration such as 10m",
        );
    }
}

#[test]
fn required_rsa_size_only_accepts_documented_raised_limits() {
    for value in ["1024", "+2048", "4096", "2147483647", "\"3072\""] {
        let findings = invalid_value_findings(&format!("RequiredRSASize {value}"));
        assert!(
            findings.is_empty(),
            "RequiredRSASize {value} should be valid, got: {findings:?}"
        );
    }

    for value in [
        "0",
        "768",
        "1023",
        "-1",
        "2048.5",
        "none",
        "2048 extra",
        "2147483648",
    ] {
        assert_invalid(
            "RequiredRSASize",
            value,
            "an integer from 1024 to 2147483647",
            "use 1024 or a stronger minimum such as 2048 or 3072",
        );
    }
}

const BOOLEAN_FLAG_DIRECTIVES: &[&str] = &[
    "BatchMode",
    "CanonicalizeFallbackLocal",
    "CheckHostIP",
    "ClearAllForwardings",
    "EnableEscapeCommandline",
    "EnableSSHKeysign",
    "ExitOnForwardFailure",
    "ForkAfterAuthentication",
    "ForwardX11",
    "ForwardX11Trusted",
    "GatewayPorts",
    "GSSAPIAuthentication",
    "GSSAPIDelegateCredentials",
    "HashKnownHosts",
    "HostbasedAuthentication",
    "IdentitiesOnly",
    "KbdInteractiveAuthentication",
    "NoHostAuthenticationForLocalhost",
    "PasswordAuthentication",
    "PermitLocalCommand",
    "ProxyUseFdpass",
    "StdinNull",
    "StreamLocalBindUnlink",
    "TCPKeepAlive",
    "VisualHostKey",
];

#[test]
fn boolean_flags_accept_all_openssh_spellings_case_insensitively() {
    for directive in BOOLEAN_FLAG_DIRECTIVES {
        for value in ["yes", "no", "true", "false", "YES", "False", "\"yes\""] {
            let findings = invalid_value_findings(&format!("{directive} {value}"));
            assert!(
                findings.is_empty(),
                "{directive} {value} should be valid, got: {findings:?}"
            );
        }
    }
}

#[test]
fn boolean_flags_reject_common_near_misses_and_extra_values() {
    for directive in BOOLEAN_FLAG_DIRECTIVES {
        for value in ["on", "off", "enabled", "1", "maybe", "yes no"] {
            assert_invalid(
                directive,
                value,
                "one of: true, false, yes, no",
                "use yes or no; true and false are also accepted",
            );
        }
    }
}

#[test]
fn obscure_keystroke_timing_accepts_flags_and_documented_interval_range() {
    for value in [
        "yes",
        "no",
        "true",
        "false",
        "interval:1",
        "interval:20",
        "interval:1000",
        "\"interval:50\"",
    ] {
        let findings = invalid_value_findings(&format!("ObscureKeystrokeTiming {value}"));
        assert!(
            findings.is_empty(),
            "ObscureKeystrokeTiming {value} should be valid, got: {findings:?}"
        );
    }
}

#[test]
fn obscure_keystroke_timing_rejects_invalid_and_out_of_range_intervals() {
    for value in [
        "interval:0",
        "interval:1001",
        "interval:-1",
        "interval:1.5",
        "interval:",
        "interval:20 extra",
        "auto",
    ] {
        assert_invalid(
            "ObscureKeystrokeTiming",
            value,
            "yes, no, or interval:1 through interval:1000",
            "use yes, no, or an interval in milliseconds such as interval:20",
        );
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

const ENUM_CASES: &[(&str, &[&str], &str, &str)] = &[
    (
        "AddressFamily",
        &["any", "inet", "inet6"],
        "one of: any, inet, inet6",
        "use any, inet, or inet6",
    ),
    (
        "RequestTTY",
        &["true", "false", "yes", "no", "force", "auto"],
        "one of: true, false, yes, no, force, auto",
        "use yes, no, force, or auto; true and false are also accepted",
    ),
    (
        "SessionType",
        &["none", "subsystem", "default"],
        "one of: none, subsystem, default",
        "use none, subsystem, or default",
    ),
    (
        "ControlMaster",
        &["true", "false", "yes", "no", "auto", "ask", "autoask"],
        "one of: true, false, yes, no, auto, ask, autoask",
        "use yes, no, auto, ask, or autoask; true and false are also accepted",
    ),
    (
        "CanonicalizeHostname",
        &["true", "false", "yes", "no", "always"],
        "one of: true, false, yes, no, always",
        "use yes, no, or always; true and false are also accepted",
    ),
    (
        "StrictHostKeyChecking",
        &["true", "false", "yes", "no", "ask", "off", "accept-new"],
        "one of: true, false, yes, no, ask, off, accept-new",
        "use yes, ask, accept-new, no, or off; true and false are also accepted",
    ),
    (
        "UpdateHostKeys",
        &["true", "false", "yes", "no", "ask"],
        "one of: true, false, yes, no, ask",
        "use yes, no, or ask; true and false are also accepted",
    ),
    (
        "VerifyHostKeyDNS",
        &["true", "false", "yes", "no", "ask"],
        "one of: true, false, yes, no, ask",
        "use yes, no, or ask; true and false are also accepted",
    ),
    (
        "Tunnel",
        &["ethernet", "point-to-point", "true", "false", "yes", "no"],
        "one of: ethernet, point-to-point, true, false, yes, no",
        "use ethernet, point-to-point, yes, or no; true and false are also accepted",
    ),
    (
        "LogLevel",
        &[
            "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3",
        ],
        "one of: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, DEBUG3",
        "use a log level from QUIET through DEBUG3",
    ),
    (
        "SyslogFacility",
        &[
            "DAEMON", "USER", "AUTH", "AUTHPRIV", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4",
            "LOCAL5", "LOCAL6", "LOCAL7",
        ],
        "one of: DAEMON, USER, AUTH, AUTHPRIV, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7",
        "use DAEMON, USER, AUTH, AUTHPRIV, or LOCAL0 through LOCAL7",
    ),
    (
        "PubkeyAuthentication",
        &["true", "false", "yes", "no", "unbound", "host-bound"],
        "one of: true, false, yes, no, unbound, host-bound",
        "use yes, no, unbound, or host-bound; true and false are also accepted",
    ),
    (
        "Compression",
        &["yes", "no"],
        "one of: yes, no",
        "use yes or no",
    ),
    (
        "WarnWeakCrypto",
        &["true", "false", "yes", "no", "no-pq-kex"],
        "one of: true, false, yes, no, no-pq-kex",
        "use yes, no, or no-pq-kex; true and false are also accepted",
    ),
];

#[test]
fn enumerated_directives_accept_every_openssh_value() {
    for (directive, values, _, _) in ENUM_CASES {
        for value in *values {
            for rendered in [
                value.to_string(),
                value.to_ascii_uppercase(),
                format!("\"{value}\""),
            ] {
                let findings = invalid_value_findings(&format!("{directive} {rendered}"));
                assert!(
                    findings.is_empty(),
                    "{directive} {rendered} should be accepted, got: {findings:?}"
                );
            }
        }
    }
}

#[test]
fn enumerated_directives_reject_unknown_and_extra_values() {
    for (directive, _, expected, hint) in ENUM_CASES {
        for value in ["bogus", "yes extra"] {
            assert_invalid(directive, value, expected, hint);
        }
    }
}

#[test]
fn enumerated_directives_reject_near_miss_spellings_and_out_of_range_names() {
    let cases = [
        ("AddressFamily", "ipv4"),
        ("RequestTTY", "always"),
        ("SessionType", "shell"),
        ("ControlMaster", "auto-ask"),
        ("CanonicalizeHostname", "auto"),
        ("StrictHostKeyChecking", "accept_new"),
        ("UpdateHostKeys", "confirm"),
        ("VerifyHostKeyDNS", "secure"),
        ("Tunnel", "pointtopoint"),
        ("LogLevel", "DEBUG4"),
        ("SyslogFacility", "LOCAL8"),
        ("PubkeyAuthentication", "bound"),
        ("Compression", "auto"),
        ("WarnWeakCrypto", "pq-only"),
    ];

    for (directive, value) in cases {
        let (_, _, expected, hint) = ENUM_CASES
            .iter()
            .find(|(candidate, _, _, _)| *candidate == directive)
            .expect("test case must have a value specification");
        assert_invalid(directive, value, expected, hint);
    }
}

#[test]
fn modern_and_platform_specific_values_are_accepted_without_version_gating() {
    for source in [
        "StrictHostKeyChecking accept-new",
        "PubkeyAuthentication unbound",
        "PubkeyAuthentication host-bound",
        "SyslogFacility AUTHPRIV",
    ] {
        assert!(
            invalid_value_findings(source).is_empty(),
            "sshconfig-lint should accept modern or platform-specific OpenSSH syntax: {source}"
        );
    }
}

#[test]
fn enumerated_validation_covers_root_host_and_match_scopes() {
    let findings = invalid_value_findings(
        "\
AddressFamily ipv4
Host example.com
  ControlMaster auto-ask
Match host internal.example.com
  PubkeyAuthentication bound
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
                "invalid value 'ipv4' for AddressFamily; expected one of: any, inet, inet6"
            ),
            (
                3,
                "invalid value 'auto-ask' for ControlMaster; expected one of: true, false, yes, no, auto, ask, autoask"
            ),
            (
                5,
                "invalid value 'bound' for PubkeyAuthentication; expected one of: true, false, yes, no, unbound, host-bound"
            ),
        ]
    );
}
