use sshconfig_lint::lint_str_portable;
use sshconfig_lint::model::Severity;

fn findings_with_code(input: &str, code: &str) -> Vec<sshconfig_lint::model::Finding> {
    lint_str_portable(input)
        .into_iter()
        .filter(|finding| finding.code == code)
        .collect()
}

#[test]
fn misspelled_directives_are_errors_with_a_useful_suggestion() {
    let findings = findings_with_code(
        "HosName server.example.com\nHost work\n  IdentitFile ~/.ssh/id_ed25519\nMatch host internal\n  ProxiJump bastion",
        "UNKNOWN_DIRECTIVE",
    );

    assert_eq!(findings.len(), 3);
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.span.line)
            .collect::<Vec<_>>(),
        vec![1, 3, 5]
    );
    assert!(findings.iter().all(|finding| {
        finding.severity == Severity::Error
            && finding.rule == "unknown-directive"
            && finding.documentation_url()
                == "https://sshconfig-lint.apps.thiering.org/en/rules/unknown-directive"
    }));
    assert!(findings[0].hint.as_deref().unwrap().contains("Hostname"));
    assert!(
        findings[1]
            .hint
            .as_deref()
            .unwrap()
            .contains("IdentityFile")
    );
    assert!(findings[2].hint.as_deref().unwrap().contains("ProxyJump"));
}

#[test]
fn ignore_unknown_applies_only_to_matching_directives_after_it() {
    let findings = findings_with_code(
        "FutureBefore yes\nIgnoreUnknown UseKeychain,Apple*,Future*\nUseKeychain yes\nAppleMultipath no\nFutureAfter yes\nStillWrong yes",
        "UNKNOWN_DIRECTIVE",
    );

    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].span.line, 1);
    assert!(findings[0].message.contains("FutureBefore"));
    assert_eq!(findings[1].span.line, 6);
    assert!(findings[1].message.contains("StillWrong"));
}

#[test]
fn current_openssh_and_common_platform_directives_are_known_case_insensitively() {
    for directive in [
        "AddKeysToAgent",
        "CanonicalizePermittedCNAMEs",
        "ChannelTimeout",
        "EnableEscapeCommandline",
        "HostbasedAcceptedAlgorithms",
        "KnownHostsCommand",
        "NoHostAuthenticationForLocalhost",
        "ObscureKeystrokeTiming",
        "PermitRemoteOpen",
        "RefuseConnection",
        "RequiredRSASize",
        "SecurityKeyProvider",
        "SessionType",
        "WarnWeakCrypto",
        "uSeKeYcHaIn",
        "AppleMultipath",
        "NoHostAuthenticationForProxyCommand",
    ] {
        let source = format!("{directive} yes");
        assert!(
            findings_with_code(&source, "UNKNOWN_DIRECTIVE").is_empty(),
            "{directive} must be recognised"
        );
    }
}

#[test]
fn every_directive_in_the_audited_openssh_keyword_table_is_known() {
    let directives = include_str!("fixtures/openssh_directives_2026_09_03.txt")
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(directives.len(), 128);

    for directive in directives {
        let source = format!("{directive} yes");
        assert!(
            findings_with_code(&source, "UNKNOWN_DIRECTIVE").is_empty(),
            "current OpenSSH directive {directive} was reported as unknown"
        );
    }
}

#[test]
fn deprecated_and_obsolete_options_report_every_occurrence() {
    let directives = [
        "Protocol",
        "Cipher",
        "FallbackToRsh",
        "GlobalKnownHostsFile2",
        "RhostsAuthentication",
        "UserKnownHostsFile2",
        "UseRoaming",
        "UserSH",
        "UsePrivilegedPort",
        "IdentityFile2",
        "KeepAlive",
        "HostbasedKeyTypes",
        "PubkeyAcceptedKeyTypes",
    ];
    let source = directives
        .iter()
        .map(|directive| format!("{directive} legacy"))
        .collect::<Vec<_>>()
        .join("\n");

    let findings = findings_with_code(&source, "DEPRECATED_OPTION");
    assert_eq!(findings.len(), directives.len());
    assert!(findings.iter().all(|finding| {
        finding.severity == Severity::Warning && finding.rule == "deprecated-option"
    }));
    assert!(findings[0].hint.as_deref().unwrap().contains("remove"));
    assert!(
        findings[9]
            .hint
            .as_deref()
            .unwrap()
            .contains("IdentityFile")
    );
    assert!(
        findings[10]
            .hint
            .as_deref()
            .unwrap()
            .contains("TCPKeepAlive")
    );
}

#[test]
fn modern_options_are_not_reported_as_deprecated() {
    for source in [
        "Ciphers aes256-gcm@openssh.com",
        "IdentityFile ~/.ssh/id_ed25519",
        "TCPKeepAlive yes",
        "HostbasedAcceptedAlgorithms ssh-ed25519",
        "PubkeyAcceptedAlgorithms ssh-ed25519",
    ] {
        assert!(findings_with_code(source, "DEPRECATED_OPTION").is_empty());
    }
}

#[test]
fn enabled_control_persist_without_any_possible_master_warns() {
    for source in [
        "ControlPersist yes",
        "ControlPersist 0",
        "Host work\n  ControlPersist 10m",
        "Match host internal\n  ControlPersist \"1h\"",
        "ControlMaster no\nControlMaster auto\nControlPersist yes",
        "ControlMaster no\nHost work\n  ControlMaster auto\n  ControlPersist 10m",
    ] {
        let findings = findings_with_code(source, "CONTROL_PERSIST_UNUSED");
        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].rule, "control-persist-requires-master");
    }
}

#[test]
fn disabled_persist_or_any_possible_master_avoids_false_positives() {
    for source in [
        "ControlPersist no",
        "ControlPersist false",
        "ControlMaster auto\nControlPersist yes",
        "Host defaults\n  ControlMaster auto\nHost work\n  ControlPersist 10m",
        "Include ~/.ssh/config.d/*\nHost work\n  ControlPersist yes",
    ] {
        assert!(
            findings_with_code(source, "CONTROL_PERSIST_UNUSED").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn update_hostkeys_ask_conflicts_with_enabled_persist_in_the_same_scope() {
    for source in [
        "UpdateHostKeys ask\nControlPersist yes",
        "ControlPersist 10m\nUpdateHostKeys \"ask\"",
        "Host work\n  UpdateHostKeys ask\n  ControlPersist 0",
        "Match host internal\n  ControlPersist 1h\n  UpdateHostKeys ask",
    ] {
        let findings = findings_with_code(source, "UPDATE_HOSTKEYS_ASK_PERSIST");
        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].rule, "update-hostkeys-control-persist");
    }
}

#[test]
fn compatible_update_hostkeys_and_separate_scopes_do_not_warn() {
    for source in [
        "UpdateHostKeys yes\nControlPersist yes",
        "UpdateHostKeys ask\nControlPersist no",
        "Host one\n  UpdateHostKeys ask\nHost two\n  ControlPersist yes",
        "UpdateHostKeys ask",
        "ControlPersist yes",
        "UpdateHostKeys yes\nUpdateHostKeys ask\nControlPersist 10m",
        "ControlPersist no\nControlPersist 10m\nUpdateHostKeys ask",
    ] {
        assert!(
            findings_with_code(source, "UPDATE_HOSTKEYS_ASK_PERSIST").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn global_update_hostkeys_and_persist_settings_apply_inside_host_scopes() {
    for source in [
        "UpdateHostKeys ask\nHost work\n  ControlPersist 10m",
        "ControlPersist 10m\nHost work\n  UpdateHostKeys ask",
    ] {
        let findings = findings_with_code(source, "UPDATE_HOSTKEYS_ASK_PERSIST");
        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert_eq!(findings[0].span.line, 3);
    }
}

#[test]
fn explicit_global_values_override_later_host_values_for_the_interaction() {
    for source in [
        "UpdateHostKeys yes\nHost work\n  UpdateHostKeys ask\n  ControlPersist 10m",
        "ControlPersist no\nHost work\n  ControlPersist 10m\n  UpdateHostKeys ask",
    ] {
        assert!(
            findings_with_code(source, "UPDATE_HOSTKEYS_ASK_PERSIST").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn missing_arguments_and_unbalanced_quotes_are_syntax_errors() {
    for (source, expected_line) in [
        ("User", 1),
        (r#"User "unterminated"#, 1),
        ("Host", 1),
        (r#"Host 'unterminated"#, 1),
        ("Include", 1),
        (r#"Include "unterminated"#, 1),
        ("Match", 1),
        (r#"Match host "unterminated"#, 1),
        ("Host work\n  User", 2),
    ] {
        let findings = findings_with_code(source, "INVALID_SYNTAX");
        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert_eq!(findings[0].span.line, expected_line);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].rule, "invalid-syntax");
    }
}

#[test]
fn malformed_known_values_report_one_syntax_error_instead_of_two_diagnostics() {
    for source in ["Port", "Port \"\"", "Port \"unterminated"] {
        let findings = lint_str_portable(source)
            .into_iter()
            .filter(|finding| matches!(finding.code, "INVALID_SYNTAX" | "INVALID_VALUE"))
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert_eq!(findings[0].code, "INVALID_SYNTAX", "{source}: {findings:?}");
    }
}

#[test]
fn valid_empty_segments_and_hashes_do_not_trigger_syntax_errors() {
    for source in [
        r#"Host prefix""suffix"#,
        r#"Host 'quoted host' escaped\ host example#legacy"#,
        r#"Match tagged """#,
        r#"SetEnv EMPTY="#,
        r##"LocalCommand printf "# not a comment""##,
    ] {
        assert!(
            findings_with_code(source, "INVALID_SYNTAX").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn valid_match_conditions_cover_separate_and_equals_forms() {
    for source in [
        "Match all\n  User alice",
        "Match final\n  User alice",
        "Match canonical host *.example.com\n  User alice",
        "Match host=*.example.com user alice\n  Port 22",
        r#"Match exec "test -f ~/.ssh/key" tagged ""
  User alice"#,
        "Match !host old.example originalhost *.example localuser noah localnetwork 192.0.2.0/24 version OpenSSH_*\n  User alice",
        r#"Match command ""
  User alice"#,
    ] {
        assert!(
            findings_with_code(source, "INVALID_MATCH").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn invalid_match_conditions_report_unknown_missing_and_combined_criteria() {
    for source in [
        "Match bogus value",
        "Match host",
        r#"Match host """#,
        "Match exec",
        "Match all host *.example.com",
        "Match host *.example.com all",
        "Match canonical unexpected",
    ] {
        let findings = findings_with_code(source, "INVALID_MATCH");
        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert_eq!(findings[0].span.line, 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].rule, "invalid-match-condition");
    }
}
