use std::fs;

use sshconfig_lint::{lint_str_at_path, lint_str_portable};
use tempfile::TempDir;

fn config_path(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn findings_with_code(input: &str, code: &str) -> Vec<sshconfig_lint::model::Finding> {
    lint_str_portable(input)
        .into_iter()
        .filter(|finding| finding.code == code)
        .collect()
}

#[test]
fn host_with_only_negated_patterns_warns() {
    let findings = findings_with_code("Host !internal !legacy\n  User deploy", "NEGATED_HOST");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 1);
    assert_eq!(findings[0].rule, "negated-only-host");
    assert!(findings[0].message.contains("never matches positively"));
    assert!(findings[0].hint.as_deref().unwrap().contains("*"));
    assert_eq!(
        findings[0].documentation_url(),
        "https://sshconfig-lint.apps.thiering.org/en/rules/negated-only-host"
    );
}

#[test]
fn host_with_a_positive_pattern_does_not_warn() {
    for source in [
        "Host * !internal\n  User deploy",
        "Host production !legacy\n  User deploy",
        "Host production\n  User deploy",
    ] {
        assert!(findings_with_code(source, "NEGATED_HOST").is_empty());
    }
}

#[test]
fn every_negated_only_host_block_gets_its_own_finding() {
    let findings = findings_with_code(
        "Host !one\n  User one\nHost valid !two\n  User two\nHost !three !four\n  User three",
        "NEGATED_HOST",
    );

    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.span.line)
            .collect::<Vec<_>>(),
        vec![1, 5]
    );
}

#[test]
fn proxy_command_and_jump_conflict_in_the_same_scope() {
    let findings = findings_with_code(
        "ProxyCommand ssh bastion -W %h:%p\nProxyJump jump.example.com",
        "PROXY_CONFLICT",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 2);
    assert!(findings[0].message.contains("ProxyCommand"));
    assert!(findings[0].message.contains("line 1"));
    assert!(findings[0].message.contains("ProxyJump"));
}

#[test]
fn proxy_conflict_reports_whichever_directive_appears_second() {
    let findings = findings_with_code(
        "Host production\n  ProxyJump jump.example.com\n  ProxyCommand ssh bastion -W %h:%p",
        "PROXY_CONFLICT",
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 3);
    assert!(findings[0].message.contains("ProxyJump"));
    assert!(findings[0].message.contains("line 2"));
}

#[test]
fn proxy_none_still_competes_with_the_other_option() {
    for source in [
        "ProxyCommand none\nProxyJump jump.example.com",
        "ProxyJump none\nProxyCommand ssh bastion -W %h:%p",
    ] {
        assert_eq!(findings_with_code(source, "PROXY_CONFLICT").len(), 1);
    }
}

#[test]
fn proxy_options_in_separate_scopes_do_not_conflict() {
    let source =
        "Host one\n  ProxyCommand ssh one -W %h:%p\nHost two\n  ProxyJump jump.example.com";
    assert!(findings_with_code(source, "PROXY_CONFLICT").is_empty());
}

#[test]
fn proxy_conflicts_are_checked_in_match_blocks() {
    let findings = findings_with_code(
        "Match host internal.example.com\n  ProxyCommand ssh bastion -W %h:%p\n  ProxyJump jump.example.com",
        "PROXY_CONFLICT",
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 3);
}

#[test]
fn local_command_without_an_enabling_option_warns() {
    let findings = findings_with_code(
        "LocalCommand notify-send connected\nHost production\n  LocalCommand logger connected",
        "LOCAL_COMMAND_DISABLED",
    );

    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.span.line)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert!(findings[0].message.contains("PermitLocalCommand"));
}

#[test]
fn explicit_disabled_permit_local_command_still_warns() {
    for value in ["no", "false", "NO"] {
        let source = format!("PermitLocalCommand {value}\nLocalCommand logger connected");
        assert_eq!(
            findings_with_code(&source, "LOCAL_COMMAND_DISABLED").len(),
            1
        );
    }
}

#[test]
fn any_possible_permit_local_command_enablement_suppresses_the_warning() {
    for value in ["yes", "true", "YES"] {
        let source = format!(
            "Host maybe\n  PermitLocalCommand {value}\nHost production\n  LocalCommand logger connected"
        );
        assert!(findings_with_code(&source, "LOCAL_COMMAND_DISABLED").is_empty());
    }
}

#[test]
fn unresolved_includes_make_local_command_check_conservative() {
    let source = "Include ~/.ssh/conf.d/*\nHost production\n  LocalCommand logger connected";
    assert!(findings_with_code(source, "LOCAL_COMMAND_DISABLED").is_empty());
}

fn filesystem_findings(
    input: &str,
    code: &str,
    temp: &TempDir,
) -> Vec<sshconfig_lint::model::Finding> {
    let config_path = temp.path().join("config");
    lint_str_at_path(input, &config_path, false)
        .into_iter()
        .filter(|finding| finding.code == code)
        .collect()
}

#[test]
fn revoked_host_keys_requires_every_explicit_file_to_be_readable() {
    let temp = TempDir::new().unwrap();
    let existing = temp.path().join("revoked keys");
    let missing = temp.path().join("missing.krl");
    fs::write(&existing, "").unwrap();

    let source = format!(
        "RevokedHostKeys \"{}\" {}",
        config_path(&existing),
        config_path(&missing)
    );
    let findings = filesystem_findings(&source, "REVOKED_HOST_KEYS_UNREADABLE", &temp);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 1);
    assert!(findings[0].message.contains(&config_path(&missing)));
    assert!(findings[0].message.contains("refused for all hosts"));
}

#[test]
fn revoked_host_keys_accepts_existing_files_and_none() {
    let temp = TempDir::new().unwrap();
    let existing = temp.path().join("revoked.krl");
    fs::write(&existing, "").unwrap();

    for source in [
        format!("RevokedHostKeys {}", existing.display()),
        "RevokedHostKeys none".to_string(),
        "RevokedHostKeys NoNe".to_string(),
    ] {
        assert!(filesystem_findings(&source, "REVOKED_HOST_KEYS_UNREADABLE", &temp).is_empty());
    }
}

#[test]
fn revoked_host_keys_rejects_a_directory_as_unreadable_key_data() {
    let temp = TempDir::new().unwrap();
    let findings = filesystem_findings(
        &format!("RevokedHostKeys {}", temp.path().display()),
        "REVOKED_HOST_KEYS_UNREADABLE",
        &temp,
    );
    assert_eq!(findings.len(), 1);
}

#[test]
fn dynamic_revoked_host_key_paths_are_not_guessed() {
    let temp = TempDir::new().unwrap();
    for value in ["%d/.ssh/revoked", "${HOME}/.ssh/revoked"] {
        assert!(
            filesystem_findings(
                &format!("RevokedHostKeys {value}"),
                "REVOKED_HOST_KEYS_UNREADABLE",
                &temp,
            )
            .is_empty()
        );
    }
}

#[test]
fn certificate_file_requires_an_existing_regular_file() {
    let temp = TempDir::new().unwrap();
    let existing = temp.path().join("id-cert.pub");
    let missing = temp.path().join("old-cert.pub");
    fs::write(&existing, "certificate").unwrap();

    let source = format!(
        "CertificateFile {}\nCertificateFile {}",
        existing.display(),
        missing.display()
    );
    let findings = filesystem_findings(&source, "MISSING_CERTIFICATE", &temp);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 2);
    assert!(findings[0].message.contains(&missing.display().to_string()));
}

#[test]
fn certificate_file_rejects_directories_and_does_not_treat_none_as_a_sentinel() {
    let temp = TempDir::new().unwrap();
    assert_eq!(
        filesystem_findings(
            &format!("CertificateFile {}", temp.path().display()),
            "MISSING_CERTIFICATE",
            &temp,
        )
        .len(),
        1
    );
    assert_eq!(
        filesystem_findings("CertificateFile none", "MISSING_CERTIFICATE", &temp).len(),
        1,
        "OpenSSH supports none for IdentityFile and RevokedHostKeys, not CertificateFile"
    );
}

#[test]
fn dynamic_certificate_paths_are_not_guessed() {
    let temp = TempDir::new().unwrap();
    for value in ["%d/.ssh/id-cert.pub", "${HOME}/.ssh/id-cert.pub"] {
        assert!(
            filesystem_findings(
                &format!("CertificateFile {value}"),
                "MISSING_CERTIFICATE",
                &temp,
            )
            .is_empty()
        );
    }
}

#[test]
fn portable_lint_skips_both_filesystem_checks() {
    let findings = lint_str_portable(
        "RevokedHostKeys /definitely/missing/revoked.krl\nCertificateFile /definitely/missing/id-cert.pub",
    );
    assert!(!findings.iter().any(|finding| {
        matches!(
            finding.code,
            "REVOKED_HOST_KEYS_UNREADABLE" | "MISSING_CERTIFICATE"
        )
    }));
}

#[test]
fn common_percent_token_group_accepts_every_documented_token() {
    let tokens = "%% %C %d %h %i %j %k %L %l %n %p %r %u";
    for directive in [
        "CertificateFile",
        "ControlPath",
        "IdentityAgent",
        "IdentityFile",
        "KnownHostsCommand",
        "RemoteCommand",
        "RevokedHostKeys",
        "UserKnownHostsFile",
        "VersionAddendum",
    ] {
        let source = format!("{directive} {tokens}");
        assert!(
            findings_with_code(&source, "INVALID_TOKEN").is_empty(),
            "{directive}"
        );
    }
}

#[test]
fn special_directives_accept_their_documented_percent_tokens() {
    let sources = [
        "Hostname %%-%h",
        "KnownHostsCommand helper %% %C %d %f %H %h %I %i %j %K %k %L %l %n %p %r %t %u",
        "LocalCommand helper %% %C %d %f %H %h %I %i %j %K %k %L %l %n %p %r %T %t %u",
        "ProxyCommand ssh jump -W %%:%h:%n:%p:%r",
        "ProxyJump %r@%h:%p",
        "Include %d/.ssh/config.d/%%-%h",
    ];

    for source in sources {
        assert!(
            findings_with_code(source, "INVALID_TOKEN").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn directive_specific_unknown_tokens_are_errors() {
    let cases = [
        ("Hostname %n", "%n"),
        ("ProxyCommand ssh jump -W %C", "%C"),
        ("ProxyJump %C", "%C"),
        ("CertificateFile %T/id-cert.pub", "%T"),
        ("KnownHostsCommand helper %T", "%T"),
        ("LocalCommand helper %Z", "%Z"),
        ("ControlPath ~/.ssh/%c", "%c"),
        ("Include ~/.ssh/config.d/%Z", "%Z"),
    ];

    for (source, token) in cases {
        let findings = findings_with_code(source, "INVALID_TOKEN");
        assert_eq!(findings.len(), 1, "{source}: {findings:?}");
        assert!(findings[0].message.contains(token));
        assert_eq!(findings[0].severity, sshconfig_lint::model::Severity::Error);
        assert_eq!(findings[0].rule, "invalid-percent-token");
    }
}

#[test]
fn dangling_percent_and_multiple_bad_tokens_report_once_per_line() {
    for source in ["Hostname host%", "LocalCommand echo %Z %Q"] {
        assert_eq!(findings_with_code(source, "INVALID_TOKEN").len(), 1);
    }
}

#[test]
fn escaped_percent_sequences_are_not_mistaken_for_tokens() {
    for source in ["Hostname %%h", "Hostname %%%h", "LocalCommand echo %%%%"] {
        assert!(
            findings_with_code(source, "INVALID_TOKEN").is_empty(),
            "{source}"
        );
    }
}

#[test]
fn percent_tokens_are_checked_recursively_in_host_and_match_scopes() {
    let findings = findings_with_code(
        "Host production\n  Hostname %n\nMatch host internal.example.com\n  ProxyCommand ssh jump -W %C",
        "INVALID_TOKEN",
    );
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.span.line)
            .collect::<Vec<_>>(),
        vec![2, 4]
    );
}

#[test]
fn match_exec_uses_the_documented_common_percent_tokens() {
    assert!(
        findings_with_code(
            "Match exec \"test %d = /home/deploy && test %h = production\"\n  User deploy",
            "INVALID_TOKEN",
        )
        .is_empty()
    );

    let findings = findings_with_code(
        "Match host production exec \"test %T = NONE\"\n  User deploy",
        "INVALID_TOKEN",
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].span.line, 1);
    assert!(findings[0].message.contains("%T"));
    assert!(findings[0].message.contains("Match exec"));
}

#[test]
fn resolved_include_can_enable_local_command() {
    let temp = TempDir::new().unwrap();
    let config = temp.path().join("config");
    fs::write(temp.path().join("local.conf"), "PermitLocalCommand yes\n").unwrap();

    let findings = lint_str_at_path(
        "Include local.conf\nHost production\n  LocalCommand logger connected",
        &config,
        true,
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == "LOCAL_COMMAND_DISABLED")
    );
}

#[test]
fn resolved_include_without_enablement_keeps_local_command_warning() {
    let temp = TempDir::new().unwrap();
    let config = temp.path().join("config");
    fs::write(
        temp.path().join("defaults.conf"),
        "ServerAliveInterval 30\n",
    )
    .unwrap();

    let findings = lint_str_at_path(
        "Include defaults.conf\nHost production\n  LocalCommand logger connected",
        &config,
        true,
    );
    let local = findings
        .iter()
        .filter(|finding| finding.code == "LOCAL_COMMAND_DISABLED")
        .collect::<Vec<_>>();
    assert_eq!(local.len(), 1);
    assert_eq!(
        local[0].span.file.as_deref(),
        Some(config.to_str().unwrap())
    );
    assert_eq!(local[0].span.line, 3);
}

#[test]
fn certificate_file_accepts_a_quoted_existing_path_with_spaces() {
    let temp = TempDir::new().unwrap();
    let certificate = temp.path().join("work key-cert.pub");
    fs::write(&certificate, "certificate").unwrap();

    let source = format!("CertificateFile \"{}\"", config_path(&certificate));
    assert!(filesystem_findings(&source, "MISSING_CERTIFICATE", &temp).is_empty());
}
