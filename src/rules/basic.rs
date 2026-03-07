use std::collections::HashMap;
use std::path::Path;

use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

/// Warns when multiple Host blocks have the same pattern.
pub struct DuplicateHost;

impl Rule for DuplicateHost {
    fn name(&self) -> &'static str {
        "duplicate-host"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut seen: HashMap<String, Span> = HashMap::new();
        let mut findings = Vec::new();

        for item in &config.items {
            if let Item::HostBlock { patterns, span, .. } = item {
                for pattern in patterns {
                    if let Some(first_span) = seen.get(pattern) {
                        findings.push(
                            Finding::new(
                                Severity::Warning,
                                "duplicate-host",
                                "DUP_HOST",
                                format!(
                                    "duplicate Host block '{}' (first seen at line {})",
                                    pattern, first_span.line
                                ),
                                span.clone(),
                            )
                            .with_hint("remove one of the duplicate Host blocks"),
                        );
                    } else {
                        seen.insert(pattern.clone(), span.clone());
                    }
                }
            }
        }

        findings
    }
}

/// Errors when an IdentityFile points to a file that doesn't exist.
/// Skips paths containing `%` or `${` (template variables).
pub struct IdentityFileExists;

impl Rule for IdentityFileExists {
    fn name(&self) -> &'static str {
        "identity-file-exists"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_identity_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_identity_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } if key.eq_ignore_ascii_case("IdentityFile") => {
                check_identity_file(value, span, findings);
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_identity_findings(items, findings);
            }
            _ => {}
        }
    }
}

fn check_identity_file(value: &str, span: &Span, findings: &mut Vec<Finding>) {
    // Skip template variables
    if value.contains('%') || value.contains("${") {
        return;
    }

    let expanded = if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(rest)
        } else {
            return; // Can't resolve ~ without home dir
        }
    } else {
        Path::new(value).to_path_buf()
    };

    if !expanded.exists() {
        findings.push(
            Finding::new(
                Severity::Error,
                "identity-file-exists",
                "MISSING_IDENTITY",
                format!("IdentityFile not found: {}", value),
                span.clone(),
            )
            .with_hint("check the path or remove the directive"),
        );
    }
}

/// Warns when `Host *` appears before more specific Host blocks.
/// In OpenSSH, first match wins, so `Host *` should usually come last.
pub struct WildcardHostOrder;

impl Rule for WildcardHostOrder {
    fn name(&self) -> &'static str {
        "wildcard-host-order"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut wildcard_span: Option<Span> = None;

        for item in &config.items {
            if let Item::HostBlock { patterns, span, .. } = item {
                for pattern in patterns {
                    if pattern == "*" {
                        if wildcard_span.is_none() {
                            wildcard_span = Some(span.clone());
                        }
                    } else if let Some(ref ws) = wildcard_span {
                        findings.push(Finding::new(
                            Severity::Warning,
                            "wildcard-host-order",
                            "WILDCARD_ORDER",
                            format!(
                                "Host '{}' appears after 'Host *' (line {}); it will never match because Host * already matched",
                                pattern, ws.line
                            ),
                            span.clone(),
                        ).with_hint("move Host * to the end of the file"));
                    }
                }
            }
        }

        findings
    }
}

pub struct DeprecatedWeakAlgorithms;

/// Directives whose values are comma-separated algorithm lists.
const ALGORITHM_DIRECTIVES: &[&str] = &[
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes",
    "casignaturealgorithms",
];

/// Known deprecated or weak algorithms.
const WEAK_ALGORITHMS: &[&str] = &[
    // Ciphers
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "rijndael-cbc@lysator.liu.se",
    // MACs
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-64-etm@openssh.com",
    // Key exchange
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    // Host key / signature
    "ssh-dss",
    "ssh-rsa",
];

impl Rule for DeprecatedWeakAlgorithms {
    fn name(&self) -> &'static str {
        "deprecated-weak-algorithms"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_weak_algorithm_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_weak_algorithm_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } if ALGORITHM_DIRECTIVES
                .iter()
                .any(|d| d.eq_ignore_ascii_case(key)) =>
            {
                check_algorithms(key, value, span, findings);
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_weak_algorithm_findings(items, findings);
            }
            _ => {}
        }
    }
}

fn check_algorithms(key: &str, value: &str, span: &Span, findings: &mut Vec<Finding>) {
    for algo in value.split(',') {
        let algo = algo.trim();
        if algo.is_empty() {
            continue;
        }
        // Handle +/- prefix modifiers (e.g. +ssh-rsa)
        let bare = algo.trim_start_matches(['+', '-', '^']);
        if WEAK_ALGORITHMS.iter().any(|w| w.eq_ignore_ascii_case(bare)) {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "deprecated-weak-algorithms",
                    "WEAK_ALGO",
                    format!("weak or deprecated algorithm '{}' in {}", bare, key),
                    span.clone(),
                )
                .with_hint(format!("remove '{}' and use a stronger algorithm", bare)),
            );
        }
    }
}

pub struct DuplicateDirectives;

impl Rule for DuplicateDirectives {
    fn name(&self) -> &'static str {
        "duplicate-directives"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_duplicate_directives(&config.items, &mut findings);
        findings
    }
}

/// Directives that are allowed (or expected) to appear multiple times.
const MULTI_VALUE_DIRECTIVES: &[&str] = &[
    "identityfile",
    "certificatefile",
    "localforward",
    "remoteforward",
    "dynamicforward",
    "sendenv",
    "setenv",
    "match",
    "host",
];

fn collect_duplicate_directives(items: &[Item], findings: &mut Vec<Finding>) {
    check_scope_for_duplicates(items, findings);
    for item in items {
        match item {
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                check_scope_for_duplicates(items, findings);
            }
            _ => {}
        }
    }
}

fn check_scope_for_duplicates(items: &[Item], findings: &mut Vec<Finding>) {
    let mut seen: HashMap<String, Span> = HashMap::new();
    for item in items {
        if let Item::Directive { key, span, .. } = item {
            let lower = key.to_ascii_lowercase();
            if MULTI_VALUE_DIRECTIVES.contains(&lower.as_str()) {
                continue;
            }
            if let Some(first_span) = seen.get(&lower) {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "duplicate-directives",
                        "DUP_DIRECTIVE",
                        format!(
                            "duplicate directive '{}' (first seen at line {})",
                            key, first_span.line
                        ),
                        span.clone(),
                    )
                    .with_hint("remove the duplicate; only the first value takes effect"),
                );
            } else {
                seen.insert(lower, span.clone());
            }
        }
    }
}

/// Warns about directives that weaken SSH security.
///
/// Catches dangerous settings like StrictHostKeyChecking no (disables MITM
/// protection) and ForwardAgent yes on wildcard hosts (exposes your agent to
/// every server you connect to).
pub struct InsecureOption;

/// (directive_lowercase, bad_value, severity, code, hint)
const INSECURE_SETTINGS: &[(&str, &str, Severity, &str, &str)] = &[
    (
        "stricthostkeychecking",
        "no",
        Severity::Warning,
        "disables host key verification, making connections vulnerable to MITM attacks",
        "remove this or set to 'accept-new' if you want to auto-accept new keys",
    ),
    (
        "stricthostkeychecking",
        "off",
        Severity::Warning,
        "disables host key verification, making connections vulnerable to MITM attacks",
        "remove this or set to 'accept-new' if you want to auto-accept new keys",
    ),
    (
        "userknownhostsfile",
        "/dev/null",
        Severity::Warning,
        "discards known host keys, disabling host verification entirely",
        "remove this to use the default ~/.ssh/known_hosts",
    ),
    (
        "loglevel",
        "quiet",
        Severity::Info,
        "suppresses all SSH log output, making issues hard to debug",
        "use INFO or VERBOSE for better visibility",
    ),
];

/// Directives that are risky when set on a wildcard Host *.
const RISKY_ON_WILDCARD: &[(&str, &str, &str)] = &[
    (
        "forwardagent",
        "yes",
        "exposes your SSH agent to every server; an attacker with root on any server can use your keys",
    ),
    (
        "forwardx11",
        "yes",
        "forwards your X11 display to every server, allowing remote keystroke capture",
    ),
    (
        "forwardx11trusted",
        "yes",
        "gives every server full access to your X11 display",
    ),
];

impl Rule for InsecureOption {
    fn name(&self) -> &'static str {
        "insecure-option"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Check root-level directives (implicitly global)
        check_insecure_directives(&config.items, true, &mut findings);
        for item in &config.items {
            match item {
                Item::HostBlock {
                    patterns, items, ..
                } => {
                    let is_wildcard = patterns.iter().any(|p| p == "*");
                    check_insecure_directives(items, is_wildcard, &mut findings);
                }
                Item::MatchBlock { items, .. } => {
                    check_insecure_directives(items, false, &mut findings);
                }
                _ => {}
            }
        }
        findings
    }
}

fn check_insecure_directives(items: &[Item], is_global: bool, findings: &mut Vec<Finding>) {
    for item in items {
        if let Item::Directive { key, value, span } = item {
            let key_lower = key.to_ascii_lowercase();
            let val_lower = value.to_ascii_lowercase();

            // Always-bad settings
            for &(directive, bad_val, severity, desc, hint) in INSECURE_SETTINGS {
                if key_lower == directive && val_lower == bad_val {
                    findings.push(
                        Finding::new(
                            severity,
                            "insecure-option",
                            "INSECURE_OPT",
                            format!("{} {} — {}", key, value, desc),
                            span.clone(),
                        )
                        .with_hint(hint),
                    );
                }
            }

            // Risky-on-wildcard settings
            if is_global {
                for &(directive, bad_val, desc) in RISKY_ON_WILDCARD {
                    if key_lower == directive && val_lower == bad_val {
                        findings.push(
                            Finding::new(
                                Severity::Warning,
                                "insecure-option",
                                "INSECURE_OPT",
                                format!("{} {} on a global/wildcard host — {}", key, value, desc),
                                span.clone(),
                            )
                            .with_hint("set this only on specific hosts you trust, not globally"),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Config, Item, Span};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn no_duplicates_no_findings() {
        let config = Config {
            items: vec![
                Item::HostBlock {
                    patterns: vec!["a".to_string()],
                    span: Span::new(1),
                    items: vec![],
                },
                Item::HostBlock {
                    patterns: vec!["b".to_string()],
                    span: Span::new(3),
                    items: vec![],
                },
            ],
        };
        let findings = DuplicateHost.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_host_warns() {
        let config = Config {
            items: vec![
                Item::HostBlock {
                    patterns: vec!["github.com".to_string()],
                    span: Span::new(1),
                    items: vec![],
                },
                Item::HostBlock {
                    patterns: vec!["github.com".to_string()],
                    span: Span::new(5),
                    items: vec![],
                },
            ],
        };
        let findings = DuplicateHost.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "duplicate-host");
        assert!(findings[0].message.contains("first seen at line 1"));
    }

    #[test]
    fn identity_file_exists_no_error() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("id_test");
        fs::write(&key_path, "fake key").unwrap();

        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["a".to_string()],
                span: Span::new(1),
                items: vec![Item::Directive {
                    key: "IdentityFile".into(),
                    value: key_path.to_string_lossy().into_owned(),
                    span: Span::new(2),
                }],
            }],
        };
        let findings = IdentityFileExists.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn identity_file_missing_errors() {
        let config = Config {
            items: vec![Item::Directive {
                key: "IdentityFile".into(),
                value: "/nonexistent/path/id_nope".into(),
                span: Span::new(1),
            }],
        };
        let findings = IdentityFileExists.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "identity-file-exists");
    }

    #[test]
    fn identity_file_skips_templates() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "IdentityFile".into(),
                    value: "~/.ssh/id_%h".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "IdentityFile".into(),
                    value: "${HOME}/.ssh/id_ed25519".into(),
                    span: Span::new(2),
                },
            ],
        };
        let findings = IdentityFileExists.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn wildcard_after_specific_no_warning() {
        let config = Config {
            items: vec![
                Item::HostBlock {
                    patterns: vec!["github.com".to_string()],
                    span: Span::new(1),
                    items: vec![],
                },
                Item::HostBlock {
                    patterns: vec!["*".to_string()],
                    span: Span::new(5),
                    items: vec![],
                },
            ],
        };
        let findings = WildcardHostOrder.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn wildcard_before_specific_warns() {
        let config = Config {
            items: vec![
                Item::HostBlock {
                    patterns: vec!["*".to_string()],
                    span: Span::new(1),
                    items: vec![],
                },
                Item::HostBlock {
                    patterns: vec!["github.com".to_string()],
                    span: Span::new(5),
                    items: vec![],
                },
            ],
        };
        let findings = WildcardHostOrder.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "wildcard-host-order");
        assert!(findings[0].message.contains("github.com"));
    }

    // ── DeprecatedWeakAlgorithms tests ──

    #[test]
    fn weak_cipher_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "Ciphers".into(),
                value: "aes128-ctr,3des-cbc,aes256-gcm@openssh.com".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "WEAK_ALGO");
        assert!(findings[0].message.contains("3des-cbc"));
        assert!(findings[0].message.contains("Ciphers"));
    }

    #[test]
    fn weak_mac_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "MACs".into(),
                value: "hmac-sha2-256,hmac-md5".into(),
                span: Span::new(3),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("hmac-md5"));
    }

    #[test]
    fn weak_kex_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "KexAlgorithms".into(),
                value: "diffie-hellman-group1-sha1".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("diffie-hellman-group1-sha1"));
    }

    #[test]
    fn weak_host_key_algorithm_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "HostKeyAlgorithms".into(),
                value: "ssh-ed25519,ssh-dss".into(),
                span: Span::new(2),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ssh-dss"));
    }

    #[test]
    fn weak_pubkey_accepted_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "PubkeyAcceptedAlgorithms".into(),
                value: "ssh-rsa,ssh-ed25519".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ssh-rsa"));
    }

    #[test]
    fn strong_algorithms_no_warning() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "Ciphers".into(),
                    value: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "MACs".into(),
                    value: "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com".into(),
                    span: Span::new(2),
                },
                Item::Directive {
                    key: "KexAlgorithms".into(),
                    value: "curve25519-sha256,diffie-hellman-group16-sha512".into(),
                    span: Span::new(3),
                },
            ],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn multiple_weak_algorithms_multiple_findings() {
        let config = Config {
            items: vec![Item::Directive {
                key: "Ciphers".into(),
                value: "3des-cbc,arcfour,blowfish-cbc".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn weak_algo_inside_host_block() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["legacy-server".to_string()],
                span: Span::new(1),
                items: vec![Item::Directive {
                    key: "Ciphers".into(),
                    value: "arcfour256".into(),
                    span: Span::new(2),
                }],
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("arcfour256"));
    }

    #[test]
    fn weak_algo_with_prefix_modifier() {
        let config = Config {
            items: vec![Item::Directive {
                key: "Ciphers".into(),
                value: "+3des-cbc".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("3des-cbc"));
    }

    #[test]
    fn non_algorithm_directive_ignored() {
        let config = Config {
            items: vec![Item::Directive {
                key: "HostName".into(),
                value: "ssh-rsa.example.com".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_algo_has_hint() {
        let config = Config {
            items: vec![Item::Directive {
                key: "MACs".into(),
                value: "hmac-md5".into(),
                span: Span::new(1),
            }],
        };
        let findings = DeprecatedWeakAlgorithms.check(&config);
        assert_eq!(findings.len(), 1);
        let hint = findings[0].hint.as_deref().unwrap();
        assert!(hint.contains("hmac-md5"));
        assert!(hint.contains("stronger algorithm"));
    }

    // ── DuplicateDirectives tests ──

    #[test]
    fn duplicate_directives_at_root() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "User".into(),
                    value: "noah".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "User".into(),
                    value: "noah2".into(),
                    span: Span::new(2),
                },
            ],
        };
        let findings = DuplicateDirectives.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "duplicate-directives");
        assert_eq!(findings[0].code, "DUP_DIRECTIVE");
        assert!(findings[0].message.contains("User"));
        assert!(findings[0].message.contains("first seen at line 1"));
    }

    #[test]
    fn duplicate_directives_inside_host_block() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["example.com".to_string()],
                span: Span::new(1),
                items: vec![
                    Item::Directive {
                        key: "HostName".into(),
                        value: "1.2.3.4".into(),
                        span: Span::new(2),
                    },
                    Item::Directive {
                        key: "HostName".into(),
                        value: "5.6.7.8".into(),
                        span: Span::new(3),
                    },
                ],
            }],
        };
        let findings = DuplicateDirectives.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("HostName"));
    }

    #[test]
    fn duplicate_directives_case_insensitive() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "User".into(),
                    value: "alice".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "user".into(),
                    value: "bob".into(),
                    span: Span::new(2),
                },
            ],
        };
        let findings = DuplicateDirectives.check(&config);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn duplicate_directives_allows_identity_file() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["server".to_string()],
                span: Span::new(1),
                items: vec![
                    Item::Directive {
                        key: "IdentityFile".into(),
                        value: "~/.ssh/id_ed25519".into(),
                        span: Span::new(2),
                    },
                    Item::Directive {
                        key: "IdentityFile".into(),
                        value: "~/.ssh/id_rsa".into(),
                        span: Span::new(3),
                    },
                ],
            }],
        };
        let findings = DuplicateDirectives.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_directives_allows_multi_value_directives() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "SendEnv".into(),
                    value: "LANG".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "SendEnv".into(),
                    value: "LC_*".into(),
                    span: Span::new(2),
                },
                Item::Directive {
                    key: "LocalForward".into(),
                    value: "8080 localhost:80".into(),
                    span: Span::new(3),
                },
                Item::Directive {
                    key: "LocalForward".into(),
                    value: "9090 localhost:90".into(),
                    span: Span::new(4),
                },
            ],
        };
        let findings = DuplicateDirectives.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_duplicate_directives_no_findings() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["server".to_string()],
                span: Span::new(1),
                items: vec![
                    Item::Directive {
                        key: "User".into(),
                        value: "git".into(),
                        span: Span::new(2),
                    },
                    Item::Directive {
                        key: "HostName".into(),
                        value: "1.2.3.4".into(),
                        span: Span::new(3),
                    },
                    Item::Directive {
                        key: "Port".into(),
                        value: "22".into(),
                        span: Span::new(4),
                    },
                ],
            }],
        };
        let findings = DuplicateDirectives.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_directives_separate_scopes_ok() {
        // Same directive in different Host blocks should NOT warn
        let config = Config {
            items: vec![
                Item::HostBlock {
                    patterns: vec!["a".to_string()],
                    span: Span::new(1),
                    items: vec![Item::Directive {
                        key: "User".into(),
                        value: "alice".into(),
                        span: Span::new(2),
                    }],
                },
                Item::HostBlock {
                    patterns: vec!["b".to_string()],
                    span: Span::new(4),
                    items: vec![Item::Directive {
                        key: "User".into(),
                        value: "bob".into(),
                        span: Span::new(5),
                    }],
                },
            ],
        };
        let findings = DuplicateDirectives.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_directives_has_hint() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "Port".into(),
                    value: "22".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "Port".into(),
                    value: "2222".into(),
                    span: Span::new(2),
                },
            ],
        };
        let findings = DuplicateDirectives.check(&config);
        assert_eq!(findings.len(), 1);
        let hint = findings[0].hint.as_deref().unwrap();
        assert!(hint.contains("first value takes effect"));
    }

    #[test]
    fn duplicate_directives_inside_match_block() {
        let config = Config {
            items: vec![Item::MatchBlock {
                criteria: "host example.com".into(),
                span: Span::new(1),
                items: vec![
                    Item::Directive {
                        key: "ForwardAgent".into(),
                        value: "yes".into(),
                        span: Span::new(2),
                    },
                    Item::Directive {
                        key: "ForwardAgent".into(),
                        value: "no".into(),
                        span: Span::new(3),
                    },
                ],
            }],
        };
        let findings = DuplicateDirectives.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ForwardAgent"));
    }

    // ── InsecureOption tests ──

    #[test]
    fn strict_host_key_checking_no_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "StrictHostKeyChecking".into(),
                value: "no".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "INSECURE_OPT");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("MITM"));
    }

    #[test]
    fn strict_host_key_checking_off_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "StrictHostKeyChecking".into(),
                value: "off".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("MITM"));
    }

    #[test]
    fn strict_host_key_checking_ask_ok() {
        let config = Config {
            items: vec![Item::Directive {
                key: "StrictHostKeyChecking".into(),
                value: "ask".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn strict_host_key_checking_accept_new_ok() {
        let config = Config {
            items: vec![Item::Directive {
                key: "StrictHostKeyChecking".into(),
                value: "accept-new".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn user_known_hosts_dev_null_warns() {
        let config = Config {
            items: vec![Item::Directive {
                key: "UserKnownHostsFile".into(),
                value: "/dev/null".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("known host keys"));
    }

    #[test]
    fn loglevel_quiet_info() {
        let config = Config {
            items: vec![Item::Directive {
                key: "LogLevel".into(),
                value: "QUIET".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn forward_agent_yes_on_wildcard_warns() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["*".to_string()],
                span: Span::new(1),
                items: vec![Item::Directive {
                    key: "ForwardAgent".into(),
                    value: "yes".into(),
                    span: Span::new(2),
                }],
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("global"));
    }

    #[test]
    fn forward_agent_yes_on_specific_host_ok() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["bastion.example.com".to_string()],
                span: Span::new(1),
                items: vec![Item::Directive {
                    key: "ForwardAgent".into(),
                    value: "yes".into(),
                    span: Span::new(2),
                }],
            }],
        };
        let findings = InsecureOption.check(&config);
        assert!(findings.is_empty());
    }

    #[test]
    fn forward_x11_yes_on_wildcard_warns() {
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["*".to_string()],
                span: Span::new(1),
                items: vec![Item::Directive {
                    key: "ForwardX11".into(),
                    value: "yes".into(),
                    span: Span::new(2),
                }],
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("X11"));
    }

    #[test]
    fn forward_agent_at_root_level_warns() {
        // Root-level directives are implicitly global
        let config = Config {
            items: vec![Item::Directive {
                key: "ForwardAgent".into(),
                value: "yes".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("global"));
    }

    #[test]
    fn strict_host_key_inside_host_block_warns() {
        // Always-bad settings should warn even inside a specific host block
        let config = Config {
            items: vec![Item::HostBlock {
                patterns: vec!["dev-server".to_string()],
                span: Span::new(1),
                items: vec![Item::Directive {
                    key: "StrictHostKeyChecking".into(),
                    value: "no".into(),
                    span: Span::new(2),
                }],
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("MITM"));
    }

    #[test]
    fn insecure_option_has_hint() {
        let config = Config {
            items: vec![Item::Directive {
                key: "StrictHostKeyChecking".into(),
                value: "no".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].hint.is_some());
        assert!(findings[0].hint.as_deref().unwrap().contains("accept-new"));
    }

    #[test]
    fn case_insensitive_directive_and_value() {
        let config = Config {
            items: vec![Item::Directive {
                key: "stricthostkeychecking".into(),
                value: "NO".into(),
                span: Span::new(1),
            }],
        };
        let findings = InsecureOption.check(&config);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn multiple_insecure_settings() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "StrictHostKeyChecking".into(),
                    value: "no".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "UserKnownHostsFile".into(),
                    value: "/dev/null".into(),
                    span: Span::new(2),
                },
                Item::Directive {
                    key: "LogLevel".into(),
                    value: "QUIET".into(),
                    span: Span::new(3),
                },
                Item::Directive {
                    key: "ForwardAgent".into(),
                    value: "yes".into(),
                    span: Span::new(4),
                },
            ],
        };
        let findings = InsecureOption.check(&config);
        // StrictHostKeyChecking + UserKnownHostsFile + LogLevel + ForwardAgent (root=global)
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn safe_config_no_findings() {
        let config = Config {
            items: vec![
                Item::Directive {
                    key: "StrictHostKeyChecking".into(),
                    value: "yes".into(),
                    span: Span::new(1),
                },
                Item::Directive {
                    key: "LogLevel".into(),
                    value: "VERBOSE".into(),
                    span: Span::new(2),
                },
                Item::HostBlock {
                    patterns: vec!["myhost".to_string()],
                    span: Span::new(3),
                    items: vec![Item::Directive {
                        key: "ForwardAgent".into(),
                        value: "yes".into(),
                        span: Span::new(4),
                    }],
                },
            ],
        };
        let findings = InsecureOption.check(&config);
        assert!(findings.is_empty());
    }
}
