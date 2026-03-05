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
}
