use super::*;
use crate::model::{Config, Item, Severity, Span};
use crate::rules::Rule;
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
fn identity_file_accepts_quoted_and_escaped_paths_with_spaces() {
    let tmp = TempDir::new().unwrap();
    let key_path = tmp.path().join("key with spaces");
    fs::write(&key_path, "fake key").unwrap();

    for value in [
        format!(r#""{}""#, key_path.display()),
        key_path.to_string_lossy().replace(' ', r#"\ "#),
    ] {
        let config = Config {
            items: vec![Item::Directive {
                key: "IdentityFile".into(),
                value,
                span: Span::new(1),
            }],
        };
        assert!(IdentityFileExists.check(&config).is_empty());
    }
}

#[test]
fn identity_file_rejects_a_directory_and_skips_malformed_argument_lists() {
    let tmp = TempDir::new().unwrap();
    let directory_config = Config {
        items: vec![Item::Directive {
            key: "IdentityFile".into(),
            value: tmp.path().to_string_lossy().into_owned(),
            span: Span::new(1),
        }],
    };
    assert_eq!(IdentityFileExists.check(&directory_config).len(), 1);

    for value in [r#""unterminated"#, "one two"] {
        let malformed = Config {
            items: vec![Item::Directive {
                key: "IdentityFile".into(),
                value: value.into(),
                span: Span::new(1),
            }],
        };
        assert!(IdentityFileExists.check(&malformed).is_empty());
    }
}

#[test]
fn duplicate_hosts_are_case_insensitive_like_openssh_matching() {
    let config = Config {
        items: vec![
            Item::HostBlock {
                patterns: vec!["Example.COM".into()],
                span: Span::new(1),
                items: vec![],
            },
            Item::HostBlock {
                patterns: vec!["example.com".into()],
                span: Span::new(2),
                items: vec![],
            },
        ],
    };
    assert_eq!(DuplicateHost.check(&config).len(), 1);
}

#[test]
fn quoted_insecure_values_are_still_detected() {
    let config = Config {
        items: vec![
            Item::Directive {
                key: "StrictHostKeyChecking".into(),
                value: r#""no""#.into(),
                span: Span::new(1),
            },
            Item::Directive {
                key: "UserKnownHostsFile".into(),
                value: r#""/dev/null" ~/.ssh/known_hosts"#.into(),
                span: Span::new(2),
            },
        ],
    };
    assert_eq!(InsecureOption.check(&config).len(), 2);
}

#[test]
fn quoted_weak_algorithm_lists_are_still_detected() {
    let config = Config {
        items: vec![Item::Directive {
            key: "Ciphers".into(),
            value: r#""aes256-ctr,3des-cbc""#.into(),
            span: Span::new(1),
        }],
    };
    let findings = DeprecatedWeakAlgorithms.check(&config);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("3des-cbc"));
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
                value:
                    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
                        .into(),
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

// ---- UnsafeControlPath tests ----

#[test]
fn control_path_with_all_tokens_ok() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "~/.ssh/sockets/%r@%h-%p".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert!(findings.is_empty());
}

#[test]
fn control_path_with_hash_c_ok() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "~/.ssh/sockets/%C".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert!(findings.is_empty());
}

#[test]
fn control_path_none_ok() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "none".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert!(findings.is_empty());
}

#[test]
fn control_path_none_case_insensitive() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "NONE".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert!(findings.is_empty());
}

#[test]
fn control_path_missing_all_tokens_warns() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "~/.ssh/sockets/master".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "UNSAFE_CTRL_PATH");
    assert!(findings[0].message.contains("%h"));
    assert!(findings[0].message.contains("%p"));
    assert!(findings[0].message.contains("%r"));
}

#[test]
fn control_path_missing_port_warns() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "/tmp/ssh-%r@%h".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("%p"));
    assert!(!findings[0].message.contains("%h"));
    assert!(!findings[0].message.contains("%r"));
}

#[test]
fn control_path_missing_user_warns() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "~/.ssh/sockets/%h-%p".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("%r"));
}

#[test]
fn control_path_inside_host_block_warns() {
    let config = Config {
        items: vec![Item::HostBlock {
            patterns: vec!["myhost".to_string()],
            span: Span::new(1),
            items: vec![Item::Directive {
                key: "ControlPath".into(),
                value: "/tmp/ssh-socket".into(),
                span: Span::new(2),
            }],
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "UNSAFE_CTRL_PATH");
}

#[test]
fn control_path_inside_match_block_warns() {
    let config = Config {
        items: vec![Item::MatchBlock {
            criteria: "host example.com".into(),
            span: Span::new(1),
            items: vec![Item::Directive {
                key: "ControlPath".into(),
                value: "~/.ssh/%h".into(),
                span: Span::new(2),
            }],
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert_eq!(findings.len(), 1);
}

#[test]
fn control_path_has_hint() {
    let config = Config {
        items: vec![Item::Directive {
            key: "ControlPath".into(),
            value: "~/.ssh/sockets/ctrl".into(),
            span: Span::new(1),
        }],
    };
    let findings = UnsafeControlPath.check(&config);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].hint.as_ref().unwrap().contains("%C"));
}
