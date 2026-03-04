use std::collections::HashMap;
use std::path::Path;

use crate::model::{Config, Finding, Item, Span};
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
                        findings.push(Finding::warning(
                            "duplicate-host",
                            format!(
                                "duplicate Host block '{}' (first seen at line {})",
                                pattern, first_span.line
                            ),
                            span.clone(),
                        ));
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
                check_identity_file(value, &span, findings);
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

    let expanded = if value.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(&value[2..])
        } else {
            return; // Can't resolve ~ without home dir
        }
    } else {
        Path::new(value).to_path_buf()
    };

    if !expanded.exists() {
        findings.push(Finding::error(
            "identity-file-exists",
            format!("IdentityFile not found: {}", value),
            span.clone(),
        ));
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
                        findings.push(Finding::warning(
                            "wildcard-host-order",
                            format!(
                                "Host '{}' appears after 'Host *' (line {}); it will never match because Host * already matched",
                                pattern, ws.line
                            ),
                            span.clone(),
                        ));
                    }
                }
            }
        }

        findings
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
}
