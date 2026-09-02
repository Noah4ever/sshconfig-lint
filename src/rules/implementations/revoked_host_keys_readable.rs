use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::explicit_path::{is_readable_regular_file, resolve_explicit_path};
use super::value_arguments::parse_value_arguments;

/// Errors when an explicit RevokedHostKeys file cannot be read.
pub struct RevokedHostKeysReadable;

impl Rule for RevokedHostKeysReadable {
    fn name(&self) -> &'static str {
        "revoked-host-keys-readable"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } if key.eq_ignore_ascii_case("RevokedHostKeys") => {
                let Some(arguments) = parse_value_arguments(value) else {
                    continue;
                };
                if matches!(arguments.as_slice(), [argument] if argument.eq_ignore_ascii_case("none"))
                {
                    continue;
                }

                for argument in arguments {
                    let Some(path) = resolve_explicit_path(&argument) else {
                        continue;
                    };
                    if !is_readable_regular_file(&path) {
                        findings.push(
                            Finding::new(
                                Severity::Error,
                                "revoked-host-keys-readable",
                                "REVOKED_HOST_KEYS_UNREADABLE",
                                format!(
                                    "RevokedHostKeys file is missing or unreadable: {}; host authentication will be refused for all hosts",
                                    argument
                                ),
                                span.clone(),
                            )
                            .with_hint("fix the path, permissions, or use RevokedHostKeys none intentionally"),
                        );
                    }
                }
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_findings(items, findings);
            }
            _ => {}
        }
    }
}
