use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

/// Warns about client options that current OpenSSH ignores or keeps only as
/// obsolete compatibility aliases.
pub struct DeprecatedOption;

struct DeprecatedSpec {
    directive: &'static str,
    replacement: Option<&'static str>,
}

const DEPRECATED: &[DeprecatedSpec] = &[
    DeprecatedSpec {
        directive: "Protocol",
        replacement: None,
    },
    DeprecatedSpec {
        directive: "Cipher",
        replacement: Some("Ciphers"),
    },
    DeprecatedSpec {
        directive: "FallbackToRsh",
        replacement: None,
    },
    DeprecatedSpec {
        directive: "GlobalKnownHostsFile2",
        replacement: Some("GlobalKnownHostsFile"),
    },
    DeprecatedSpec {
        directive: "RhostsAuthentication",
        replacement: None,
    },
    DeprecatedSpec {
        directive: "UserKnownHostsFile2",
        replacement: Some("UserKnownHostsFile"),
    },
    DeprecatedSpec {
        directive: "UseRoaming",
        replacement: None,
    },
    DeprecatedSpec {
        directive: "UserSH",
        replacement: None,
    },
    DeprecatedSpec {
        directive: "UsePrivilegedPort",
        replacement: None,
    },
    DeprecatedSpec {
        directive: "IdentityFile2",
        replacement: Some("IdentityFile"),
    },
    DeprecatedSpec {
        directive: "KeepAlive",
        replacement: Some("TCPKeepAlive"),
    },
    DeprecatedSpec {
        directive: "HostbasedKeyTypes",
        replacement: Some("HostbasedAcceptedAlgorithms"),
    },
    DeprecatedSpec {
        directive: "PubkeyAcceptedKeyTypes",
        replacement: Some("PubkeyAcceptedAlgorithms"),
    },
];

impl Rule for DeprecatedOption {
    fn name(&self) -> &'static str {
        "deprecated-option"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect(&config.items, &mut findings);
        findings
    }
}

fn collect(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive { key, span, .. } => {
                let Some(spec) = DEPRECATED
                    .iter()
                    .find(|spec| key.eq_ignore_ascii_case(spec.directive))
                else {
                    continue;
                };
                let hint = spec.replacement.map_or_else(
                    || format!("remove {}; current OpenSSH ignores it", spec.directive),
                    |replacement| format!("replace {} with {replacement}", spec.directive),
                );
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "deprecated-option",
                        "DEPRECATED_OPTION",
                        format!(
                            "{} is deprecated or obsolete in current OpenSSH",
                            spec.directive
                        ),
                        span.clone(),
                    )
                    .with_hint(hint),
                );
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect(items, findings);
            }
            _ => {}
        }
    }
}
