use std::path::Path;

use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

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
    // OpenSSH uses "none" to explicitly disable identity files. Template
    // variables cannot be resolved reliably without a concrete connection.
    if value.eq_ignore_ascii_case("none") || value.contains('%') || value.contains("${") {
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
