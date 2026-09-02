use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

use super::explicit_path::{is_readable_regular_file, resolve_explicit_path};
use super::value_arguments::parse_value_arguments;

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
    let Some(arguments) = parse_value_arguments(value) else {
        return;
    };
    let [argument] = arguments.as_slice() else {
        return;
    };

    // OpenSSH uses "none" to explicitly disable identity files. Template
    // variables cannot be resolved reliably without a concrete connection.
    if argument.eq_ignore_ascii_case("none") {
        return;
    }
    let Some(expanded) = resolve_explicit_path(argument) else {
        return;
    };

    if !is_readable_regular_file(&expanded) {
        findings.push(
            Finding::new(
                Severity::Error,
                "identity-file-exists",
                "MISSING_IDENTITY",
                format!("IdentityFile not found or unreadable: {}", argument),
                span.clone(),
            )
            .with_hint("check the path or remove the directive"),
        );
    }
}
