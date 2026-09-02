use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::explicit_path::{is_readable_regular_file, resolve_explicit_path};
use super::value_arguments::parse_value_arguments;

/// Errors when an explicit CertificateFile path is not a readable file.
pub struct CertificateFileExists;

impl Rule for CertificateFileExists {
    fn name(&self) -> &'static str {
        "certificate-file-exists"
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
            } if key.eq_ignore_ascii_case("CertificateFile") => {
                let Some(arguments) = parse_value_arguments(value) else {
                    continue;
                };
                let [argument] = arguments.as_slice() else {
                    continue;
                };
                let Some(path) = resolve_explicit_path(argument) else {
                    continue;
                };
                if !is_readable_regular_file(&path) {
                    findings.push(
                        Finding::new(
                            Severity::Error,
                            "certificate-file-exists",
                            "MISSING_CERTIFICATE",
                            format!("CertificateFile not found or unreadable: {}", argument),
                            span.clone(),
                        )
                        .with_hint("check the path or remove the CertificateFile directive"),
                    );
                }
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_findings(items, findings);
            }
            _ => {}
        }
    }
}
