use std::collections::HashMap;

use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

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
