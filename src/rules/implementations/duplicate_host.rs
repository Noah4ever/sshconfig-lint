use std::collections::HashMap;

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
                    let normalized = pattern.to_ascii_lowercase();
                    if let Some(first_span) = seen.get(&normalized) {
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
                        seen.insert(normalized, span.clone());
                    }
                }
            }
        }

        findings
    }
}
