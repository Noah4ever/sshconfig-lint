use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

/// Warns when `Host *` appears before more specific Host blocks.
/// OpenSSH applies all matching blocks but generally keeps the first value it
/// obtains for each option, so broad defaults should usually come last.
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
                                "Host '{}' appears after 'Host *' (line {}); options already set by Host * may not be overridden",
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
