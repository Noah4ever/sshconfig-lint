use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

/// Warns when ProxyCommand and ProxyJump compete in one configuration scope.
pub struct ProxyCommandJumpConflict;

impl Rule for ProxyCommandJumpConflict {
    fn name(&self) -> &'static str {
        "proxy-command-jump-conflict"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_scope_conflicts(&config.items, &mut findings);
        findings
    }
}

fn collect_scope_conflicts(items: &[Item], findings: &mut Vec<Finding>) {
    check_scope(items, findings);
    for item in items {
        if let Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } = item {
            collect_scope_conflicts(items, findings);
        }
    }
}

fn check_scope(items: &[Item], findings: &mut Vec<Finding>) {
    let mut first: Option<(&str, Span)> = None;

    for item in items {
        let Item::Directive { key, span, .. } = item else {
            continue;
        };
        let current = if key.eq_ignore_ascii_case("ProxyCommand") {
            "ProxyCommand"
        } else if key.eq_ignore_ascii_case("ProxyJump") {
            "ProxyJump"
        } else {
            continue;
        };

        match &first {
            None => first = Some((current, span.clone())),
            Some((first_name, first_span)) if *first_name != current => {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "proxy-command-jump-conflict",
                        "PROXY_CONFLICT",
                        format!(
                            "{} on line {} takes effect first, so {} on this line is ignored",
                            first_name, first_span.line, current
                        ),
                        span.clone(),
                    )
                    .with_hint(format!(
                        "remove either {} or {} from this scope",
                        first_name, current
                    )),
                );
                break;
            }
            _ => {}
        }
    }
}
