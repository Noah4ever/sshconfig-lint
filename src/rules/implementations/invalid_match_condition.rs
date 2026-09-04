use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::value_arguments::parse_value_arguments;

/// Reports malformed or unsupported Match criteria using the grammar accepted
/// by current portable OpenSSH.
pub struct InvalidMatchCondition;

impl Rule for InvalidMatchCondition {
    fn name(&self) -> &'static str {
        "invalid-match-condition"
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
            Item::MatchBlock {
                criteria,
                span,
                items,
            } => {
                if let Some((message, hint)) = validate(criteria) {
                    findings.push(
                        Finding::new(
                            Severity::Error,
                            "invalid-match-condition",
                            "INVALID_MATCH",
                            message,
                            span.clone(),
                        )
                        .with_hint(hint),
                    );
                }
                collect(items, findings);
            }
            Item::HostBlock { items, .. } => collect(items, findings),
            _ => {}
        }
    }
}

fn validate(criteria: &str) -> Option<(String, &'static str)> {
    let arguments = parse_value_arguments(criteria)?;
    let mut index = 0;

    while index < arguments.len() {
        let raw = &arguments[index];
        let criterion = raw.strip_prefix('!').unwrap_or(raw);
        let lower = criterion.to_ascii_lowercase();

        if lower == "all" {
            if arguments.len() != 1 {
                return Some((
                    "Match all cannot be combined with other criteria".to_string(),
                    "put Match all in its own block",
                ));
            }
            return None;
        }

        if matches!(lower.as_str(), "canonical" | "final") {
            index += 1;
            continue;
        }

        let (name, inline_value) = match lower.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (lower.as_str(), None),
        };
        let supported = matches!(
            name,
            "host"
                | "originalhost"
                | "user"
                | "localuser"
                | "localnetwork"
                | "version"
                | "tagged"
                | "command"
                | "exec"
        );
        if !supported {
            return Some((
                format!("unsupported Match criterion: {criterion}"),
                "use a criterion supported by the installed OpenSSH client",
            ));
        }

        let value = if let Some(value) = inline_value {
            value
        } else {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Some((
                    format!("Match {name} is missing its argument"),
                    "add the value required by this Match criterion",
                ));
            };
            value
        };

        if value.is_empty() && !matches!(name, "tagged" | "command") {
            return Some((
                format!("Match {name} has an empty argument"),
                "provide a non-empty value for this Match criterion",
            ));
        }
        index += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::validate;

    #[test]
    fn invalid_quotes_are_left_to_the_syntax_rule() {
        assert_eq!(validate(r#"host "unterminated"#), None);
    }
}
