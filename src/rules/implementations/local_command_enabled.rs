use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::value_arguments::parse_value_arguments;

/// Warns when LocalCommand is certainly disabled by the parsed configuration.
pub struct LocalCommandEnabled;

impl Rule for LocalCommandEnabled {
    fn name(&self) -> &'static str {
        "local-command-enabled"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        if contains_include(&config.items) || contains_possible_enablement(&config.items) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        collect_local_commands(&config.items, &mut findings);
        findings
    }
}

fn contains_include(items: &[Item]) -> bool {
    items.iter().any(|item| match item {
        Item::Include { .. } => true,
        Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => contains_include(items),
        _ => false,
    })
}

fn contains_possible_enablement(items: &[Item]) -> bool {
    items.iter().any(|item| match item {
        Item::Directive { key, value, .. }
            if key.eq_ignore_ascii_case("PermitLocalCommand") =>
        {
            parse_value_arguments(value).is_some_and(|arguments| {
                matches!(arguments.as_slice(), [argument] if argument.eq_ignore_ascii_case("yes") || argument.eq_ignore_ascii_case("true"))
            })
        }
        Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
            contains_possible_enablement(items)
        }
        _ => false,
    })
}

fn collect_local_commands(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive { key, span, .. } if key.eq_ignore_ascii_case("LocalCommand") => {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "local-command-enabled",
                        "LOCAL_COMMAND_DISABLED",
                        "LocalCommand is ignored because PermitLocalCommand is not enabled",
                        span.clone(),
                    )
                    .with_hint(
                        "add PermitLocalCommand yes in an applicable scope or remove LocalCommand",
                    ),
                );
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_local_commands(items, findings);
            }
            _ => {}
        }
    }
}
