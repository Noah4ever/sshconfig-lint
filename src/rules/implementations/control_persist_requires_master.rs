use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::invalid_directive_value::parse_time_seconds;
use super::value_arguments::parse_value_arguments;

/// Warns when ControlPersist is enabled but no ControlMaster setting in the
/// document can create a master connection.
pub struct ControlPersistRequiresMaster;

impl Rule for ControlPersistRequiresMaster {
    fn name(&self) -> &'static str {
        "control-persist-requires-master"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        if contains_include(&config.items) {
            return Vec::new();
        }

        if let Some(root_master_enabled) = first_master_setting(&config.items) {
            if root_master_enabled {
                return Vec::new();
            }
        } else if contains_possible_enabled_master(&config.items) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        collect_enabled_persist(&config.items, &mut findings);
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

fn contains_possible_enabled_master(items: &[Item]) -> bool {
    items.iter().any(|item| match item {
        Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
            first_master_setting(items).unwrap_or(false) || contains_possible_enabled_master(items)
        }
        _ => false,
    })
}

fn first_master_setting(items: &[Item]) -> Option<bool> {
    items.iter().find_map(|item| match item {
        Item::Directive { key, value, .. } if key.eq_ignore_ascii_case("ControlMaster") => {
            Some(parse_value_arguments(value).is_some_and(|arguments| {
                matches!(arguments.as_slice(), [argument] if matches!(
                    argument.to_ascii_lowercase().as_str(),
                    "yes" | "true" | "ask" | "auto" | "autoask"
                ))
            }))
        }
        _ => None,
    })
}

fn collect_enabled_persist(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } if key.eq_ignore_ascii_case("ControlPersist") && persist_is_enabled(value) => {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        "control-persist-requires-master",
                        "CONTROL_PERSIST_UNUSED",
                        "ControlPersist has no effect because ControlMaster is not enabled",
                        span.clone(),
                    )
                    .with_hint("enable ControlMaster or remove ControlPersist"),
                );
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_enabled_persist(items, findings);
            }
            _ => {}
        }
    }
}

pub(super) fn persist_is_enabled(value: &str) -> bool {
    parse_value_arguments(value).is_some_and(|arguments| match arguments.as_slice() {
        [argument] if matches!(argument.to_ascii_lowercase().as_str(), "yes" | "true") => true,
        [argument] if matches!(argument.to_ascii_lowercase().as_str(), "no" | "false") => false,
        [argument] => parse_time_seconds(argument).is_some(),
        _ => false,
    })
}
