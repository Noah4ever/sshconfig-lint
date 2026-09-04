use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

use super::control_persist_requires_master::persist_is_enabled;
use super::value_arguments::parse_value_arguments;

/// Warns about OpenSSH disabling UpdateHostKeys confirmation when connection
/// multiplexing persists in an applicable configuration scope.
pub struct UpdateHostKeysControlPersist;

#[derive(Clone)]
struct FirstSetting {
    active: bool,
    span: Span,
}

#[derive(Default)]
struct ScopeSettings {
    update_hostkeys: Option<FirstSetting>,
    control_persist: Option<FirstSetting>,
}

impl Rule for UpdateHostKeysControlPersist {
    fn name(&self) -> &'static str {
        "update-hostkeys-control-persist"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root = settings_for(&config.items);
        report_conflict(
            root.update_hostkeys.as_ref(),
            root.control_persist.as_ref(),
            &mut findings,
        );
        if !findings.is_empty() {
            return findings;
        }

        for item in &config.items {
            if let Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } = item {
                collect_blocks(
                    items,
                    root.update_hostkeys.as_ref(),
                    root.control_persist.as_ref(),
                    &mut findings,
                );
            }
        }
        findings
    }
}

fn collect_blocks(
    items: &[Item],
    inherited_update: Option<&FirstSetting>,
    inherited_persist: Option<&FirstSetting>,
    findings: &mut Vec<Finding>,
) {
    let local = settings_for(items);
    let update = inherited_update.or(local.update_hostkeys.as_ref());
    let persist = inherited_persist.or(local.control_persist.as_ref());
    let finding_count = findings.len();
    report_conflict(update, persist, findings);
    if findings.len() != finding_count {
        return;
    }

    for item in items {
        if let Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } = item {
            collect_blocks(items, update, persist, findings);
        }
    }
}

fn settings_for(items: &[Item]) -> ScopeSettings {
    let mut settings = ScopeSettings::default();

    for item in items {
        let Item::Directive {
            key, value, span, ..
        } = item
        else {
            continue;
        };

        if key.eq_ignore_ascii_case("UpdateHostKeys") && settings.update_hostkeys.is_none() {
            let active = parse_value_arguments(value).is_some_and(|arguments| {
                matches!(arguments.as_slice(), [argument] if argument.eq_ignore_ascii_case("ask"))
            });
            settings.update_hostkeys = Some(FirstSetting {
                active,
                span: span.clone(),
            });
        } else if key.eq_ignore_ascii_case("ControlPersist") && settings.control_persist.is_none() {
            settings.control_persist = Some(FirstSetting {
                active: persist_is_enabled(value),
                span: span.clone(),
            });
        }
    }

    settings
}

fn report_conflict(
    update: Option<&FirstSetting>,
    persist: Option<&FirstSetting>,
    findings: &mut Vec<Finding>,
) {
    let (Some(update), Some(persist)) = (update, persist) else {
        return;
    };
    if !update.active || !persist.active {
        return;
    }

    let report_span = if update.span.line >= persist.span.line {
        update.span.clone()
    } else {
        persist.span.clone()
    };
    findings.push(
        Finding::new(
            Severity::Warning,
            "update-hostkeys-control-persist",
            "UPDATE_HOSTKEYS_ASK_PERSIST",
            format!(
                "UpdateHostKeys ask on line {} cannot confirm changes while ControlPersist on line {} is enabled",
                update.span.line, persist.span.line
            ),
            report_span,
        )
        .with_hint("use UpdateHostKeys yes or disable ControlPersist for this scope"),
    );
}
