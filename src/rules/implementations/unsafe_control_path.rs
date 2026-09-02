use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

/// Warns when `ControlPath` doesn't include the tokens needed to uniquely
/// identify connections. The OpenSSH man page recommends that ControlPath
/// include at least `%h`, `%p`, and `%r` (or alternatively `%C`).
pub struct UnsafeControlPath;

impl Rule for UnsafeControlPath {
    fn name(&self) -> &'static str {
        "unsafe-control-path"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_control_path_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_control_path_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive { key, value, span } if key.eq_ignore_ascii_case("ControlPath") => {
                check_control_path(value, span, findings);
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_control_path_findings(items, findings);
            }
            _ => {}
        }
    }
}

fn check_control_path(value: &str, span: &Span, findings: &mut Vec<Finding>) {
    // "none" disables connection sharing — nothing to check
    if value.eq_ignore_ascii_case("none") {
        return;
    }

    // %C is a hash of %l%h%p%r — a single token that covers all four
    if value.contains("%C") {
        return;
    }

    let has_h = value.contains("%h");
    let has_p = value.contains("%p");
    let has_r = value.contains("%r");

    if has_h && has_p && has_r {
        return;
    }

    let mut missing = Vec::new();
    if !has_h {
        missing.push("%h");
    }
    if !has_p {
        missing.push("%p");
    }
    if !has_r {
        missing.push("%r");
    }

    findings.push(
        Finding::new(
            Severity::Warning,
            "unsafe-control-path",
            "UNSAFE_CTRL_PATH",
            format!(
                "ControlPath is missing {} — connections to different hosts may share a socket",
                missing.join(", ")
            ),
            span.clone(),
        )
        .with_hint("include %h, %p, and %r (or %C) in the path"),
    );
}
