use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

use super::value_arguments::parse_value_arguments;

/// Warns about directives that weaken SSH security.
///
/// Catches dangerous settings like StrictHostKeyChecking no (disables MITM
/// protection) and ForwardAgent yes on wildcard hosts (exposes your agent to
/// every server you connect to).
pub struct InsecureOption;

/// (directive_lowercase, bad_value, severity, code, hint)
const INSECURE_SETTINGS: &[(&str, &str, Severity, &str, &str)] = &[
    (
        "stricthostkeychecking",
        "no",
        Severity::Warning,
        "disables host key verification, making connections vulnerable to MITM attacks",
        "remove this or set to 'accept-new' if you want to auto-accept new keys",
    ),
    (
        "stricthostkeychecking",
        "off",
        Severity::Warning,
        "disables host key verification, making connections vulnerable to MITM attacks",
        "remove this or set to 'accept-new' if you want to auto-accept new keys",
    ),
    (
        "userknownhostsfile",
        "/dev/null",
        Severity::Warning,
        "discards known host keys, disabling host verification entirely",
        "remove this to use the default ~/.ssh/known_hosts",
    ),
    (
        "loglevel",
        "quiet",
        Severity::Info,
        "suppresses all SSH log output, making issues hard to debug",
        "use INFO or VERBOSE for better visibility",
    ),
];

/// Directives that are risky when set on a wildcard Host *.
const RISKY_ON_WILDCARD: &[(&str, &str, &str)] = &[
    (
        "forwardagent",
        "yes",
        "exposes your SSH agent to every server; an attacker with root on any server can use your keys",
    ),
    (
        "forwardx11",
        "yes",
        "forwards your X11 display to every server, allowing remote keystroke capture",
    ),
    (
        "forwardx11trusted",
        "yes",
        "gives every server full access to your X11 display",
    ),
];

impl Rule for InsecureOption {
    fn name(&self) -> &'static str {
        "insecure-option"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Check root-level directives (implicitly global)
        check_insecure_directives(&config.items, true, &mut findings);
        for item in &config.items {
            match item {
                Item::HostBlock {
                    patterns, items, ..
                } => {
                    let is_wildcard = patterns.iter().any(|p| p == "*");
                    check_insecure_directives(items, is_wildcard, &mut findings);
                }
                Item::MatchBlock { items, .. } => {
                    check_insecure_directives(items, false, &mut findings);
                }
                _ => {}
            }
        }
        findings
    }
}

fn check_insecure_directives(items: &[Item], is_global: bool, findings: &mut Vec<Finding>) {
    for item in items {
        if let Item::Directive { key, value, span } = item {
            let key_lower = key.to_ascii_lowercase();
            let Some(arguments) = parse_value_arguments(value) else {
                continue;
            };

            // Always-bad settings
            for &(directive, bad_val, severity, desc, hint) in INSECURE_SETTINGS {
                let has_bad_value = if directive == "userknownhostsfile" {
                    arguments
                        .iter()
                        .any(|argument| argument.eq_ignore_ascii_case(bad_val))
                } else {
                    matches!(arguments.as_slice(), [argument] if argument.eq_ignore_ascii_case(bad_val))
                };
                if key_lower == directive && has_bad_value {
                    findings.push(
                        Finding::new(
                            severity,
                            "insecure-option",
                            "INSECURE_OPT",
                            format!("{} {} — {}", key, value, desc),
                            span.clone(),
                        )
                        .with_hint(hint),
                    );
                }
            }

            // Risky-on-wildcard settings
            if is_global {
                for &(directive, bad_val, desc) in RISKY_ON_WILDCARD {
                    if key_lower == directive
                        && matches!(arguments.as_slice(), [argument] if argument.eq_ignore_ascii_case(bad_val))
                    {
                        findings.push(
                            Finding::new(
                                Severity::Warning,
                                "insecure-option",
                                "INSECURE_OPT",
                                format!("{} {} on a global/wildcard host — {}", key, value, desc),
                                span.clone(),
                            )
                            .with_hint("set this only on specific hosts you trust, not globally"),
                        );
                    }
                }
            }
        }
    }
}
