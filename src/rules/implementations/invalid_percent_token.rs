use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

use super::value_arguments::parse_value_arguments;

const COMMON_TOKENS: &[char] = &[
    '%', 'C', 'd', 'h', 'i', 'j', 'k', 'L', 'l', 'n', 'p', 'r', 'u',
];
const KNOWN_HOSTS_TOKENS: &[char] = &[
    '%', 'C', 'd', 'f', 'H', 'h', 'I', 'i', 'j', 'K', 'k', 'L', 'l', 'n', 'p', 'r', 't', 'u',
];
const ALL_TOKENS: &[char] = &[
    '%', 'C', 'd', 'f', 'H', 'h', 'I', 'i', 'j', 'K', 'k', 'L', 'l', 'n', 'p', 'r', 'T', 't', 'u',
];
const HOSTNAME_TOKENS: &[char] = &['%', 'h'];
const PROXY_TOKENS: &[char] = &['%', 'h', 'n', 'p', 'r'];

/// Errors on unsupported or incomplete percent tokens.
pub struct InvalidPercentToken;

impl Rule for InvalidPercentToken {
    fn name(&self) -> &'static str {
        "invalid-percent-token"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } => {
                if let Some(allowed) = allowed_tokens(key) {
                    check_value(key, value, span, allowed, findings);
                }
            }
            Item::Include { patterns, span } => {
                for pattern in patterns {
                    check_value("Include", pattern, span, COMMON_TOKENS, findings);
                }
            }
            Item::HostBlock { items, .. } => collect_findings(items, findings),
            Item::MatchBlock {
                criteria,
                span,
                items,
            } => {
                check_match_exec(criteria, span, findings);
                collect_findings(items, findings);
            }
            _ => {}
        }
    }
}

fn allowed_tokens(key: &str) -> Option<&'static [char]> {
    if key.eq_ignore_ascii_case("KnownHostsCommand") {
        return Some(KNOWN_HOSTS_TOKENS);
    }
    if key.eq_ignore_ascii_case("LocalCommand") {
        return Some(ALL_TOKENS);
    }
    if key.eq_ignore_ascii_case("Hostname") {
        return Some(HOSTNAME_TOKENS);
    }
    if key.eq_ignore_ascii_case("ProxyCommand") || key.eq_ignore_ascii_case("ProxyJump") {
        return Some(PROXY_TOKENS);
    }
    if [
        "CertificateFile",
        "ControlPath",
        "IdentityAgent",
        "IdentityFile",
        "LocalForward",
        "RemoteCommand",
        "RemoteForward",
        "RevokedHostKeys",
        "UserKnownHostsFile",
        "VersionAddendum",
    ]
    .iter()
    .any(|directive| key.eq_ignore_ascii_case(directive))
    {
        return Some(COMMON_TOKENS);
    }
    None
}

fn check_match_exec(criteria: &str, span: &Span, findings: &mut Vec<Finding>) {
    let Some(arguments) = parse_value_arguments(criteria) else {
        return;
    };
    for window in arguments.windows(2) {
        if window[0].eq_ignore_ascii_case("exec") {
            check_value("Match exec", &window[1], span, COMMON_TOKENS, findings);
            break;
        }
    }
}

fn check_value(
    directive: &str,
    value: &str,
    span: &Span,
    allowed: &[char],
    findings: &mut Vec<Finding>,
) {
    let Some(token) = first_invalid_token(value, allowed) else {
        return;
    };
    findings.push(
        Finding::new(
            Severity::Error,
            "invalid-percent-token",
            "INVALID_TOKEN",
            format!("unsupported percent token '{}' in {}", token, directive),
            span.clone(),
        )
        .with_hint(
            "escape a literal percent sign as %% or use a token supported by this directive",
        ),
    );
}

fn first_invalid_token(value: &str, allowed: &[char]) -> Option<String> {
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            continue;
        }
        let Some(token) = characters.next() else {
            return Some("%".to_string());
        };
        if !allowed.contains(&token) {
            return Some(format!("%{}", token));
        }
    }
    None
}
