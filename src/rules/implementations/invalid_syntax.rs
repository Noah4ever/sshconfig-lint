use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

use super::value_arguments::parse_value_arguments;

/// Reports parser-level mistakes that OpenSSH rejects before it evaluates an
/// individual option, namely missing arguments and unbalanced quotes.
pub struct InvalidSyntax;

impl Rule for InvalidSyntax {
    fn name(&self) -> &'static str {
        "invalid-syntax"
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
            Item::Directive {
                key, value, span, ..
            } => {
                validate_arguments(key, value, span, findings);
            }
            Item::HostBlock {
                patterns,
                span,
                items,
            } => {
                validate_parsed_list("Host", patterns, span, findings);
                collect(items, findings);
            }
            Item::MatchBlock {
                criteria,
                span,
                items,
            } => {
                validate_arguments("Match", criteria, span, findings);
                collect(items, findings);
            }
            Item::Include { patterns, span } => {
                validate_parsed_list("Include", patterns, span, findings);
            }
            Item::Comment { .. } => {}
        }
    }
}

fn validate_arguments(key: &str, value: &str, span: &Span, findings: &mut Vec<Finding>) {
    match parse_value_arguments(value) {
        None => findings.push(syntax_finding(
            key,
            "contains unbalanced quotes",
            "close the single or double quote before the end of the line",
            span,
        )),
        Some(arguments) if arguments.is_empty() => findings.push(syntax_finding(
            key,
            "has no argument",
            "add the value required by this directive",
            span,
        )),
        Some(arguments) if arguments.iter().any(String::is_empty) && key != "Match" => {
            findings.push(syntax_finding(
                key,
                "contains an empty argument",
                "remove the empty argument or provide a non-empty value",
                span,
            ));
        }
        Some(_) => {}
    }
}

fn validate_parsed_list(key: &str, arguments: &[String], span: &Span, findings: &mut Vec<Finding>) {
    if arguments.is_empty() {
        findings.push(syntax_finding(
            key,
            "has no valid argument or contains unbalanced quotes",
            "provide at least one argument and close all quotes",
            span,
        ));
    } else if arguments.iter().any(String::is_empty) {
        findings.push(syntax_finding(
            key,
            "contains an empty argument",
            "remove the empty argument or provide a non-empty value",
            span,
        ));
    }
}

fn syntax_finding(key: &str, problem: &str, hint: &str, span: &Span) -> Finding {
    Finding::new(
        Severity::Error,
        "invalid-syntax",
        "INVALID_SYNTAX",
        format!("{key} {problem}"),
        span.clone(),
    )
    .with_hint(hint)
}
