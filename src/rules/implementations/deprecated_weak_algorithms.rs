use crate::model::{Config, Finding, Item, Severity, Span};
use crate::rules::Rule;

pub struct DeprecatedWeakAlgorithms;

/// Directives whose values are comma-separated algorithm lists.
const ALGORITHM_DIRECTIVES: &[&str] = &[
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes",
    "casignaturealgorithms",
];

/// Known deprecated or weak algorithms.
const WEAK_ALGORITHMS: &[&str] = &[
    // Ciphers
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "rijndael-cbc@lysator.liu.se",
    // MACs
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-64-etm@openssh.com",
    // Key exchange
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    // Host key / signature
    "ssh-dss",
    "ssh-rsa",
];

impl Rule for DeprecatedWeakAlgorithms {
    fn name(&self) -> &'static str {
        "deprecated-weak-algorithms"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect_weak_algorithm_findings(&config.items, &mut findings);
        findings
    }
}

fn collect_weak_algorithm_findings(items: &[Item], findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Directive {
                key, value, span, ..
            } if ALGORITHM_DIRECTIVES
                .iter()
                .any(|d| d.eq_ignore_ascii_case(key)) =>
            {
                check_algorithms(key, value, span, findings);
            }
            Item::HostBlock { items, .. } | Item::MatchBlock { items, .. } => {
                collect_weak_algorithm_findings(items, findings);
            }
            _ => {}
        }
    }
}

fn check_algorithms(key: &str, value: &str, span: &Span, findings: &mut Vec<Finding>) {
    for algo in value.split(',') {
        let algo = algo.trim();
        if algo.is_empty() {
            continue;
        }
        // Handle +/- prefix modifiers (e.g. +ssh-rsa)
        let bare = algo.trim_start_matches(['+', '-', '^']);
        if WEAK_ALGORITHMS.iter().any(|w| w.eq_ignore_ascii_case(bare)) {
            findings.push(
                Finding::new(
                    Severity::Warning,
                    "deprecated-weak-algorithms",
                    "WEAK_ALGO",
                    format!("weak or deprecated algorithm '{}' in {}", bare, key),
                    span.clone(),
                )
                .with_hint(format!("remove '{}' and use a stronger algorithm", bare)),
            );
        }
    }
}
