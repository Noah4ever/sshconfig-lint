pub mod basic;

use crate::model::{Config, Finding};

/// A lint rule that checks a parsed config.
pub trait Rule {
    /// Human-readable name for this rule.
    fn name(&self) -> &'static str;
    /// Check the config and return any findings.
    fn check(&self, config: &Config) -> Vec<Finding>;
}

/// Run all registered rules against a config and return merged findings.
pub fn run_all(config: &Config) -> Vec<Finding> {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(basic::DuplicateHost),
        Box::new(basic::IdentityFileExists),
        Box::new(basic::WildcardHostOrder),
        Box::new(basic::DeprecatedWeakAlgorithms),
        Box::new(basic::DuplicateDirectives),
        Box::new(basic::InsecureOption),
    ];

    let mut findings = Vec::new();
    for rule in &rules {
        findings.extend(rule.check(config));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Config, Finding, Item, Severity, Span};

    struct DummyRule;
    impl Rule for DummyRule {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn check(&self, _config: &Config) -> Vec<Finding> {
            vec![Finding::new(
                Severity::Info,
                "dummy",
                "TEST",
                "this is a test",
                Span::new(1),
            )]
        }
    }

    #[test]
    fn trait_rule_returns_finding() {
        let config = Config { items: vec![] };
        let rule = DummyRule;
        let findings = rule.check(&config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "dummy");
    }

    #[test]
    fn run_all_merges_findings() {
        // run_all on an empty config should return no errors
        let config = Config { items: vec![] };
        let findings = run_all(&config);
        // All rules on empty config should produce no findings
        assert!(findings.is_empty());
    }

    #[test]
    fn run_all_on_config_with_duplicates() {
        let config = Config {
            items: vec![
                Item::HostBlock {
                    patterns: vec!["github.com".to_string()],
                    span: Span::new(1),
                    items: vec![],
                },
                Item::HostBlock {
                    patterns: vec!["github.com".to_string()],
                    span: Span::new(5),
                    items: vec![],
                },
            ],
        };
        let findings = run_all(&config);
        assert!(findings.iter().any(|f| f.rule == "duplicate-host"));
    }
}
