use crate::model::{Config, Finding, Item, Severity};
use crate::rules::Rule;

/// Warns about Host blocks that have exclusions but no positive pattern.
pub struct NegatedOnlyHost;

impl Rule for NegatedOnlyHost {
    fn name(&self) -> &'static str {
        "negated-only-host"
    }

    fn check(&self, config: &Config) -> Vec<Finding> {
        config
            .items
            .iter()
            .filter_map(|item| {
                let Item::HostBlock { patterns, span, .. } = item else {
                    return None;
                };
                (!patterns.is_empty() && patterns.iter().all(|pattern| pattern.starts_with('!')))
                    .then(|| {
                        Finding::new(
                            Severity::Warning,
                            self.name(),
                            "NEGATED_HOST",
                            format!(
                                "Host block with patterns '{}' never matches positively",
                                patterns.join(" ")
                            ),
                            span.clone(),
                        )
                        .with_hint("add a positive pattern such as * alongside the exclusions")
                    })
            })
            .collect()
    }
}
