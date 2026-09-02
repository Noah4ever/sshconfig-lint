mod arguments;
pub mod lexer;
pub mod lsp;
pub mod model;
pub mod parser;
pub mod report;
pub mod resolve;
pub mod rules;

use std::path::Path;

use model::{Config, Finding, Item, Span};

/// Sort findings by file then line number for deterministic output.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.span
            .file
            .cmp(&b.span.file)
            .then(a.span.line.cmp(&b.span.line))
    });
}

/// Lint an SSH config from a string. Does not touch the filesystem.
pub fn lint_str(input: &str) -> Vec<Finding> {
    let lines = lexer::lex(input);
    let config = parser::parse(lines);
    let mut findings = rules::run_all(&config);
    sort_findings(&mut findings);
    findings
}

/// Lint an SSH config from an untitled editor buffer.
///
/// Rules that require a real filesystem location are intentionally skipped.
pub fn lint_str_portable(input: &str) -> Vec<Finding> {
    let lines = lexer::lex(input);
    let config = parser::parse(lines);
    let mut findings = rules::run_portable(&config);
    sort_findings(&mut findings);
    findings
}

fn assign_span_file(span: &mut Span, file: &str) {
    span.file = Some(file.to_string());
}

pub(crate) fn assign_file_to_config(config: &mut Config, path: &Path) {
    let file = path.to_string_lossy();

    fn assign_items(items: &mut [Item], file: &str) {
        for item in items {
            match item {
                Item::Comment { span, .. }
                | Item::Directive { span, .. }
                | Item::Include { span, .. } => assign_span_file(span, file),
                Item::HostBlock { span, items, .. } | Item::MatchBlock { span, items, .. } => {
                    assign_span_file(span, file);
                    assign_items(items, file);
                }
            }
        }
    }

    assign_items(&mut config.items, &file);
}

/// Lint in-memory contents while associating root diagnostics with `path`.
/// Include directives are resolved relative to that path when enabled.
pub fn lint_str_at_path(input: &str, path: &Path, resolve_includes: bool) -> Vec<Finding> {
    let lines = lexer::lex(input);
    let mut config = parser::parse(lines);
    assign_file_to_config(&mut config, path);

    let mut findings = if resolve_includes {
        let base_dir = path.parent().unwrap_or(Path::new("."));
        resolve::resolve_includes(&mut config, base_dir)
    } else {
        Vec::new()
    };
    findings.extend(rules::run_all(&config));
    sort_findings(&mut findings);
    findings
}

/// Lint an SSH config from a string, with Include resolution against a base dir.
pub fn lint_str_with_includes(input: &str, base_dir: &Path) -> Vec<Finding> {
    let lines = lexer::lex(input);
    let mut config = parser::parse(lines);
    let mut findings = resolve::resolve_includes(&mut config, base_dir);
    findings.extend(rules::run_all(&config));
    sort_findings(&mut findings);
    findings
}

/// Lint an SSH config file by path, resolving Includes.
pub fn lint_file(path: &Path) -> Result<Vec<Finding>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(lint_str_at_path(&content, path, true))
}

/// Lint an SSH config file by path, skipping Include resolution.
pub fn lint_file_no_includes(path: &Path) -> Result<Vec<Finding>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(lint_str_at_path(&content, path, false))
}

/// Returns true if any finding has Error severity.
pub fn has_errors(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.severity == model::Severity::Error)
}

/// Returns true if any finding has Warning or Error severity.
pub fn has_warnings(findings: &[Finding]) -> bool {
    findings.iter().any(|f| {
        matches!(
            f.severity,
            model::Severity::Warning | model::Severity::Error
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_str_empty_returns_empty() {
        let findings = lint_str("");
        assert!(findings.is_empty());
    }

    #[test]
    fn lint_str_clean_config_no_findings() {
        let input = "\
Host github.com
  User git
  IdentityFile %d/.ssh/id_ed25519

Host gitlab.com
  User git
";
        let findings = lint_str(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn lint_str_duplicate_host_found() {
        let input = "\
Host github.com
  User git

Host github.com
  User git2
";
        let findings = lint_str(input);
        assert!(findings.iter().any(|f| f.rule == "duplicate-host"));
    }

    #[test]
    fn lint_str_wildcard_before_specific_warns() {
        let input = "\
Host *
  ServerAliveInterval 60

Host github.com
  User git
";
        let findings = lint_str(input);
        assert!(findings.iter().any(|f| f.rule == "wildcard-host-order"));
    }

    #[test]
    fn has_errors_true_when_error_present() {
        let findings = vec![Finding::new(
            model::Severity::Error,
            "test",
            "TEST",
            "bad",
            model::Span::new(1),
        )];
        assert!(has_errors(&findings));
    }

    #[test]
    fn has_errors_false_when_only_warnings() {
        let findings = vec![Finding::new(
            model::Severity::Warning,
            "test",
            "TEST",
            "meh",
            model::Span::new(1),
        )];
        assert!(!has_errors(&findings));
    }

    #[test]
    fn has_warnings_true_when_warning_present() {
        let findings = vec![Finding::new(
            model::Severity::Warning,
            "test",
            "TEST",
            "meh",
            model::Span::new(1),
        )];
        assert!(has_warnings(&findings));
    }

    #[test]
    fn has_warnings_false_when_only_info() {
        let findings = vec![Finding::new(
            model::Severity::Info,
            "test",
            "TEST",
            "ok",
            model::Span::new(1),
        )];
        assert!(!has_warnings(&findings));
    }

    #[test]
    #[ignore]
    fn lint_my_real_config() {
        let home = dirs::home_dir().expect("no home dir");
        let config_path = home.join(".ssh/config");
        if !config_path.exists() {
            eprintln!("~/.ssh/config not found, skipping");
            return;
        }
        let findings = lint_file(&config_path).expect("failed to read config");
        for f in &findings {
            eprintln!(
                "  line {}: [{}] ({}) {}",
                f.span.line, f.severity, f.rule, f.message
            );
        }
    }
}
