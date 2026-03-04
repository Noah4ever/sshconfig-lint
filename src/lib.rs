pub mod lexer;
pub mod model;
pub mod parser;
pub mod report;
pub mod resolve;
pub mod rules;

use std::path::Path;

use model::Finding;

/// Sort findings by file then line number for deterministic output.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.span
            .file
            .cmp(&b.span.file)
            .then(a.span.line.cmp(&b.span.line))
    });
}

/// Lint an SSH config from a string (no filesystem). Great for unit tests.
pub fn lint_str(input: &str) -> Vec<Finding> {
    let lines = lexer::lex(input);
    let config = parser::parse(lines);
    let mut findings = rules::run_all(&config);
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
    let base_dir = path.parent().unwrap_or(Path::new("."));
    Ok(lint_str_with_includes(&content, base_dir))
}

/// Lint an SSH config file by path, skipping Include resolution.
pub fn lint_file_no_includes(path: &Path) -> Result<Vec<Finding>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(lint_str(&content))
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
        let findings = vec![Finding::error("test", "TEST", "bad", model::Span::new(1))];
        assert!(has_errors(&findings));
    }

    #[test]
    fn has_errors_false_when_only_warnings() {
        let findings = vec![Finding::warning("test", "TEST", "meh", model::Span::new(1))];
        assert!(!has_errors(&findings));
    }

    #[test]
    fn has_warnings_true_when_warning_present() {
        let findings = vec![Finding::warning("test", "TEST", "meh", model::Span::new(1))];
        assert!(has_warnings(&findings));
    }

    #[test]
    fn has_warnings_false_when_only_info() {
        let findings = vec![Finding::info("test", "TEST", "ok", model::Span::new(1))];
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
