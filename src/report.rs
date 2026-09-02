use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::model::{Finding, Severity};

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// Emit findings as human-readable text, optionally with ANSI colors.
pub fn emit_text(findings: &[Finding], colored: bool) -> String {
    if findings.is_empty() {
        return if colored {
            format!("{GREEN}{BOLD}No issues found.{RESET}\n")
        } else {
            String::from("No issues found.\n")
        };
    }

    let mut out = String::new();
    for finding in findings {
        let file_info = finding
            .span
            .file
            .as_ref()
            .map(|file| format!("{file}:"))
            .unwrap_or_default();

        let severity = if colored {
            let (color, label) = match finding.severity {
                Severity::Error => (RED, "error"),
                Severity::Warning => (YELLOW, "warning"),
                Severity::Info => (CYAN, "info"),
            };
            format!("{BOLD}{color}{label}{RESET}")
        } else {
            finding.severity.to_string()
        };

        let code = if colored {
            format!("{BOLD}{}{RESET}", finding.code)
        } else {
            finding.code.to_string()
        };

        out.push_str(&format!(
            "{}line {}: [{}] {} ({}) {}",
            file_info, finding.span.line, severity, code, finding.rule, finding.message
        ));
        if let Some(hint) = &finding.hint {
            if colored {
                out.push_str(&format!(" {DIM}(hint: {hint}){RESET}"));
            } else {
                out.push_str(&format!(" (hint: {hint})"));
            }
        }
        out.push('\n');
    }
    out
}

fn finding_json(finding: &Finding) -> Value {
    json!({
        "severity": finding.severity.to_string(),
        "code": finding.code,
        "rule": finding.rule,
        "line": finding.span.line,
        "file": finding.span.file,
        "message": finding.message,
        "hint": finding.hint,
        "documentation": finding.documentation_url(),
    })
}

/// Emit findings as one stable JSON array.
pub fn emit_json(findings: &[Finding]) -> String {
    let values: Vec<Value> = findings.iter().map(finding_json).collect();
    serde_json::to_string(&values).expect("findings are serializable")
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn artifact_uri(file: &str) -> String {
    file.replace('\\', "/").replace(' ', "%20")
}

/// Emit SARIF 2.1.0 for GitHub Code Scanning and compatible tools.
pub fn emit_sarif(findings: &[Finding]) -> String {
    let mut rules = BTreeMap::new();
    for finding in findings {
        rules.entry(finding.code).or_insert_with(|| {
            json!({
                "id": finding.code,
                "name": finding.rule,
                "helpUri": finding.documentation_url(),
                "shortDescription": { "text": finding.message },
                "properties": { "defaultConfiguration": { "level": sarif_level(finding.severity) } }
            })
        });
    }

    let results: Vec<Value> = findings
        .iter()
        .map(|finding| {
            let mut result = json!({
                "ruleId": finding.code,
                "level": sarif_level(finding.severity),
                "message": {
                    "text": match &finding.hint {
                        Some(hint) => format!("{} Hint: {}", finding.message, hint),
                        None => finding.message.clone(),
                    }
                }
            });

            if let Some(file) = &finding.span.file {
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": artifact_uri(file) },
                        "region": { "startLine": finding.span.line }
                    }
                }]);
            }
            result
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sshconfig-lint",
                    "informationUri": "https://sshconfig-lint.apps.thiering.org",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules.into_values().collect::<Vec<_>>()
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("SARIF is serializable")
}

fn github_escape_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn github_escape_property(value: &str) -> String {
    github_escape_data(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn relative_to_current_dir(file: &str) -> String {
    let path = Path::new(file);
    std::env::current_dir()
        .ok()
        .and_then(|cwd| path.strip_prefix(cwd).ok().map(Path::to_path_buf))
        .unwrap_or_else(|| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

/// Emit native GitHub workflow commands for inline annotations.
pub fn emit_github(findings: &[Finding]) -> String {
    let mut out = String::new();
    for finding in findings {
        let command = match finding.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "notice",
        };
        let file = finding
            .span
            .file
            .as_deref()
            .map(relative_to_current_dir)
            .unwrap_or_default();
        let message = match &finding.hint {
            Some(hint) => format!("{} Hint: {}", finding.message, hint),
            None => finding.message.clone(),
        };
        out.push_str(&format!(
            "::{command} file={},line={},title={}::{}\n",
            github_escape_property(&file),
            finding.span.line,
            github_escape_property(finding.code),
            github_escape_data(&message)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Severity, Span};

    fn sample() -> Finding {
        Finding::new(
            Severity::Warning,
            "duplicate-host",
            "DUP_HOST",
            "duplicate Host block",
            Span::with_file(4, "configs/ssh config"),
        )
        .with_hint("remove the duplicate")
    }

    #[test]
    fn text_no_findings() {
        assert_eq!(emit_text(&[], false), "No issues found.\n");
    }

    #[test]
    fn json_contains_stable_diagnostic_fields() {
        let output = emit_json(&[sample()]);
        assert!(output.contains("\"code\":\"DUP_HOST\""));
        assert!(output.contains("\"documentation\""));
        assert!(output.contains("/en/rules/duplicate-host"));
    }

    #[test]
    fn sarif_contains_rule_and_location() {
        let output = emit_sarif(&[sample()]);
        assert!(output.contains("\"version\": \"2.1.0\""));
        assert!(output.contains("DUP_HOST"));
        assert!(output.contains("configs/ssh%20config"));
    }

    #[test]
    fn github_contains_escaped_annotation() {
        let output = emit_github(&[sample()]);
        assert!(output.starts_with("::warning "));
        assert!(output.contains("line=4"));
        assert!(output.contains("title=DUP_HOST"));
    }

    #[test]
    fn github_escapes_every_reserved_character_in_properties_and_messages() {
        let finding = Finding::new(
            Severity::Error,
            "invalid-percent-token",
            "INVALID_TOKEN",
            "first%\r\nsecond",
            Span::with_file(7, "configs/a:b,c% file"),
        )
        .with_hint("try 100%, then\nretry");

        assert_eq!(
            emit_github(&[finding]),
            "::error file=configs/a%3Ab%2Cc%25 file,line=7,title=INVALID_TOKEN::first%25%0D%0Asecond Hint: try 100%25, then%0Aretry\n"
        );
    }

    #[test]
    fn colored_error_uses_ansi() {
        let finding = Finding::new(Severity::Error, "test", "TEST", "bad", Span::new(1));
        let output = emit_text(&[finding], true);
        assert!(output.contains(RED));
        assert!(output.contains(RESET));
    }
}
