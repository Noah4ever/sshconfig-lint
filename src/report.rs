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
    for f in findings {
        let file_info = match &f.span.file {
            Some(file) => format!("{}:", file),
            None => String::new(),
        };

        let severity_str = if colored {
            let (color, label) = match f.severity {
                Severity::Error => (RED, "error"),
                Severity::Warning => (YELLOW, "warning"),
                Severity::Info => (CYAN, "info"),
            };
            format!("{BOLD}{color}{label}{RESET}")
        } else {
            f.severity.to_string()
        };

        let code_str = if colored {
            format!("{BOLD}{}{RESET}", f.code)
        } else {
            f.code.to_string()
        };

        out.push_str(&format!(
            "{}line {}: [{}] {} ({}) {}",
            file_info, f.span.line, severity_str, code_str, f.rule, f.message
        ));
        if let Some(hint) = &f.hint {
            if colored {
                out.push_str(&format!(" {DIM}(hint: {}){RESET}", hint));
            } else {
                out.push_str(&format!(" (hint: {})", hint));
            }
        }
        out.push('\n');
    }
    out
}

/// Escape a string for JSON output.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Emit findings as JSON (one JSON array).
pub fn emit_json(findings: &[Finding]) -> String {
    let entries: Vec<String> = findings
        .iter()
        .map(|f| {
            let file = match &f.span.file {
                Some(file) => format!("\"{}\"", json_escape(file)),
                None => "null".to_string(),
            };
            let hint = match &f.hint {
                Some(h) => format!("\"{}\"", json_escape(h)),
                None => "null".to_string(),
            };
            format!(
                r#"  {{"severity":"{}","code":"{}","rule":"{}","line":{},"file":{},"message":"{}","hint":{}}}"#,
                f.severity,
                f.code,
                json_escape(&f.rule),
                f.span.line,
                file,
                json_escape(&f.message),
                hint
            )
        })
        .collect();

    if entries.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{}\n]", entries.join(",\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Severity, Span};

    #[test]
    fn text_no_findings() {
        let output = emit_text(&[][..], false);
        assert_eq!(output, "No issues found.\n");
    }

    #[test]
    fn text_single_finding() {
        let findings = vec![
            Finding::new(
                Severity::Warning,
                "test-rule",
                "TEST",
                "something is wrong",
                Span::new(42),
            )
            .with_hint("fix it"),
        ];
        let output = emit_text(&findings, false);
        assert!(output.contains("line 42"));
        assert!(output.contains("[warning]"));
        assert!(output.contains("TEST"));
        assert!(output.contains("(test-rule)"));
        assert!(output.contains("something is wrong"));
        assert!(output.contains("(hint: fix it)"));
    }

    #[test]
    fn text_finding_with_file() {
        let findings = vec![Finding::new(
            Severity::Error,
            "test-rule",
            "TEST",
            "bad config",
            Span::with_file(10, "/etc/ssh/config"),
        )];
        let output = emit_text(&findings, false);
        assert!(output.contains("/etc/ssh/config:line 10"));
    }

    #[test]
    fn json_no_findings() {
        let output = emit_json(&[][..]);
        assert_eq!(output, "[]");
    }

    #[test]
    fn json_single_finding() {
        let findings = vec![Finding::new(
            Severity::Info,
            "my-rule",
            "TEST",
            "hello",
            Span::new(1),
        )];
        let output = emit_json(&findings);
        assert!(output.contains("\"severity\":\"info\""));
        assert!(output.contains("\"code\":\"TEST\""));
        assert!(output.contains("\"rule\":\"my-rule\""));
        assert!(output.contains("\"message\":\"hello\""));
        assert!(output.contains("\"line\":1"));
        assert!(output.contains("\"file\":null"));
        assert!(output.contains("\"hint\":null"));
    }

    #[test]
    fn json_finding_with_file() {
        let findings = vec![Finding::new(
            Severity::Error,
            "x",
            "TEST",
            "msg",
            Span::with_file(5, "test.conf"),
        )];
        let output = emit_json(&findings);
        assert!(output.contains("\"file\":\"test.conf\""));
    }

    #[test]
    fn text_colored_no_findings() {
        let output = emit_text(&[][..], true);
        assert!(output.contains("No issues found."));
        assert!(output.contains("\x1b[32m")); // green
        assert!(output.contains("\x1b[0m")); // reset
    }

    #[test]
    fn text_colored_error_is_red() {
        let findings = vec![Finding::new(
            Severity::Error,
            "r",
            "ERR",
            "bad",
            Span::new(1),
        )];
        let output = emit_text(&findings, true);
        assert!(output.contains("\x1b[31m")); // red
        assert!(output.contains("error"));
    }

    #[test]
    fn text_colored_warning_is_yellow() {
        let findings = vec![
            Finding::new(Severity::Warning, "r", "WARN", "hmm", Span::new(1)).with_hint("try this"),
        ];
        let output = emit_text(&findings, true);
        assert!(output.contains("\x1b[33m")); // yellow
        assert!(output.contains("warning"));
        assert!(output.contains("\x1b[2m")); // dim for hint
    }
}
