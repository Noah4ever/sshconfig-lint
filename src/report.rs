use crate::model::Finding;

/// Emit findings as human-readable text.
pub fn emit_text(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::from("No issues found.\n");
    }

    let mut out = String::new();
    for f in findings {
        let file_info = match &f.span.file {
            Some(file) => format!("{}:", file),
            None => String::new(),
        };
        out.push_str(&format!(
            "{}line {}: [{}] ({}) {}\n",
            file_info, f.span.line, f.severity, f.rule, f.message
        ));
    }
    out
}

/// Emit findings as JSON (one JSON array).
pub fn emit_json(findings: &[Finding]) -> String {
    let entries: Vec<String> = findings
        .iter()
        .map(|f| {
            let file = match &f.span.file {
                Some(file) => format!("\"{}\"", file.replace('\\', "\\\\").replace('"', "\\\"")),
                None => "null".to_string(),
            };
            format!(
                r#"  {{"severity":"{}","rule":"{}","line":{},"file":{},"message":"{}"}}"#,
                f.severity,
                f.rule,
                f.span.line,
                file,
                f.message.replace('\\', "\\\\").replace('"', "\\\"")
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
    use crate::model::{Finding, Span};

    #[test]
    fn text_no_findings() {
        let output = emit_text(&[]);
        assert_eq!(output, "No issues found.\n");
    }

    #[test]
    fn text_single_finding() {
        let findings = vec![Finding::warning(
            "test-rule",
            "something is wrong",
            Span::new(42),
        )];
        let output = emit_text(&findings);
        assert!(output.contains("line 42"));
        assert!(output.contains("[warning]"));
        assert!(output.contains("(test-rule)"));
        assert!(output.contains("something is wrong"));
    }

    #[test]
    fn text_finding_with_file() {
        let findings = vec![Finding::error(
            "test-rule",
            "bad config",
            Span::with_file(10, "/etc/ssh/config"),
        )];
        let output = emit_text(&findings);
        assert!(output.contains("/etc/ssh/config:line 10"));
    }

    #[test]
    fn json_no_findings() {
        let output = emit_json(&[]);
        assert_eq!(output, "[]");
    }

    #[test]
    fn json_single_finding() {
        let findings = vec![Finding::info("my-rule", "hello", Span::new(1))];
        let output = emit_json(&findings);
        assert!(output.contains("\"severity\":\"info\""));
        assert!(output.contains("\"rule\":\"my-rule\""));
        assert!(output.contains("\"message\":\"hello\""));
        assert!(output.contains("\"line\":1"));
        assert!(output.contains("\"file\":null"));
    }

    #[test]
    fn json_finding_with_file() {
        let findings = vec![Finding::error("x", "msg", Span::with_file(5, "test.conf"))];
        let output = emit_json(&findings);
        assert!(output.contains("\"file\":\"test.conf\""));
    }
}
