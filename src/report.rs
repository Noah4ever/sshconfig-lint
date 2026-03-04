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
            "{}line {}: [{}] {} ({}) {}",
            file_info, f.span.line, f.severity, f.code, f.rule, f.message
        ));
        if let Some(hint) = &f.hint {
            out.push_str(&format!(" (hint: {})", hint));
        }
        out.push('\n');
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
            let hint = match &f.hint {
                Some(h) => format!("\"{}\"", h.replace('\\', "\\\\").replace('"', "\\\"")),
                None => "null".to_string(),
            };
            format!(
                r#"  {{"severity":"{}","code":"{}","rule":"{}","line":{},"file":{},"message":"{}","hint":{}}}"#,
                f.severity,
                f.code,
                f.rule,
                f.span.line,
                file,
                f.message.replace('\\', "\\\\").replace('"', "\\\""),
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
    use crate::model::{Finding, Span};

    #[test]
    fn text_no_findings() {
        let output = emit_text(&[][..]);
        assert_eq!(output, "No issues found.\n");
    }

    #[test]
    fn text_single_finding() {
        let findings = vec![
            Finding::warning("test-rule", "TEST", "something is wrong", Span::new(42))
                .with_hint("fix it"),
        ];
        let output = emit_text(&findings);
        assert!(output.contains("line 42"));
        assert!(output.contains("[warning]"));
        assert!(output.contains("TEST"));
        assert!(output.contains("(test-rule)"));
        assert!(output.contains("something is wrong"));
        assert!(output.contains("(hint: fix it)"));
    }

    #[test]
    fn text_finding_with_file() {
        let findings = vec![Finding::error(
            "test-rule",
            "TEST",
            "bad config",
            Span::with_file(10, "/etc/ssh/config"),
        )];
        let output = emit_text(&findings);
        assert!(output.contains("/etc/ssh/config:line 10"));
    }

    #[test]
    fn json_no_findings() {
        let output = emit_json(&[][..]);
        assert_eq!(output, "[]");
    }

    #[test]
    fn json_single_finding() {
        let findings = vec![Finding::info("my-rule", "TEST", "hello", Span::new(1))];
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
        let findings = vec![Finding::error(
            "x",
            "TEST",
            "msg",
            Span::with_file(5, "test.conf"),
        )];
        let output = emit_json(&findings);
        assert!(output.contains("\"file\":\"test.conf\""));
    }
}
