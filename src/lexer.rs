use crate::model::{Line, LineKind, Span};

/// Lex raw text into a sequence of Lines.
pub fn lex(input: &str) -> Vec<Line> {
    input
        .lines()
        .enumerate()
        .map(|(i, raw)| {
            let line_num = i + 1; // 1-based
            let trimmed = raw.trim();

            let kind = if trimmed.is_empty() {
                LineKind::Empty
            } else if trimmed.starts_with('#') {
                LineKind::Comment(trimmed.to_string())
            } else {
                parse_directive(trimmed)
            };

            Line {
                kind,
                span: Span::new(line_num),
            }
        })
        .collect()
}

/// Parse a directive line into key/value.
/// Handles both `Key Value` and `Key=Value` and `Key = Value` forms.
fn parse_directive(line: &str) -> LineKind {
    // First try splitting on '='
    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim();
        // Only treat as key=value if the key part has no spaces
        // (otherwise it's a regular "Key Value" where value contains '=')
        if !key.contains(' ') {
            return LineKind::Directive {
                key: key.to_string(),
                value: value.to_string(),
            };
        }
    }

    // Split on first whitespace
    if let Some(space_pos) = line.find(|c: char| c.is_whitespace()) {
        let key = line[..space_pos].trim();
        let value = line[space_pos..].trim();
        LineKind::Directive {
            key: key.to_string(),
            value: value.to_string(),
        }
    } else {
        // Bare keyword with no value (shouldn't happen often)
        LineKind::Directive {
            key: line.to_string(),
            value: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        let lines = lex("");
        assert_eq!(lines.len(), 0);
    }

    #[test]
    fn empty_line() {
        let lines = lex("\n");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].kind, LineKind::Empty);
    }

    #[test]
    fn comment_line() {
        let lines = lex("# this is a comment");
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].kind,
            LineKind::Comment("# this is a comment".into())
        );
    }

    #[test]
    fn directive_space_separated() {
        let lines = lex("Host foo");
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].kind,
            LineKind::Directive {
                key: "Host".into(),
                value: "foo".into(),
            }
        );
    }

    #[test]
    fn directive_equals_no_spaces() {
        let lines = lex("IdentityFile=~/.ssh/id_ed25519");
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].kind,
            LineKind::Directive {
                key: "IdentityFile".into(),
                value: "~/.ssh/id_ed25519".into(),
            }
        );
    }

    #[test]
    fn directive_equals_with_spaces() {
        let lines = lex("IdentityFile = ~/.ssh/id_ed25519");
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].kind,
            LineKind::Directive {
                key: "IdentityFile".into(),
                value: "~/.ssh/id_ed25519".into(),
            }
        );
    }

    #[test]
    fn directive_with_leading_whitespace() {
        let lines = lex("  User alice");
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].kind,
            LineKind::Directive {
                key: "User".into(),
                value: "alice".into(),
            }
        );
    }

    #[test]
    fn span_line_numbers_correct() {
        let input = "Host foo\n  User bar\n\n# comment";
        let lines = lex(input);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].span.line, 1);
        assert_eq!(lines[1].span.line, 2);
        assert_eq!(lines[2].span.line, 3);
        assert_eq!(lines[3].span.line, 4);
    }

    #[test]
    fn mixed_content() {
        let input = "# header\nHost github.com\n  IdentityFile ~/.ssh/gh\n  User git";
        let lines = lex(input);
        assert_eq!(lines.len(), 4);
        assert!(matches!(lines[0].kind, LineKind::Comment(_)));
        assert!(matches!(
            lines[1].kind,
            LineKind::Directive {
                ref key,
                ref value
            } if key == "Host" && value == "github.com"
        ));
        assert!(matches!(
            lines[2].kind,
            LineKind::Directive {
                ref key,
                ref value
            } if key == "IdentityFile" && value == "~/.ssh/gh"
        ));
        assert!(matches!(
            lines[3].kind,
            LineKind::Directive {
                ref key,
                ref value
            } if key == "User" && value == "git"
        ));
    }
}
