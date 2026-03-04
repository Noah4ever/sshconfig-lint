use crate::model::{Config, Item, Line, LineKind};

/// Parse a space-separated list of patterns, respecting quoted values.
fn parse_patterns(value: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for ch in value.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                current.push(ch);
            }
            ' ' | '\t' if !in_quote => {
                if !current.is_empty() {
                    patterns.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        patterns.push(current);
    }

    patterns
}

/// Parse lexed lines into a structured Config AST.
pub fn parse(lines: Vec<Line>) -> Config {
    let mut items = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = &lines[i];
        match &line.kind {
            LineKind::Empty => {
                i += 1;
            }
            LineKind::Comment(text) => {
                items.push(Item::Comment {
                    text: text.clone(),
                    span: line.span.clone(),
                });
                i += 1;
            }
            LineKind::Directive { key, value } => {
                let key_lower = key.to_lowercase();
                match key_lower.as_str() {
                    "host" => {
                        let span = line.span.clone();
                        let patterns = parse_patterns(value);
                        let (block_items, next_i) = collect_block(&lines, i + 1);
                        items.push(Item::HostBlock {
                            patterns,
                            span,
                            items: block_items,
                        });
                        i = next_i;
                    }
                    "match" => {
                        let span = line.span.clone();
                        let criteria = value.clone();
                        let (block_items, next_i) = collect_block(&lines, i + 1);
                        items.push(Item::MatchBlock {
                            criteria,
                            span,
                            items: block_items,
                        });
                        i = next_i;
                    }
                    "include" => {
                        let span = line.span.clone();
                        let patterns = parse_patterns(value);
                        items.push(Item::Include { patterns, span });
                        i += 1;
                    }
                    _ => {
                        items.push(Item::Directive {
                            key: key.clone(),
                            value: value.clone(),
                            span: line.span.clone(),
                        });
                        i += 1;
                    }
                }
            }
        }
    }

    Config { items }
}

/// Collect directives that belong inside a Host/Match block.
/// A block ends when we hit another Host, Match, or end-of-input.
fn collect_block(lines: &[Line], start: usize) -> (Vec<Item>, usize) {
    let mut items = Vec::new();
    let mut i = start;

    while i < lines.len() {
        let line = &lines[i];
        match &line.kind {
            LineKind::Empty => {
                i += 1;
            }
            LineKind::Comment(text) => {
                items.push(Item::Comment {
                    text: text.clone(),
                    span: line.span.clone(),
                });
                i += 1;
            }
            LineKind::Directive { key, value } => {
                let key_lower = key.to_lowercase();
                match key_lower.as_str() {
                    // These start a new block, so we stop collecting.
                    "host" | "match" => break,
                    "include" => {
                        let span = line.span.clone();
                        let patterns = parse_patterns(value);
                        items.push(Item::Include { patterns, span });
                        i += 1;
                    }
                    _ => {
                        items.push(Item::Directive {
                            key: key.clone(),
                            value: value.clone(),
                            span: line.span.clone(),
                        });
                        i += 1;
                    }
                }
            }
        }
    }

    (items, i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    #[test]
    fn empty_config() {
        let config = parse(lex(""));
        assert!(
            config.items.is_empty()
                || config
                    .items
                    .iter()
                    .all(|i| matches!(i, Item::Comment { .. }))
        );
    }

    #[test]
    fn single_root_directive() {
        let config = parse(lex("ServerAliveInterval 60"));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::Directive { key, value, .. } => {
                assert_eq!(key, "ServerAliveInterval");
                assert_eq!(value, "60");
            }
            other => panic!("expected Directive, got {:?}", other),
        }
    }

    #[test]
    fn host_block_collects_directives() {
        let input = "Host github.com\n  User git\n  IdentityFile ~/.ssh/gh";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::HostBlock {
                patterns, items, ..
            } => {
                assert_eq!(patterns, &vec!["github.com".to_string()]);
                assert_eq!(items.len(), 2);
                match &items[0] {
                    Item::Directive { key, value, .. } => {
                        assert_eq!(key, "User");
                        assert_eq!(value, "git");
                    }
                    other => panic!("expected Directive, got {:?}", other),
                }
            }
            other => panic!("expected HostBlock, got {:?}", other),
        }
    }

    #[test]
    fn multiple_host_blocks() {
        let input = "Host a\n  User alice\nHost b\n  User bob";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 2);
        assert!(matches!(
            &config.items[0],
            Item::HostBlock { patterns, .. } if patterns == &vec!["a".to_string()]
        ));
        assert!(matches!(
            &config.items[1],
            Item::HostBlock { patterns, .. } if patterns == &vec!["b".to_string()]
        ));
    }

    #[test]
    fn match_block() {
        let input = "Match host github.com\n  User git";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::MatchBlock {
                criteria, items, ..
            } => {
                assert_eq!(criteria, "host github.com");
                assert_eq!(items.len(), 1);
            }
            other => panic!("expected MatchBlock, got {:?}", other),
        }
    }

    #[test]
    fn include_becomes_item() {
        let input = "Include config.d/*";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::Include { patterns, .. } => {
                assert_eq!(patterns, &vec!["config.d/*".to_string()]);
            }
            other => panic!("expected Include, got {:?}", other),
        }
    }

    #[test]
    fn include_inside_host_block() {
        let input = "Host a\n  Include extra.conf\n  User alice";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::HostBlock { items, .. } => {
                assert_eq!(items.len(), 2);
                assert!(matches!(
                    &items[0],
                    Item::Include { patterns, .. } if patterns == &vec!["extra.conf".to_string()]
                ));
                assert!(matches!(&items[1], Item::Directive { key, .. } if key == "User"));
            }
            other => panic!("expected HostBlock, got {:?}", other),
        }
    }

    #[test]
    fn root_directives_before_host() {
        let input = "ServerAliveInterval 60\n\nHost a\n  User alice";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 2);
        assert!(matches!(
            &config.items[0],
            Item::Directive { key, .. } if key == "ServerAliveInterval"
        ));
        assert!(matches!(
            &config.items[1],
            Item::HostBlock { patterns, .. } if patterns == &vec!["a".to_string()]
        ));
    }

    #[test]
    fn comments_preserved() {
        let input = "# global comment\nHost a\n  # block comment\n  User alice";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 2);
        assert!(matches!(&config.items[0], Item::Comment { .. }));
        match &config.items[1] {
            Item::HostBlock { items, .. } => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], Item::Comment { .. }));
            }
            other => panic!("expected HostBlock, got {:?}", other),
        }
    }

    #[test]
    fn host_with_multiple_patterns() {
        let input = "Host github.com gitlab.com *.corp";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::HostBlock { patterns, .. } => {
                assert_eq!(
                    patterns,
                    &vec![
                        "github.com".to_string(),
                        "gitlab.com".to_string(),
                        "*.corp".to_string()
                    ]
                );
            }
            other => panic!("expected HostBlock, got {:?}", other),
        }
    }

    #[test]
    fn include_with_multiple_patterns() {
        let input = "Include ~/.ssh/conf.d/*.conf ~/.ssh/extra.conf";
        let config = parse(lex(input));
        assert_eq!(config.items.len(), 1);
        match &config.items[0] {
            Item::Include { patterns, .. } => {
                assert_eq!(
                    patterns,
                    &vec![
                        "~/.ssh/conf.d/*.conf".to_string(),
                        "~/.ssh/extra.conf".to_string()
                    ]
                );
            }
            other => panic!("expected Include, got {:?}", other),
        }
    }
}
