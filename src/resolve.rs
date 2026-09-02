use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::lexer;
use crate::model::{Config, Finding, Item, Severity, Span};
use crate::parser;

const MAX_INCLUDE_DEPTH: usize = 16;

/// Resolve all Include directives in-place, returning any findings (missing files, cycles, etc).
pub fn resolve_includes(config: &mut Config, base_dir: &Path) -> Vec<Finding> {
    let mut visited = HashSet::new();
    let mut findings = Vec::new();
    config.items = resolve_items(&config.items, base_dir, 0, &mut visited, &mut findings);
    findings
}

fn resolve_items(
    items: &[Item],
    base_dir: &Path,
    depth: usize,
    visited: &mut HashSet<PathBuf>,
    findings: &mut Vec<Finding>,
) -> Vec<Item> {
    let mut result = Vec::new();

    for item in items {
        match item {
            Item::Include { patterns, span } => {
                // Expand each include pattern separately
                for pattern in patterns {
                    let expanded =
                        expand_include(pattern, base_dir, depth, span, visited, findings);
                    result.extend(expanded);
                }
            }
            Item::HostBlock {
                patterns,
                span,
                items: block_items,
            } => {
                let resolved_items = resolve_items(block_items, base_dir, depth, visited, findings);
                result.push(Item::HostBlock {
                    patterns: patterns.clone(),
                    span: span.clone(),
                    items: resolved_items,
                });
            }
            Item::MatchBlock {
                criteria,
                span,
                items: block_items,
            } => {
                let resolved_items = resolve_items(block_items, base_dir, depth, visited, findings);
                result.push(Item::MatchBlock {
                    criteria: criteria.clone(),
                    span: span.clone(),
                    items: resolved_items,
                });
            }
            other => result.push(other.clone()),
        }
    }

    result
}

fn expand_include(
    pattern: &str,
    base_dir: &Path,
    depth: usize,
    span: &Span,
    visited: &mut HashSet<PathBuf>,
    findings: &mut Vec<Finding>,
) -> Vec<Item> {
    if depth >= MAX_INCLUDE_DEPTH {
        findings.push(
            Finding::new(
                Severity::Error,
                "include-depth",
                "INCLUDE_DEPTH",
                format!(
                    "Include nesting exceeds OpenSSH's maximum depth of {MAX_INCLUDE_DEPTH}: {pattern}"
                ),
                span.clone(),
            )
            .with_hint("flatten the Include chain to at most 16 nested files"),
        );
        return Vec::new();
    }

    let resolved_pattern = if pattern == "~" {
        if let Some(home) = dirs::home_dir() {
            home.to_string_lossy().to_string()
        } else {
            pattern.to_string()
        }
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(rest).to_string_lossy().to_string()
        } else {
            pattern.to_string()
        }
    } else if !Path::new(pattern).is_absolute() {
        base_dir.join(pattern).to_string_lossy().to_string()
    } else {
        pattern.to_string()
    };

    let paths = match glob::glob(&resolved_pattern) {
        Ok(paths) => {
            let mut sorted: Vec<PathBuf> = paths.filter_map(|p| p.ok()).collect();
            sorted.sort();
            sorted
        }
        Err(_) => {
            findings.push(Finding::new(
                Severity::Error,
                "include-glob",
                "INCLUDE_GLOB",
                format!("invalid Include glob pattern: {}", pattern),
                span.clone(),
            ));
            return Vec::new();
        }
    };

    if paths.is_empty() {
        // OpenSSH silently ignores includes that match nothing, so just info.
        findings.push(Finding::new(
            Severity::Info,
            "include-no-match",
            "INCLUDE_NO_MATCH",
            format!("Include pattern '{}' matched no files", pattern),
            span.clone(),
        ));
        return Vec::new();
    }

    let mut result = Vec::new();
    for path in paths {
        let canonical = match path.canonicalize() {
            Ok(c) => c,
            Err(_) => {
                findings.push(Finding::new(
                    Severity::Error,
                    "include-read",
                    "INCLUDE_READ",
                    format!("cannot read included file: {}", path.display()),
                    span.clone(),
                ));
                continue;
            }
        };

        if !visited.insert(canonical.clone()) {
            findings.push(
                Finding::new(
                    Severity::Error,
                    "include-cycle",
                    "INCLUDE_CYCLE",
                    format!("Include cycle detected: {}", canonical.display()),
                    span.clone(),
                )
                .with_hint("break the circular Include chain"),
            );
            continue;
        }

        match std::fs::read_to_string(&canonical) {
            Ok(content) => {
                let lines = lexer::lex(&content);
                let mut sub_config = parser::parse(lines);
                crate::assign_file_to_config(&mut sub_config, &canonical);
                // Resolve includes within the included file.
                let sub_dir = canonical.parent().unwrap_or(base_dir);
                let sub_items =
                    resolve_items(&sub_config.items, sub_dir, depth + 1, visited, findings);
                sub_config.items = sub_items;
                result.extend(sub_config.items);
            }
            Err(e) => {
                findings.push(Finding::new(
                    Severity::Error,
                    "include-read",
                    "INCLUDE_READ",
                    format!("cannot read included file {}: {}", canonical.display(), e),
                    span.clone(),
                ));
            }
        }

        visited.remove(&canonical);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn include_resolves_single_file() {
        let tmp = TempDir::new().unwrap();
        let sub_file = tmp.path().join("extra.conf");
        fs::write(&sub_file, "User alice\n").unwrap();

        let main_content = format!("Include {}", sub_file.display());
        let lines = lexer::lex(&main_content);
        let mut config = parser::parse(lines);
        let findings = resolve_includes(&mut config, tmp.path());

        // Should have spliced in the directive from extra.conf
        assert_eq!(config.items.len(), 1);
        assert!(matches!(
            &config.items[0],
            Item::Directive { key, value, .. } if key == "User" && value == "alice"
        ));
        // No errors expected
        assert!(
            findings
                .iter()
                .all(|f| f.severity != crate::model::Severity::Error)
        );
    }

    #[test]
    fn include_glob_returns_sorted() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("b.conf"), "User bob\n").unwrap();
        fs::write(tmp.path().join("a.conf"), "User alice\n").unwrap();

        let pattern = tmp.path().join("*.conf");
        let main_content = format!("Include {}", pattern.display());
        let lines = lexer::lex(&main_content);
        let mut config = parser::parse(lines);
        let findings = resolve_includes(&mut config, tmp.path());

        assert_eq!(config.items.len(), 2);
        // a.conf should come first (sorted)
        assert!(matches!(
            &config.items[0],
            Item::Directive { value, .. } if value == "alice"
        ));
        assert!(matches!(
            &config.items[1],
            Item::Directive { value, .. } if value == "bob"
        ));
        assert!(
            findings
                .iter()
                .all(|f| f.severity != crate::model::Severity::Error)
        );
    }

    #[test]
    fn include_cycle_detected() {
        let tmp = TempDir::new().unwrap();
        let file_a = tmp.path().join("a.conf");
        let file_b = tmp.path().join("b.conf");

        // a includes b, b includes a
        fs::write(&file_a, format!("Include {}", file_b.display())).unwrap();
        fs::write(&file_b, format!("Include {}", file_a.display())).unwrap();

        let main_content = format!("Include {}", file_a.display());
        let lines = lexer::lex(&main_content);
        let mut config = parser::parse(lines);
        let findings = resolve_includes(&mut config, tmp.path());

        let cycle_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "include-cycle")
            .collect();
        assert!(
            !cycle_findings.is_empty(),
            "should detect include cycle, got findings: {:?}",
            findings
        );
    }

    #[test]
    fn include_no_match_is_info() {
        let tmp = TempDir::new().unwrap();
        let main_content = format!("Include {}/nonexistent*.conf", tmp.path().display());
        let lines = lexer::lex(&main_content);
        let mut config = parser::parse(lines);
        let findings = resolve_includes(&mut config, tmp.path());

        assert!(findings.iter().any(|f| f.rule == "include-no-match"));
        assert!(
            findings
                .iter()
                .filter(|f| f.rule == "include-no-match")
                .all(|f| f.severity == crate::model::Severity::Info)
        );
    }

    #[test]
    fn bare_tilde_include_never_panics() {
        let result = std::panic::catch_unwind(|| {
            let lines = lexer::lex("Include ~");
            let mut config = parser::parse(lines);
            resolve_includes(&mut config, Path::new("."))
        });
        assert!(result.is_ok(), "Include ~ must not panic");
    }

    #[test]
    fn quoted_include_path_with_spaces_resolves() {
        let tmp = TempDir::new().unwrap();
        let included = tmp.path().join("extra config");
        fs::write(&included, "User alice\n").unwrap();
        let input = format!(r#"Include "{}""#, included.display());
        let mut config = parser::parse(lexer::lex(&input));

        let findings = resolve_includes(&mut config, tmp.path());

        assert!(
            findings
                .iter()
                .all(|finding| finding.severity != Severity::Error)
        );
        assert!(matches!(
            &config.items[0],
            Item::Directive { key, value, .. } if key == "User" && value == "alice"
        ));
    }

    #[test]
    fn escaped_space_in_include_path_resolves() {
        let tmp = TempDir::new().unwrap();
        let included = tmp.path().join("extra config");
        fs::write(&included, "User alice\n").unwrap();
        let escaped = included.to_string_lossy().replace(' ', r#"\ "#);
        let mut config = parser::parse(lexer::lex(&format!("Include {escaped}")));

        let findings = resolve_includes(&mut config, tmp.path());

        assert!(
            findings
                .iter()
                .all(|finding| finding.severity != Severity::Error)
        );
        assert!(matches!(&config.items[0], Item::Directive { key, .. } if key == "User"));
    }

    #[test]
    fn direct_self_include_is_bounded_and_reported() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("config");
        fs::write(&root, format!("Include {}\n", root.display())).unwrap();
        let findings = crate::lint_file(&root).unwrap();
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "INCLUDE_CYCLE")
                .count(),
            1
        );
    }

    #[test]
    fn acyclic_include_depth_is_bounded_like_openssh() {
        let tmp = TempDir::new().unwrap();
        for index in 0..18 {
            let content = if index == 17 {
                "User alice\n".to_string()
            } else {
                format!(
                    "Include {}\n",
                    tmp.path()
                        .join(format!("{next}.conf", next = index + 1))
                        .display()
                )
            };
            fs::write(tmp.path().join(format!("{index}.conf")), content).unwrap();
        }

        let findings = crate::lint_file(&tmp.path().join("0.conf")).unwrap();
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "INCLUDE_DEPTH")
                .count(),
            1,
            "{findings:?}"
        );
    }
}
