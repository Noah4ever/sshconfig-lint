/// Span tracks where something came from in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// 1-based line number.
    pub line: usize,
    /// Optional file path (for includes).
    pub file: Option<String>,
}

impl Span {
    pub fn new(line: usize) -> Self {
        Self { line, file: None }
    }

    pub fn with_file(line: usize, file: impl Into<String>) -> Self {
        Self {
            line,
            file: Some(file.into()),
        }
    }
}

/// A single lexed line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineKind {
    Empty,
    Comment(String),
    Directive { key: String, value: String },
}

/// A lexed line with its span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub kind: LineKind,
    pub span: Span,
}

/// Parsed items that form the config AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A comment line.
    Comment { text: String, span: Span },
    /// A standalone directive (at root level or inside a block).
    Directive {
        key: String,
        value: String,
        span: Span,
    },
    /// A Host block with patterns and child directives.
    HostBlock {
        patterns: Vec<String>,
        span: Span,
        items: Vec<Item>,
    },
    /// A Match block with its criteria and child directives.
    MatchBlock {
        criteria: String,
        span: Span,
        items: Vec<Item>,
    },
    /// An Include directive with one or more patterns.
    Include { patterns: Vec<String>, span: Span },
}

/// The full parsed config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub items: Vec<Item>,
}

/// Severity level for a lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

/// A single lint finding/diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub span: Span,
    /// Rule name like "duplicate-host".
    pub rule: String,
}

impl Finding {
    pub fn new(
        severity: Severity,
        rule: impl Into<String>,
        code: &'static str,
        message: impl Into<String>,
        span: Span,
    ) -> Self {
        Self {
            severity,
            code,
            message: message.into(),
            hint: None,
            span,
            rule: rule.into(),
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}
