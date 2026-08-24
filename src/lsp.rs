use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    CodeDescription, Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    InitializeParams, InitializeResult, InitializedParams, MessageType, NumberOrString, Position,
    Range, SaveOptions, ServerCapabilities, ServerInfo, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextDocumentSyncOptions, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::model::{Finding, Severity};
use crate::{lint_str_at_path, lint_str_portable};

#[derive(Debug)]
struct Backend {
    client: Client,
}

fn severity(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Info => DiagnosticSeverity::INFORMATION,
    }
}

fn line_end_utf16(source: &str, one_based_line: usize) -> u32 {
    source
        .lines()
        .nth(one_based_line.saturating_sub(1))
        .map(|line| line.encode_utf16().count() as u32)
        .unwrap_or_default()
}

fn diagnostics(source: &str, uri: &Url) -> Vec<Diagnostic> {
    let path = uri.to_file_path().ok();
    let findings = path
        .as_deref()
        .map(|path| lint_str_at_path(source, path, true))
        .unwrap_or_else(|| lint_str_portable(source));

    let mut diagnostics: Vec<_> = findings
        .into_iter()
        .map(|finding| finding_to_diagnostic(source, finding))
        .collect();

    if path.is_none()
        && source.lines().any(|line| {
            let keyword = line.split_whitespace().next().unwrap_or_default();
            keyword.eq_ignore_ascii_case("include") || keyword.eq_ignore_ascii_case("identityfile")
        })
    {
        diagnostics.push(Diagnostic {
            range: Range::new(Position::new(0, 0), Position::new(0, line_end_utf16(source, 1))),
            severity: Some(DiagnosticSeverity::INFORMATION),
            code: Some(NumberOrString::String("EDITOR_FS_LIMIT".to_string())),
            code_description: Url::parse(
                "https://sshconfig-lint.apps.thiering.org/en/editor",
            )
            .ok()
            .map(|href| CodeDescription { href }),
            source: Some("sshconfig-lint".to_string()),
            message: "Save this document to enable Include resolution and filesystem-dependent checks such as IdentityFile existence.".to_string(),
            ..Diagnostic::default()
        });
    }

    diagnostics
}

fn finding_to_diagnostic(source: &str, finding: Finding) -> Diagnostic {
    let line = finding.span.line.saturating_sub(1) as u32;
    let documentation = Url::parse(&finding.documentation_url()).ok();
    let message = match finding.hint {
        Some(hint) => format!("{}\nHint: {}", finding.message, hint),
        None => finding.message,
    };

    Diagnostic {
        range: Range::new(
            Position::new(line, 0),
            Position::new(line, line_end_utf16(source, finding.span.line)),
        ),
        severity: Some(severity(finding.severity)),
        code: Some(NumberOrString::String(finding.code.to_string())),
        code_description: documentation.map(|href| CodeDescription { href }),
        source: Some("sshconfig-lint".to_string()),
        message,
        ..Diagnostic::default()
    }
}

impl Backend {
    async fn publish(&self, uri: Url, text: String, version: Option<i32>) {
        self.client
            .publish_diagnostics(uri.clone(), diagnostics(&text, &uri), version)
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(
                            SaveOptions {
                                include_text: Some(true),
                            }
                            .into(),
                        ),
                        ..TextDocumentSyncOptions::default()
                    },
                )),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "sshconfig-lint".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "sshconfig-lint language server ready")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.publish(
            params.text_document.uri,
            params.text_document.text,
            Some(params.text_document.version),
        )
        .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().last() {
            self.publish(
                params.text_document.uri,
                change.text,
                Some(params.text_document.version),
            )
            .await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let text = match params.text {
            Some(text) => Some(text),
            None => params
                .text_document
                .uri
                .to_file_path()
                .ok()
                .and_then(|path| std::fs::read_to_string(path).ok()),
        };
        if let Some(text) = text {
            self.publish(params.text_document.uri, text, None).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.client
            .publish_diagnostics(params.text_document.uri, Vec::new(), None)
            .await;
    }
}

/// Start the language server on stdin/stdout.
pub fn run() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("cannot start language server runtime");

    runtime.block_on(async {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let (service, socket) = LspService::new(|client| Backend { client });
        Server::new(stdin, stdout, socket).serve(service).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_use_full_line_and_documentation() {
        let source = "Host example\nHost example\n";
        let uri = Url::parse("untitled:ssh-config").unwrap();
        let diagnostics = diagnostics(source, &uri);
        let duplicate = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == Some(NumberOrString::String("DUP_HOST".to_string()))
            })
            .expect("duplicate host diagnostic");

        assert_eq!(duplicate.range.start, Position::new(1, 0));
        assert_eq!(duplicate.range.end, Position::new(1, 12));
        assert!(duplicate.code_description.is_some());
    }

    #[test]
    fn untitled_buffers_skip_filesystem_rules() {
        let source = "Host example\n  IdentityFile /definitely/missing\n";
        let uri = Url::parse("untitled:ssh-config").unwrap();
        let diagnostics = diagnostics(source, &uri);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            Some(NumberOrString::String("EDITOR_FS_LIMIT".to_string()))
        );
    }

    #[test]
    fn file_buffers_keep_their_source_path() {
        let source = "Host example\nHost example\n";
        let directory = tempfile::tempdir().unwrap();
        let uri = Url::from_file_path(directory.path().join("ssh_config")).unwrap();
        let diagnostics = diagnostics(source, &uri);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == Some(NumberOrString::String("DUP_HOST".to_string()))
        }));
    }

    #[test]
    fn saved_buffers_resolve_include_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("included.conf"),
            "Host example\n  User included\n",
        )
        .unwrap();
        let root = directory.path().join("ssh_config");
        let source = "Include included.conf\nHost example\n  User root\n";
        let uri = Url::from_file_path(root).unwrap();

        assert!(diagnostics(source, &uri).iter().any(|diagnostic| {
            diagnostic.code == Some(NumberOrString::String("DUP_HOST".to_string()))
        }));
    }
}
