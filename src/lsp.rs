use std::collections::{HashMap, HashSet};

use tokio::sync::Mutex;
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
    published_uris: Mutex<HashMap<Url, HashSet<Url>>>,
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

fn needs_filesystem_context(source: &str) -> bool {
    crate::lexer::lex(source).into_iter().any(|line| {
        let crate::model::LineKind::Directive { key: keyword, .. } = line.kind else {
            return false;
        };
        [
            "include",
            "identityfile",
            "certificatefile",
            "revokedhostkeys",
        ]
        .iter()
        .any(|candidate| keyword.eq_ignore_ascii_case(candidate))
    })
}

fn editor_filesystem_limit(source: &str) -> Diagnostic {
    Diagnostic {
        range: Range::new(
            Position::new(0, 0),
            Position::new(0, line_end_utf16(source, 1)),
        ),
        severity: Some(DiagnosticSeverity::INFORMATION),
        code: Some(NumberOrString::String("EDITOR_FS_LIMIT".to_string())),
        code_description: Url::parse("https://sshconfig-lint.apps.thiering.org/en/editor")
            .ok()
            .map(|href| CodeDescription { href }),
        source: Some("sshconfig-lint".to_string()),
        message: "Save this document to enable Include resolution and filesystem-dependent checks for IdentityFile, CertificateFile, and RevokedHostKeys paths."
            .to_string(),
        ..Diagnostic::default()
    }
}

fn diagnostics_by_uri(source: &str, uri: &Url) -> HashMap<Url, Vec<Diagnostic>> {
    let path = uri.to_file_path().ok();
    let findings = path
        .as_deref()
        .map(|path| lint_str_at_path(source, path, true))
        .unwrap_or_else(|| lint_str_portable(source));

    let mut diagnostics = HashMap::<Url, Vec<Diagnostic>>::new();
    diagnostics.entry(uri.clone()).or_default();

    for finding in findings {
        let target_uri = finding
            .span
            .file
            .as_deref()
            .and_then(|file| Url::from_file_path(file).ok())
            .unwrap_or_else(|| uri.clone());
        let target_source = if target_uri == *uri {
            source.to_string()
        } else {
            target_uri
                .to_file_path()
                .ok()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .unwrap_or_default()
        };
        diagnostics
            .entry(target_uri)
            .or_default()
            .push(finding_to_diagnostic(&target_source, finding));
    }

    if path.is_none() && needs_filesystem_context(source) {
        diagnostics
            .entry(uri.clone())
            .or_default()
            .push(editor_filesystem_limit(source));
    }

    diagnostics
}

#[cfg(test)]
fn diagnostics(source: &str, uri: &Url) -> Vec<Diagnostic> {
    diagnostics_by_uri(source, uri)
        .remove(uri)
        .unwrap_or_default()
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
        let diagnostics = diagnostics_by_uri(&text, &uri);
        let current_uris = diagnostics.keys().cloned().collect::<HashSet<_>>();
        let stale_uris = {
            let mut published = self.published_uris.lock().await;
            let previous = published
                .insert(uri.clone(), current_uris.clone())
                .unwrap_or_default();
            previous
                .difference(&current_uris)
                .cloned()
                .collect::<Vec<_>>()
        };

        for stale_uri in stale_uris {
            self.client
                .publish_diagnostics(stale_uri, Vec::new(), None)
                .await;
        }

        let mut documents = diagnostics.into_iter().collect::<Vec<_>>();
        documents.sort_by(|(left, _), (right, _)| {
            let left_is_root = left == &uri;
            let right_is_root = right == &uri;
            right_is_root
                .cmp(&left_is_root)
                .then(left.as_str().cmp(right.as_str()))
        });
        for (document_uri, document_diagnostics) in documents {
            let document_version = (document_uri == uri).then_some(version).flatten();
            self.client
                .publish_diagnostics(document_uri, document_diagnostics, document_version)
                .await;
        }
    }

    async fn clear(&self, uri: Url) {
        let published_uris = self
            .published_uris
            .lock()
            .await
            .remove(&uri)
            .unwrap_or_else(|| HashSet::from([uri.clone()]));
        for published_uri in published_uris {
            self.client
                .publish_diagnostics(published_uri, Vec::new(), None)
                .await;
        }
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
        self.clear(params.text_document.uri).await;
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
        let (service, socket) = LspService::new(|client| Backend {
            client,
            published_uris: Mutex::new(HashMap::new()),
        });
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
    fn every_untitled_filesystem_directive_explains_the_editor_limit() {
        for source in [
            "CertificateFile /definitely/missing\n",
            "RevokedHostKeys /definitely/missing\n",
        ] {
            let uri = Url::parse("untitled:ssh-config").unwrap();
            let diagnostics = diagnostics(source, &uri);
            assert_eq!(diagnostics.len(), 1, "{source}: {diagnostics:?}");
            assert_eq!(
                diagnostics[0].code,
                Some(NumberOrString::String("EDITOR_FS_LIMIT".to_string()))
            );
        }
    }

    #[test]
    fn equals_form_in_untitled_buffers_explains_the_editor_limit() {
        for source in [
            "Include=extra.conf\n",
            "IdentityFile=/missing/key\n",
            "CertificateFile=/missing/cert\n",
            "RevokedHostKeys=/missing/revoked\n",
        ] {
            let uri = Url::parse("untitled:ssh-config").unwrap();
            let diagnostics = diagnostics(source, &uri);
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == Some(NumberOrString::String("EDITOR_FS_LIMIT".to_string()))
                }),
                "{source}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn diagnostic_end_columns_use_utf16_code_units() {
        let source = "Host 😀\nHost 😀\n";
        let uri = Url::parse("untitled:ssh-config").unwrap();
        let duplicate = diagnostics(source, &uri)
            .into_iter()
            .find(|diagnostic| {
                diagnostic.code == Some(NumberOrString::String("DUP_HOST".to_string()))
            })
            .unwrap();
        assert_eq!(duplicate.range.end.character, 7);
    }

    #[test]
    fn saved_buffers_run_every_filesystem_rule() {
        let directory = tempfile::tempdir().unwrap();
        let uri = Url::from_file_path(directory.path().join("ssh_config")).unwrap();
        let source = format!(
            "IdentityFile {}\nCertificateFile {}\nRevokedHostKeys {}\n",
            directory.path().join("missing-key").display(),
            directory.path().join("missing-cert").display(),
            directory.path().join("missing-revoked").display(),
        );
        let diagnostics = diagnostics(&source, &uri);
        for code in [
            "MISSING_IDENTITY",
            "MISSING_CERTIFICATE",
            "REVOKED_HOST_KEYS_UNREADABLE",
        ] {
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == Some(NumberOrString::String(code.to_string()))
                }),
                "missing {code}: {diagnostics:?}"
            );
        }
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

    #[test]
    fn nested_include_diagnostics_keep_the_included_file_uri() {
        let directory = tempfile::tempdir().unwrap();
        let nested_directory = directory.path().join("nested");
        std::fs::create_dir(&nested_directory).unwrap();
        let deepest = nested_directory.join("deep.conf");
        std::fs::write(&deepest, "Host !internal\n").unwrap();
        std::fs::write(
            directory.path().join("first.conf"),
            "Include nested/deep.conf\n",
        )
        .unwrap();
        let root = directory.path().join("ssh_config");
        let root_uri = Url::from_file_path(root).unwrap();
        let deepest_uri = Url::from_file_path(deepest.canonicalize().unwrap()).unwrap();

        let by_uri = diagnostics_by_uri("Include first.conf\n", &root_uri);
        assert!(
            by_uri.get(&deepest_uri).is_some_and(|diagnostics| {
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == Some(NumberOrString::String("NEGATED_HOST".to_string()))
                })
            }),
            "nested diagnostics were published for: {:?}",
            by_uri.keys().collect::<Vec<_>>()
        );
    }
}
