use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

fn write_message(writer: &mut impl Write, message: &Value) {
    let body = serde_json::to_vec(message).unwrap();
    write!(writer, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    writer.write_all(&body).unwrap();
    writer.flush().unwrap();
}

fn read_message(reader: &mut impl BufRead) -> Option<Value> {
    let mut content_length = None;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            return None;
        }
        if header == "\r\n" {
            break;
        }
        if let Some(value) = header.strip_prefix("Content-Length:") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    let mut body = vec![0; content_length?];
    reader.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

fn receive_matching(receiver: &mpsc::Receiver<Value>, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let message = receiver
            .recv_timeout(remaining)
            .expect("timed out waiting for LSP message");
        if predicate(&message) {
            return message;
        }
    }
}

#[test]
fn lsp_publishes_and_updates_diagnostics_over_stdio() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sshconfig-lint"))
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        while let Some(message) = read_message(&mut reader) {
            if sender.send(message).is_err() {
                break;
            }
        }
    });

    write_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}}
        }),
    );
    let initialize = receive_matching(&receiver, |message| message["id"] == 1);
    assert_eq!(initialize["result"]["serverInfo"]["name"], "sshconfig-lint");

    write_message(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    );
    write_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "untitled:ssh-config",
                    "languageId": "sshconfig",
                    "version": 1,
                    "text": "Host example\nHost example\n"
                }
            }
        }),
    );
    let opened = receive_matching(&receiver, |message| {
        message["method"] == "textDocument/publishDiagnostics"
    });
    assert!(
        opened["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "DUP_HOST")
    );
    assert!(
        opened["params"]["diagnostics"][0]["codeDescription"]["href"]
            .as_str()
            .is_some()
    );

    write_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": {
                "textDocument": {"uri": "untitled:ssh-config", "version": 2},
                "contentChanges": [{"text": "Host example\n"}]
            }
        }),
    );
    let changed = receive_matching(&receiver, |message| {
        message["method"] == "textDocument/publishDiagnostics"
    });
    assert!(
        changed["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let directory = tempfile::tempdir().unwrap();
    let nested_directory = directory.path().join("nested");
    std::fs::create_dir(&nested_directory).unwrap();
    let deepest = nested_directory.join("deep.conf");
    let missing_certificate = directory
        .path()
        .join("missing-cert.pub")
        .to_string_lossy()
        .replace('\\', "/");
    std::fs::write(
        &deepest,
        format!("Host !internal\n  CertificateFile {missing_certificate}\n"),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("first.conf"),
        "Include nested/deep.conf\n",
    )
    .unwrap();
    let root = directory.path().join("ssh_config");
    let root_uri = tower_lsp::lsp_types::Url::from_file_path(&root)
        .unwrap()
        .to_string();
    let deepest_uri = tower_lsp::lsp_types::Url::from_file_path(deepest.canonicalize().unwrap())
        .unwrap()
        .to_string();

    write_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": root_uri,
                    "languageId": "sshconfig",
                    "version": 1,
                    "text": "Include first.conf\n"
                }
            }
        }),
    );
    let included = receive_matching(&receiver, |message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["uri"] == deepest_uri
    });
    let included_diagnostics = included["params"]["diagnostics"].as_array().unwrap();
    for code in ["NEGATED_HOST", "MISSING_CERTIFICATE"] {
        let diagnostic = included_diagnostics
            .iter()
            .find(|diagnostic| diagnostic["code"] == code)
            .unwrap_or_else(|| panic!("missing {code}: {included_diagnostics:?}"));
        assert!(
            diagnostic["codeDescription"]["href"]
                .as_str()
                .is_some_and(|href| href.contains("/en/rules/"))
        );
    }
    assert_eq!(included_diagnostics[0]["range"]["start"]["line"], 0);

    write_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": root_uri}}
        }),
    );
    let cleared_include = receive_matching(&receiver, |message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["uri"] == deepest_uri
            && message["params"]["diagnostics"] == json!([])
    });
    assert_eq!(cleared_include["params"]["uri"], deepest_uri);

    write_message(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null}),
    );
    receive_matching(&receiver, |message| message["id"] == 2);
    write_message(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "exit", "params": null}),
    );
    drop(stdin);

    let status = child.wait().unwrap();
    assert!(status.success());
    reader_thread.join().unwrap();
}
