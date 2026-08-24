use clap::{Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process;

use sshconfig_lint::{has_errors, has_warnings, lint_file, lint_file_no_includes, report};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
    Github,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the Language Server Protocol server over stdio
    Lsp,
}

#[derive(Parser, Debug)]
#[command(
    name = "sshconfig-lint",
    version,
    about = "Lint OpenSSH client configs wherever they change"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Paths to SSH config files (default: ~/.ssh/config)
    #[arg(value_name = "PATH", conflicts_with = "config")]
    paths: Vec<PathBuf>,

    /// Path to an SSH config file (backwards-compatible alias)
    #[arg(short, long, conflicts_with = "paths")]
    config: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "text")]
    format: OutputFormat,

    /// Treat warnings as errors (useful in CI)
    #[arg(long)]
    strict: bool,

    /// Skip Include directive resolution
    #[arg(long)]
    no_includes: bool,
}

fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .expect("cannot determine home directory")
        .join(".ssh")
        .join("config")
}

fn main() {
    let args = Args::parse();

    if matches!(args.command, Some(Command::Lsp)) {
        sshconfig_lint::lsp::run();
        return;
    }

    let paths = if let Some(config) = args.config {
        vec![config]
    } else if args.paths.is_empty() {
        vec![default_config_path()]
    } else {
        args.paths
    };

    let mut findings = Vec::new();
    let mut unreadable = false;

    for path in &paths {
        if !path.exists() {
            eprintln!("error: config file not found: {}", path.display());
            unreadable = true;
            continue;
        }

        let result = if args.no_includes {
            lint_file_no_includes(path)
        } else {
            lint_file(path)
        };

        match result {
            Ok(mut path_findings) => findings.append(&mut path_findings),
            Err(error) => {
                eprintln!("error: cannot read {}: {}", path.display(), error);
                unreadable = true;
            }
        }
    }

    findings.sort_by(|a, b| {
        a.span
            .file
            .cmp(&b.span.file)
            .then(a.span.line.cmp(&b.span.line))
            .then(a.code.cmp(b.code))
    });

    let colored = matches!(args.format, OutputFormat::Text)
        && std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none();

    let output = match args.format {
        OutputFormat::Text => report::emit_text(&findings, colored),
        OutputFormat::Json => report::emit_json(&findings),
        OutputFormat::Sarif => report::emit_sarif(&findings),
        OutputFormat::Github => report::emit_github(&findings),
    };
    if !output.is_empty() {
        println!("{}", output.trim_end());
    }

    if unreadable {
        process::exit(2);
    }

    let should_fail = if args.strict {
        has_warnings(&findings)
    } else {
        has_errors(&findings)
    };

    if should_fail {
        process::exit(1);
    }
}
