use clap::Parser;
use std::path::PathBuf;
use std::process;

use sshconfig_lint::{has_errors, has_warnings, lint_file, lint_file_no_includes, report};

#[derive(Parser, Debug)]
#[command(
    name = "sshconfig-lint",
    version,
    about = "Lint OpenSSH client config (~/.ssh/config)"
)]
struct Args {
    /// Path to ssh config file (default: ~/.ssh/config)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    format: String,

    /// Treat warnings as errors (useful in CI)
    #[arg(long)]
    strict: bool,

    /// Skip Include directive resolution
    #[arg(long)]
    no_includes: bool,
}

fn main() {
    let args = Args::parse();

    let config_path = args.config.unwrap_or_else(|| {
        let home = dirs::home_dir().expect("cannot determine home directory");
        home.join(".ssh").join("config")
    });

    if !config_path.exists() {
        eprintln!("error: config file not found: {}", config_path.display());
        process::exit(2);
    }

    let findings = if args.no_includes {
        lint_file_no_includes(&config_path)
    } else {
        lint_file(&config_path)
    };

    let findings = match findings {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", config_path.display(), e);
            process::exit(2);
        }
    };

    let output = match args.format.as_str() {
        "json" => report::emit_json(&findings[..]),
        _ => report::emit_text(&findings[..]),
    };
    print!("{}", output);

    let should_fail = if args.strict {
        has_warnings(&findings[..])
    } else {
        has_errors(&findings[..])
    };

    if should_fail {
        process::exit(1);
    }
}
