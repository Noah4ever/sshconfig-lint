use clap::Parser;
use std::path::PathBuf;
use std::process;

use sshconfig_lint::{has_errors, lint_file, report};

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

    let findings = match lint_file(&config_path) {
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

    if has_errors(&findings[..]) {
        process::exit(1);
    }
}
