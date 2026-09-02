use std::fs;
use std::path::{Path, PathBuf};

const RULE_GUIDES: &[(&str, &str)] = &[
    ("INVALID_VALUE", "invalid-directive-value"),
    ("DUP_HOST", "duplicate-host"),
    ("MISSING_IDENTITY", "identity-file-exists"),
    ("WILDCARD_ORDER", "wildcard-host-order"),
    ("WEAK_ALGO", "deprecated-weak-algorithms"),
    ("DUP_DIRECTIVE", "duplicate-directives"),
    ("INSECURE_OPT", "insecure-option"),
    ("UNSAFE_CTRL_PATH", "unsafe-control-path"),
    ("INCLUDE_CYCLE", "include-cycle"),
    ("INCLUDE_DEPTH", "include-depth"),
    ("INCLUDE_READ", "include-read"),
    ("INCLUDE_GLOB", "include-glob"),
    ("INCLUDE_NO_MATCH", "include-no-match"),
    ("NEGATED_HOST", "negated-only-host"),
    ("PROXY_CONFLICT", "proxy-command-jump-conflict"),
    ("REVOKED_HOST_KEYS_UNREADABLE", "revoked-host-keys-readable"),
    ("MISSING_CERTIFICATE", "certificate-file-exists"),
    ("LOCAL_COMMAND_DISABLED", "local-command-enabled"),
    ("INVALID_TOKEN", "invalid-percent-token"),
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("documentation file should be readable")
}

#[test]
fn readme_and_vscode_offer_every_public_rule_guide() {
    let root = repository_root();
    let readme = read(root.join("README.md"));
    let vscode_rules = read(root.join("editors/vscode/src/rules.ts"));

    for (code, slug) in RULE_GUIDES {
        assert!(
            readme.contains(&format!("`{code}`")),
            "README misses {code}"
        );
        assert!(
            readme.contains(&format!("/en/rules/{slug}")),
            "README misses the {code} guide URL"
        );
        assert!(
            vscode_rules.contains(&format!("['{code}', '{slug}']")),
            "VS Code misses the {code} guide"
        );
    }
}

#[test]
fn integration_examples_use_the_same_public_release() {
    let root = repository_root();
    let readme = read(root.join("README.md"));
    let action = read(root.join("action.yml"));
    let extension_package = read(root.join("editors/vscode/package.json"));

    assert!(readme.contains("uses: Noah4ever/sshconfig-lint@v0.5.0"));
    assert!(readme.contains("rev: v0.5.0"));
    assert!(action.contains("'v0.5.0'"));
    assert!(extension_package.contains("\"cliVersion\": \"0.5.0\""));
}

#[test]
fn editor_documentation_covers_vscode_and_neovim() {
    let root = repository_root();
    let readme = read(root.join("README.md"));
    let vscode = read(root.join("editors/vscode/README.md"));
    let neovim = read(root.join("editors/neovim/README.md"));

    assert!(readme.contains("editors/vscode"));
    assert!(readme.contains("editors/neovim"));
    assert!(vscode.contains("sshconfigLint.binaryPath"));
    assert!(vscode.contains("reused offline"));
    assert!(neovim.contains("sshconfig-lint lsp"));
    assert!(neovim.contains("require(\"sshconfig_lint\").setup()"));
}

#[test]
fn sibling_playground_is_in_sync_when_available() {
    let root = repository_root();
    let Some(parent) = root.parent() else {
        return;
    };
    let website = parent.join("sshconfig-lint-website");
    if !website.is_dir() {
        return;
    }

    let website_rules = read(website.join("lib/rules.ts"));
    let ci_page = read(website.join("app/[locale]/ci/page.tsx"));
    for (code, slug) in RULE_GUIDES {
        assert!(
            website_rules.contains(&format!("slug: '{slug}', code: '{code}'")),
            "playground misses the {code} guide"
        );
    }
    assert!(ci_page.contains("uses: Noah4ever/sshconfig-lint@v0.5.0"));
    assert!(ci_page.contains("rev: v0.5.0"));
}
