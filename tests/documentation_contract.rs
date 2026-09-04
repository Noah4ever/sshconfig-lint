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
    ("UNKNOWN_DIRECTIVE", "unknown-directive"),
    ("DEPRECATED_OPTION", "deprecated-option"),
    ("CONTROL_PERSIST_UNUSED", "control-persist-requires-master"),
    (
        "UPDATE_HOSTKEYS_ASK_PERSIST",
        "update-hostkeys-control-persist",
    ),
    ("INVALID_SYNTAX", "invalid-syntax"),
    ("INVALID_MATCH", "invalid-match-condition"),
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("documentation file should be readable")
}

#[test]
fn contributing_uses_the_one_file_per_rule_layout() {
    let contributing = read(repository_root().join("CONTRIBUTING.md"));

    assert!(contributing.contains("src/rules/implementations/my_rule.rs"));
    assert!(contributing.contains("src/rules/implementations/mod.rs"));
    assert!(contributing.contains("src/rules/implementations/tests.rs"));
    assert!(contributing.contains("run_portable()"));
    assert!(!contributing.contains("Implement the `Rule` trait in `src/rules/basic.rs`"));
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
    let version = env!("CARGO_PKG_VERSION");
    let tag = format!("v{version}");

    assert!(readme.contains(&format!("uses: Noah4ever/sshconfig-lint@{tag}")));
    assert!(readme.contains(&format!("rev: {tag}")));
    assert!(action.contains(&format!("'{tag}'")));
    assert!(extension_package.contains(&format!("\"cliVersion\": \"{version}\"")));
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
    assert!(ci_page.contains("uses: Noah4ever/sshconfig-lint@v"));
    assert!(ci_page.contains("rev: v"));
}
