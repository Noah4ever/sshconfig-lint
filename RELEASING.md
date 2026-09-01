# Releasing sshconfig-lint

Intermediate development is pushed to `main` and may be marked with
`checkpoint/...` tags. These tags do not trigger `.github/workflows/release.yml`.
Only a final version tag such as `v1.0.0` creates a public GitHub release.

## One-time macOS setup

Required tools are available through Homebrew:

```sh
brew install git gh rustup-init node
gh auth login
gh auth setup-git
cargo login
```

`cargo login` stores the crates.io token using Cargo's configured credential
provider. Do not commit registry, AUR, GitHub, or Marketplace credentials.

The AUR stage uses the SSH key already registered with the AUR account. Verify
it once before release:

```sh
ssh -T aur@aur.archlinux.org
```

The VS Code Marketplace remains a manual browser upload because this project
does not store a `VSCE_PAT`. The release script downloads the finished VSIX and
prints the publisher-management URL.

Publishing the GitHub Action in Marketplace is also a one-time manual release
page step. Select "Publish this Action to the GitHub Marketplace" on the final
GitHub release after accepting the Marketplace agreement.

## Optional development checkpoint

After a completed, committed, and fully tested checkpoint:

```sh
scripts/checkpoint.sh 01-value-foundation
```

This runs the full local checks, pushes the current branch, and creates the
annotated tag `checkpoint/01-value-foundation`. It does not publish packages or
start the release workflow.

## Final release

Update the `Unreleased` changelog section and verify every v1.0 release gate in
`ROADMAP.md`. Then run:

```sh
scripts/release.sh 1.0.0
```

The command performs the preflight, synchronizes Cargo and extension versions,
creates and pushes `v1.0.0`, waits for GitHub's cross-platform assets, publishes
the crate, updates AUR and Homebrew, and either publishes the extension with
`VSCE_PAT` or downloads the VSIX for manual upload.

Rehearse the macOS path against an existing release without publishing:

```sh
DRY_RUN=1 scripts/release.sh 0.5.0
```

Individual stages can be retried without repeating successful stages:

```sh
scripts/release.sh 1.0.0 --only wait
scripts/release.sh 1.0.0 --only crates
scripts/release.sh 1.0.0 --only aur
scripts/release.sh 1.0.0 --only homebrew
scripts/release.sh 1.0.0 --only vscode
```

Publishing to crates.io is permanent. The tag, crate, AUR package, Homebrew
formula, VS Code extension, changelog, and GitHub release must all describe the
same version.
