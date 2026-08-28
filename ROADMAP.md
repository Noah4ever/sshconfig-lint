# Roadmap

sshconfig-lint is the same semantic rule engine everywhere an OpenSSH client config changes. The roadmap favors predictable diagnostics and safe workflows over automatic rewrites.

## v0.5: Workflow Everywhere

- [x] Multiple config paths and source-aware diagnostics
- [x] JSON, SARIF, and GitHub output contracts
- [x] Language Server Protocol diagnostics
- [x] VS Code extension without telemetry
- [x] GitHub Action and pre-commit hooks
- [x] Verified cross-platform releases
- [ ] Public beta with external dotfiles, homelab, and DevOps users
- [x] VS Code Marketplace publication

## v1.0: Stable Contracts

v1.0 will stabilize the CLI, rule codes, JSON, SARIF, and LSP behavior after at least four weeks of v0.5 feedback. It will focus on reliability, performance, documentation, and compatibility rather than adding a broad fixer.

Release gates:

- no open critical or high-severity defects
- cross-platform CLI, Action, and editor tests passing
- at least ten confirmed external workflow users
- documented support and upgrade policy

## Later candidates

- safe, explicitly scoped editor code actions
- Winget packaging
- additional editors using the same LSP
- Debian and Ubuntu packages with a committed package maintainer

Ideas and real configs are welcome in [GitHub Discussions](https://github.com/Noah4ever/sshconfig-lint/discussions). Security reports belong in the private process described in [SECURITY.md](SECURITY.md).
