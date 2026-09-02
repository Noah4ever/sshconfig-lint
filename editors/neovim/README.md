# sshconfig-lint for Neovim

The CLI includes an LSP server, so Neovim does not need a separate plugin.
Install `sshconfig-lint`, copy [`sshconfig_lint.lua`](sshconfig_lint.lua) to
`~/.config/nvim/lua/sshconfig_lint.lua`, and add this to `init.lua`:

```lua
require("sshconfig_lint").setup()
```

The example recognizes `.ssh/config`, `ssh_config`, and
`dot_ssh/config`. It starts one `sshconfig-lint lsp` process for the current
project and shows diagnostics through Neovim's built-in LSP client.

To use a custom binary:

```lua
require("sshconfig_lint").setup({
  cmd = { "/absolute/path/to/sshconfig-lint", "lsp" },
})
```

The example requires Neovim 0.10 or newer and is exercised by
[`tests/config_spec.lua`](tests/config_spec.lua) in CI.
