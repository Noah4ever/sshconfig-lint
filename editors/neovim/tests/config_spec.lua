local captured = {
  filetypes = nil,
  autocmd = nil,
  lsp = nil,
}

vim = {
  api = {
    nvim_create_augroup = function(name, options)
      assert(name == "sshconfig_lint")
      assert(options.clear == true)
      return 42
    end,
    nvim_create_autocmd = function(event, options)
      captured.autocmd = { event = event, options = options }
    end,
  },
  filetype = {
    add = function(spec)
      captured.filetypes = spec
    end,
  },
  fs = {
    root = function(file, marker)
      assert(file == "/repo/.ssh/config")
      assert(marker == ".git")
      return "/repo"
    end,
    dirname = function()
      error("dirname fallback should not be used")
    end,
  },
  lsp = {
    start = function(config, options)
      captured.lsp = { config = config, options = options }
    end,
  },
}

local module_path = arg[1] or "editors/neovim/sshconfig_lint.lua"
local setup = dofile(module_path)

assert(type(setup.setup) == "function")
setup.setup({ cmd = { "/custom/sshconfig-lint", "lsp" } })

assert(captured.filetypes.pattern[".*/%.ssh/config"] == "sshconfig")
assert(captured.filetypes.pattern[".*/ssh_config"] == "sshconfig")
assert(captured.filetypes.pattern[".*/dot_ssh/config"] == "sshconfig")
assert(captured.autocmd.event == "FileType")
assert(captured.autocmd.options.pattern == "sshconfig")

captured.autocmd.options.callback({ buf = 7, file = "/repo/.ssh/config" })
assert(captured.lsp.config.name == "sshconfig-lint")
assert(captured.lsp.config.cmd[1] == "/custom/sshconfig-lint")
assert(captured.lsp.config.cmd[2] == "lsp")
assert(captured.lsp.config.root_dir == "/repo")
assert(captured.lsp.options.bufnr == 7)

print("Neovim LSP example passed")
