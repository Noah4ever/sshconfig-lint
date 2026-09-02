local M = {}

local defaults = {
  cmd = { "sshconfig-lint", "lsp" },
}

local function root_for(file)
  if vim.fs and vim.fs.root then
    return vim.fs.root(file, ".git") or vim.fs.dirname(file)
  end
  return nil
end

function M.setup(options)
  local config = options or {}
  local command = config.cmd or defaults.cmd

  vim.filetype.add({
    pattern = {
      [".*/%.ssh/config"] = "sshconfig",
      [".*/ssh_config"] = "sshconfig",
      [".*/dot_ssh/config"] = "sshconfig",
    },
  })

  local group = vim.api.nvim_create_augroup("sshconfig_lint", { clear = true })
  vim.api.nvim_create_autocmd("FileType", {
    group = group,
    pattern = "sshconfig",
    callback = function(args)
      vim.lsp.start({
        name = "sshconfig-lint",
        cmd = command,
        root_dir = root_for(args.file),
      }, { bufnr = args.buf })
    end,
  })
end

return M
