class SshconfigLint < Formula
  desc "Linter for OpenSSH client config files"
  homepage "https://github.com/Noah4ever/sshconfig-lint"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-arm64.tar.gz"
      sha256 "1769c6ae9befec7ddf7173637e44102a744f7a9d98bdbac3a68ebd2dd64a4950"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-x86_64.tar.gz"
      sha256 "16f6bac929072f75215e00e55e319f41bd25d705543c2ddbbbb04b49ea44e8de"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-arm64.tar.gz"
      sha256 "08db3193fae246216d8cad0c88cff0faeefaa5a8987e227d0441fbefce82bb1e"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-x86_64.tar.gz"
      sha256 "d4f39629ad57382807cabb768cbae9bc37939e3dc23e2f218934d28e4e9dcdd3"
    end
  end

  def install
    if OS.mac?
      if Hardware::CPU.arm?
        bin.install "sshconfig-lint-macos-arm64" => "sshconfig-lint"
      else
        bin.install "sshconfig-lint-macos-x86_64" => "sshconfig-lint"
      end
    else
      if Hardware::CPU.arm?
        bin.install "sshconfig-lint-linux-arm64" => "sshconfig-lint"
      else
        bin.install "sshconfig-lint-linux-x86_64" => "sshconfig-lint"
      end
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sshconfig-lint --version")
  end
end
