class SshconfigLint < Formula
  desc "Linter for OpenSSH client config files"
  homepage "https://github.com/Noah4ever/sshconfig-lint"
  license "MIT"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-arm64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-x86_64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-arm64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-x86_64.tar.gz"
      sha256 "PLACEHOLDER"
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
    assert_match "sshconfig-lint", shell_output("#{bin}/sshconfig-lint --version")
  end
end
