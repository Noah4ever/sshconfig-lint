class SshconfigLint < Formula
  desc "Linter for OpenSSH client config files"
  homepage "https://github.com/Noah4ever/sshconfig-lint"
  license "MIT"
  version "0.4.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-arm64.tar.gz"
      sha256 "e2929c229d2c41ef2d6a87422d9ad3be01b325190fd172257671c8f30f6304ac"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-x86_64.tar.gz"
      sha256 "8abe32bcdf7414292acbaa020d0ebbbffd80f770b77f2106cd6fbec78897edb6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-arm64.tar.gz"
      sha256 "ca90a819fd065c8b58056759f0279444bb2716336d0cbbf8610e868e76cad3b6"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-x86_64.tar.gz"
      sha256 "bb4365acf2d9b814d7075f0160126895c480dfee0c1a618e826b1875317fb53a"
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
