class SshconfigLint < Formula
  desc "Linter for OpenSSH client config files"
  homepage "https://github.com/Noah4ever/sshconfig-lint"
  license "MIT"
  version "0.5.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-arm64.tar.gz"
      sha256 "a35c8d6b93d9726f1f8cda918a4150324acf42380248d47478416380ceb7cf5f"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-macos-x86_64.tar.gz"
      sha256 "1e50a4089d9e25d0cc22dae43b86e40780fa1be22a6fc25e10ca4b76ff9f3323"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-arm64.tar.gz"
      sha256 "bbde019535b472b64ed24bf98832aded72b4a88f76553a6f86efd98355744dca"
    else
      url "https://github.com/Noah4ever/sshconfig-lint/releases/download/v#{version}/sshconfig-lint-linux-x86_64.tar.gz"
      sha256 "042501f8c26271b78b2bf45593f829f36e54d3a272865f191473aa95e4abd186"
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
