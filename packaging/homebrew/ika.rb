class Ika < Formula
  desc "Ika Network CLI - Decentralized MPC signing network on Sui"
  homepage "https://ika.xyz"
  version "1.1.8"
  license "BSD-3-Clause-Clear"

  on_macos do
    on_arm do
      url "https://github.com/AftermathFinance/ika/releases/download/v#{version}/ika-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    end

    on_intel do
      url "https://github.com/AftermathFinance/ika/releases/download/v#{version}/ika-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X86_64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/AftermathFinance/ika/releases/download/v#{version}/ika-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    end

    on_intel do
      url "https://github.com/AftermathFinance/ika/releases/download/v#{version}/ika-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X86_64"
    end
  end

  def install
    bin.install "ika"
  end

  def caveats
    <<~EOS
      Ika CLI requires the Sui CLI for key management and on-chain operations.

      Install Sui CLI:
        cargo install --locked --git https://github.com/MystenLabs/sui.git sui

      Or via Homebrew (if a tap is available):
        brew install sui
    EOS
  end

  test do
    assert_match "ika", shell_output("#{bin}/ika --version")
  end
end
