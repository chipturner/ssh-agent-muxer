# This formula is overwritten by .github/workflows/release.yml on each tagged release.
# This in-repo copy is just a placeholder so the path exists; the canonical formula
# lives in the homebrew-tap repo and is regenerated from the release workflow.
class SshAgentMux < Formula
  desc "SSH agent multiplexer and diagnostic tool for Linux"
  homepage "https://github.com/chipturner/ssh-agent-fixer"
  version "0.0.0"
  license "MIT"

  # Linux-only: depends on /proc/*/environ, inotify, and SO_PEERCRED.
  depends_on :linux

  on_linux do
    on_arm do
      url "https://github.com/chipturner/ssh-agent-fixer/releases/download/v#{version}/ssh-agent-mux-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/chipturner/ssh-agent-fixer/releases/download/v#{version}/ssh-agent-mux-x86_64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "ssh-agent-mux", "ssh-agent-probe"
  end

  test do
    system bin/"ssh-agent-mux", "--help"
    system bin/"ssh-agent-probe", "--help"
  end
end
