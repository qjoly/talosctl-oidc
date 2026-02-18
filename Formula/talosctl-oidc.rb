class TalosctlOidc < Formula
  desc "OIDC certificate exchange server and client for Talos Linux"
  homepage "https://github.com/qjoly/talosctl-oidc"
  url "https://github.com/qjoly/talosctl-oidc/archive/refs/tags/v0.0.1.tar.gz"
  sha256 "14902b31f6d892c066b46402b3c044c577f19d585e810a193551962327209920"
  license "MIT"
  head "https://github.com/qjoly/talosctl-oidc.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    system "#{bin}/talosctl-oidc", "--help"
  end
end
