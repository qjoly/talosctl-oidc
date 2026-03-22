{
  description = "OIDC certificate exchange server and client for Talos Linux";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          version = "0.0.3";
        in
        {
          talosctl-oidc = pkgs.buildGoModule {
            pname = "talosctl-oidc";
            inherit version;

            src = self;

            vendorHash = "sha256-hpQ+Bvppu+8x8+Fd/y6A47E4zgBNx/ZK74Z7ZI/aW8o=";

            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
              "-X main.commit=${self.rev or self.dirtyRev or "unknown"}"
            ];

            preBuild = ''
              buildFlagsArray+=(
                -ldflags="-X main.date=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                                      || date -u -r  "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
              )
            '';

            meta = with pkgs.lib; {
              description = "OIDC certificate exchange server and client for Talos Linux";
              homepage = "https://github.com/qjoly/talosctl-oidc";
              license = licenses.mit;
              mainProgram = "talosctl-oidc";
              platforms = platforms.linux ++ platforms.darwin;
            };
          };

          default = self.packages.${system}.talosctl-oidc;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              go
              gopls
              gotools
            ];
          };
        }
      );
    };
}
