{
  description = "Flake for developing zig-dis-x86_64";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    zig.url = "github:mitchellh/zig-overlay";
    zls.url = "github:zigtools/zls";

    # Used for shell.nix
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }@inputs:
    let
      # Our supported systems are the same supported systems as the Zig binaries
      systems = builtins.attrNames inputs.zig.packages;
    in
    flake-utils.lib.eachSystem systems (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig = inputs.zig.packages.${system}.master;
        zls = inputs.zls.packages.${system}.default.overrideAttrs (old: {
          nativeBuildInputs = [ zig ];
        });
      in
      rec {
        devShells.default = pkgs.mkShell {
          name = "zig-dis-x86_64";
          buildInputs = [
            zig
            zls
          ];
        };

        # For compatibility with older versions of the `nix` binary
        devShell = self.devShells.${system}.default;
      }
    );
}
