{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils/main";
    nixpkgs.url = "github:nixos/nixpkgs/master";
  };
  outputs = { flake-utils, nixpkgs, ... }: flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.default = pkgs.mkShell {
        packages = [
          pkgs.bazel
        ];
      };
    });
}