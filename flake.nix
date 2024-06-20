# This is a simple deterministic rust development environment
# This exposes Cargo, rustfmt, rust-analyzer and clippy
# This does not allow you to build binaries using nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:

    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Pick what rust compiler to use
        rustVersion = pkgs.rust-bin.stable.latest.default;
      in {
        devShell = pkgs.mkShell {

          # More agressively cache build artefacts
          # Uses more disk but speeds up compile times significantly
          env = {
            PROJECT_ROOT = builtins.getEnv "PWD";
            OUT_DIR = "{PROJECT_ROOT}/chain-signatures/target";
          };

          # Everything in this list is added to your path
          buildInputs = with pkgs;
            [
              # Native build dependencies
              protobuf
              curl
              gmp
              openssl

              # Development
              # A nice LSP IDE backend
              rust-analyzer

              # Adds cargo, rustc and rustfmt
              (rustVersion.override {

                # We need this for rust analyzer to jump to library code
                extensions = [ "rust-src" "clippy" "rustfmt" ];

                # Add foreign compile targets here
                targets = [
                  "wasm32-unknown-unknown"
                  "x86_64-apple-darwin"
                  "wasm32-wasi"
                ];
              })
              cargo-watch
              cargo-audit
              cargo-make

              # For David's scripts
              haskellPackages.cabal-fmt
              haskellPackages.cabal-install
              haskellPackages.haskell-language-server
              haskellPackages.hlint
              ghc

              clang

              # TODO Add podman + docker image dependencies
              # TODO Add AWS-CLI and dummy credentials
            ] ++

            pkgs.lib.optionals pkgs.stdenv.isDarwin [
              # Mac crypto libs
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.SystemConfiguration
            ];
        };
      });
}
