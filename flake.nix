{
  description = "kobe - CLI for the cluster-pool operator: instant CI/dev Kubernetes clusters";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }: let
    kobeOverlay = final: _prev: let
      # Pin the toolchain that CI builds with (kobe has no rust-toolchain.toml;
      # the dev toolchain is managed by mise). Bump alongside the CI image.
      rustToolchain = final.rust-bin.stable."1.95.0".default;
      rustPlatform = final.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };
    in {
      kobe = final.callPackage ./nix/package.nix {
        inherit rustPlatform;
      };
    };
  in
    {
      overlays = {
        kobe = kobeOverlay;
        default = nixpkgs.lib.composeManyExtensions [
          rust-overlay.overlays.default
          kobeOverlay
        ];
      };
    }
    // flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [self.overlays.default];
      };
    in {
      packages = {
        kobe = pkgs.kobe;
        default = pkgs.kobe;
      };
    });
}
