{
  description = "Herdr Authorization Proxy";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    rust-overlay,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux"];
      perSystem = {
        config,
        system,
        ...
      }: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };

        rustNightly = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [
            "rust-src"
            "clippy"
            "rustfmt"
            "llvm-tools-preview"
            "rust-analyzer"
          ];
        };

        basePackages = [
          rustNightly
          pkgs.stdenv.cc
          pkgs.clang
          pkgs.mold
          pkgs.fd
          pkgs.git
          pkgs.nix
          pkgs.jq
          pkgs.ripgrep
          pkgs.coreutils
          pkgs.gawk
          pkgs.diffutils
          pkgs.just
          pkgs.util-linux
          pkgs.python315
        ];
      in {
        devShells.default = pkgs.mkShell {
          name = "herdr-auth-proxy";
          packages = basePackages;

          # `store = auto` makes nix pick local mode inside the jail, which
          # writes `/nix/var/nix/db` directly; the jail ro-binds that, so
          # `nix build` dies on the db lock. Force the daemon client instead:
          # the socket is bound rw and the daemon owns all store writes.
          NIX_REMOTE = "daemon";
        };
      };
    };
}
