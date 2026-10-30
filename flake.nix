{
  description = "Herdr Authorization Proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    rust-overlay,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux"];

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

        herdr-auth-proxy = pkgs.rustPlatform.buildRustPackage {
          pname = "herdr-auth-proxy";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = ["--bins"];
          meta = {
            description = "JWT-authenticating, permission-filtering proxy for herdr's socket API";
            homepage = "https://github.com/butzist/herdr-auth-proxy";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "herdr-auth-proxy";
          };
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
        packages = {
          default = herdr-auth-proxy;
          herdr-auth-proxy = herdr-auth-proxy;
        };

        apps.default = {
          type = "app";
          program = "${herdr-auth-proxy}/bin/herdr-auth-proxy";
        };

        formatter = pkgs.nixfmt-rfc-style;

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

      flake = {
        overlays.default = final: prev: {
          herdr-auth-proxy = self.packages.${final.stdenv.hostPlatform.system}.default;
        };

        nixosModules.default = {
          config,
          lib,
          pkgs,
          ...
        }: {
          options.programs.herdr-auth-proxy.enable =
            lib.mkEnableOption "herdr-auth-proxy (JWT proxy for herdr's socket API)";

          config = lib.mkIf config.programs.herdr-auth-proxy.enable {
            environment.systemPackages = [
              self.packages.${pkgs.stdenv.hostPlatform.system}.default
            ];
          };
        };

        homeManagerModules.default = {
          pkgs,
          ...
        }: {
          home.packages = [self.packages.${pkgs.stdenv.hostPlatform.system}.default];
        };
      };
    };
}
