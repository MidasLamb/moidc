{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    crane,
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        pemFilter = path: _type: builtins.match ".*pem$" path != null;
        pemOrCargo = path: type:
          (pemFilter path type) || (craneLib.filterCargoSources path type);
        #src = craneLib.cleanCargoSource ./.;
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = pemOrCargo;
          name = "source";
        };
        nativeBuildInputs = with pkgs; [rustToolchain pkg-config];
        buildInputs = with pkgs; [openssl];
        commonArgs = {
          inherit src buildInputs nativeBuildInputs;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        bin = craneLib.buildPackage (commonArgs
          // {
            inherit cargoArtifacts;
          });
	    muslPkgs = pkgs.pkgsCross.musl64;
		muslBuild = muslPkgs.rustPlatform.buildRustPackage {
		  pname = "moidc";
		  version = "0.1.0";
		  src = ./.;
		  cargoLock.lockFile = ./Cargo.lock;
		  # fully static musl binary, no runtime deps at all
		};

		appFiles = pkgs.runCommand "app-files" {} ''
			    mkdir -p $out/app
				cp ${./settings.yaml} $out/app/settings.yaml
				cp ${./private-key.pem} $out/app/private-key.pem
		'';

        dockerImage = pkgs.dockerTools.streamLayeredImage {
          name = "moidc";
          tag = "latest";
          contents = [appFiles];
          config = {
            Entrypoint = ["${muslBuild}/bin/moidc"];
			WorkingDir = "/app";
          };
        };
      in
        with pkgs; {
          packages = {
            inherit bin dockerImage;
            default = bin;
          };
          devShells.default = mkShell {
            inputsFrom = [bin];
            buildInputs = with pkgs; [dive nix-tree rustToolchain rust-analyzer];
          };
        }
    );
}
