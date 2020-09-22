{ pkgs ? null
} @ args:

let
  pkgs = (import ./.nix/release.nix {}).ensurePkgs args;
in

with pkgs;

let
  nix-lib = callPackage ./nix-lib {};
  python-lib = (import ./cli/release.nix { inherit pkgs; }).default;
  cli = python-lib;
in

{
  inherit nix-lib;
  inherit python-lib;
  inherit cli;

  shell = {
    root = mkShell rec {
      name = "nsf-ssh-auth-root-shell";

      buildInputs = [
        cli
        nsf-pin-cli
      ];

      shellHook = with nsf-shc-nix-lib; ''
        ${nsfShC.env.exportXdgDataDirsOf buildInputs}
        ${nsfShC.env.ensureDynamicBashCompletionLoaderInstalled}
      '';
    };
  };
}
