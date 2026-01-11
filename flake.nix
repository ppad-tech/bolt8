{
  description = "A Haskell implementation of BOLT #8.";

  inputs = {
    ppad-aead = {
      type = "git";
      url  = "git://git.ppad.tech/aead.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-hkdf = {
      # XX temporarily using github mirror
      type = "github";
      owner = "ppad-tech";
      repo = "hkdf";
      # type = "git";
      # url  = "git://git.ppad.tech/hkdf.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
      inputs.ppad-sha256.follows = "ppad-sha256";
    };
    ppad-secp256k1 = {
      type = "git";
      url  = "git://git.ppad.tech/secp256k1.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
      inputs.ppad-sha256.follows = "ppad-sha256";
    };
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-nixpkgs = {
      type = "git";
      url  = "git://git.ppad.tech/nixpkgs.git";
      ref  = "master";
    };
    flake-utils.follows = "ppad-nixpkgs/flake-utils";
    nixpkgs.follows = "ppad-nixpkgs/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-nixpkgs
            , ppad-aead, ppad-hkdf, ppad-secp256k1, ppad-sha256
            }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-bolt8";

        pkgs  = import nixpkgs { inherit system; };
        hlib  = pkgs.haskell.lib;
        llvm  = pkgs.llvmPackages_19.llvm;
        clang = pkgs.llvmPackages_19.clang;

        aead = ppad-aead.packages.${system}.default;
        aead-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag aead "llvm")
            [ llvm clang ];

        hkdf = ppad-hkdf.packages.${system}.default;
        hkdf-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag hkdf "llvm")
            [ llvm clang ];

        secp256k1 = ppad-secp256k1.packages.${system}.default;
        secp256k1-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag secp256k1 "llvm")
            [ llvm clang ];

        sha256 = ppad-sha256.packages.${system}.default;
        sha256-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag sha256 "llvm")
            [ llvm clang ];

        hpkgs = pkgs.haskell.packages.ghc910.extend (new: old: {
          ppad-aead = aead-llvm;
          ppad-hkdf = hkdf-llvm;
          ppad-secp256k1 = secp256k1-llvm;
          ppad-sha256 = sha256-llvm;
          ${lib} = new.callCabal2nix lib ./. {
            ppad-aead = new.ppad-aead;
            ppad-hkdf = new.ppad-hkdf;
            ppad-secp256k1 = new.ppad-secp256k1;
            ppad-sha256 = new.ppad-sha256;
          };
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

          packages.haddock = hpkgs.${lib}.doc;

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
              llvm
            ];

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

