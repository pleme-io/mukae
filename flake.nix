{
  description = "mukae (迎え) — the pleme-io-native login manager. Renamed from genkan 2026-08-17: 玄関 is blue's dynamic-dispatch hook (BLUE.md:733), a strict prefix of the live `gen` tool, and a same-domain collision with three upstream auth projects. Aperture/Threshold sibling of kabe — kabe governs the door we cannot replace, mukae is the one we own. M0 SHIPPED 2026-08-18: the typed border + the mockable SeatEnv seam, 27 tests, 6 committed trybuild seals. M1-M9 (PAM linkage, seat/VT, faces, handoff) remain design.";
  inputs = {
    nixpkgs = {
      follows = "substrate/nixpkgs";
    };
    crate2nix = {
      url = "github:nix-community/crate2nix";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    substrate = {
      url = "github:pleme-io/substrate";
    };
    fenix = {
      url = "github:nix-community/fenix";
    };
  };
  outputs = inputs @ { self, nixpkgs, crate2nix, fenix, substrate, ... }:
    (import "${substrate}/lib/rust-library-workspace-flake.nix" {
      inherit nixpkgs crate2nix fenix;
    }) {
      workspaceName = "mukae";
      members = [ "mukae" "mukae-spec" ];
      src = self;
    };
}
