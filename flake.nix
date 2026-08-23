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
      # ★ mukae-greeter carries `[[bin]] name = "mukae"` — the binary a display
      # manager execs. It was ABSENT from this list, so `nix build` produced
      # libraries and no greeter: the whole workspace was unshippable while
      # every crate in it compiled. mukae-lisp and mukae-host are members for
      # the same reason — a crate absent here is not built by the flake at all.
      members = [ "mukae" "mukae-spec" "mukae-lisp" "mukae-host" "mukae-face" "mukae-greetd" "mukae-native" "mukae-greeter" ];
      src = self;
      # ★ libpam, as a FUNCTION of pkgs. These args are given once and reused
      # for every system, so a derivation named here would belong to one
      # system and be silently wrong on the others — which is why substrate's
      # helper had to learn the function form before this could be expressed
      # at all. Without it the build reaches the linker and dies on
      # `unable to find library -lpam`.
      buildInputs = p: [ p.pam ];
      # ★ AND libpam AT RUN TIME, which is a SEPARATE fact from linking against
      # it. `buildInputs` gets the linker its `-L`; it does not give the
      # resulting cargo test binary a RUNPATH into the nix store, so on Linux
      # `mukae-host`'s test binary died with
      #
      #   error while loading shared libraries: libpam.so.0
      #
      # and `cargo nextest` could not even enumerate the tests (exit 127) —
      # which reads as a broken test harness rather than a missing library.
      # Same function-of-pkgs form and same reason as `buildInputs` above.
      devEnvVars = p: { LD_LIBRARY_PATH = "${p.pam}/lib"; };
    };
}
