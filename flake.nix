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
    let
      # ── ★ THE MODULE TRIO, VIA THE DIRECT PATH ───────────────────────────
      # `rust.tool` consumers (mado, namimado, omoya) pass a `module = {...}`
      # attr and the builder emits the trio for them. This workspace is built
      # by `rust-library-workspace-flake.nix`, which has NO such seam — so the
      # trio is constructed here explicitly, which is the usage
      # `lib/module-trio.nix`'s own header documents.
      #
      # Measured before writing this: mukae's flake emitted
      # `apps checks devShells overlays packages` and NO module outputs at
      # all. The greeter that logs every operator in had no module of its
      # own, while the terminal it eventually launches shipped three.
      #
      # ★ withAnvilMcp — the binary gains `mukae mcp`, a READ-ONLY stdio
      # sidecar (mukae-greeter/src/mcp.rs). Registering it with
      # blackmatter-anvil is what makes the login flow observable by an
      # agent: which PAM step, what prompt, whether echo is masked, how many
      # attempts have failed. There is deliberately no write surface — see
      # that module's header for why an agent must not type at a greeter.
      trio = (import "${substrate}/lib/module-trio.nix" {
        lib = nixpkgs.lib;
      }).mkModuleTrio {
        name = "mukae";
        description = "mukae (迎え) — the pleme-io-native login face";
        # The workspace's shipped binary is `mukae`, from mukae-greeter.
        binaryName = "mukae";
        hmNamespace = "blackmatter.components";
        withAnvilMcp = true;
        anvilDescription =
          "mukae (迎え) — the login face. OBSERVE ONLY: read which PAM step the greeter is on, "
          + "what it is prompting for, whether echo is masked, and the attempt/failure counters. "
          + "No synthetic input is exposed at the authentication boundary. `blind` means no "
          + "greeter is running, which is the normal state once someone is logged in.";
      };

      base = (import "${substrate}/lib/rust-library-workspace-flake.nix" {
        inherit nixpkgs crate2nix fenix;
      }) {
      workspaceName = "mukae";
      # ★ mukae-greeter carries `[[bin]] name = "mukae"` — the binary a display
      # manager execs. It was ABSENT from this list, so `nix build` produced
      # libraries and no greeter: the whole workspace was unshippable while
      # every crate in it compiled. mukae-lisp and mukae-host are members for
      # the same reason — a crate absent here is not built by the flake at all.
      members = [ "mukae" "mukae-seat" "mukae-spec" "mukae-lisp" "mukae-host" "mukae-face" "mukae-greetd" "mukae-native" "mukae-greeter" ];
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
    in
    base
    // {
      nixosModules.default = trio.nixosModule;
      darwinModules.default = trio.darwinModule;
      homeManagerModules.default = trio.homeManagerModule;
    };
}
