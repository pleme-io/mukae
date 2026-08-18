//! # mukae (迎え) — the pleme-io-native login manager
//!
//! `mukae` is *to meet, to receive* — the person who comes to the door when
//! you arrive. Its sibling `kabe` (壁) governs the door we cannot replace;
//! mukae is the one we own.
//!
//! This is the umbrella: one import that re-exports the whole surface as it
//! lands, so a consumer writes `mukae::` and never has to track which crate a
//! type moved to. The pattern is the fleet's (`shigoto` does the same), and
//! substrate's `rust-library-workspace-flake` expects it — `defaultMember`
//! defaults to the workspace name, so `nix build .#default` builds this.
//!
//! ## What is behind this door today, and what is not
//!
//! **Here:** [`spec`] — the typed login border and the mockable `SeatEnv`
//! seam. The capability chain, the seat typestate, the PAM conversation, and
//! a mock that runs a whole login with no machine.
//!
//! **Not here**, and each is a named phase in
//! [`theory/MUKAE.md`](https://github.com/pleme-io/theory/blob/main/MUKAE.md)
//! §7 rather than an oversight:
//!
//! | | phase |
//! |---|---|
//! | `mukae-auth` — the PAM linkage (`HostSeatEnv`) | M3 |
//! | the seat / device / VT half, with its typestate | M4 |
//! | `mukae-tty` — the text face | M5 |
//! | the GPU face, as a mode of omoya | M6 |
//! | `mukae-handoff` — the greeter→session config envelope | M7 |
//!
//! A re-export appears here when the crate behind it exists. An empty
//! `pub mod` that a consumer could `use` and get nothing from would be worse
//! than the absence, because only the absence is a compile error.

pub use mukae_spec as spec;

// The types a consumer reaches for most, lifted to the root so the common
// path is `mukae::SeatCapability` rather than `mukae::spec::capability::…`.
pub use mukae_spec::{
    Argv, Ask, AuthMethod, AuthProof, Authenticated, Conversation, Denied, Face, Outcome,
    PamAnswer, PamStep, SeatCapability, SeatEnv, SeatId, SessionHandle, SessionPlan, Uid, UserName,
    start_session,
};

#[cfg(test)]
mod tests {
    /// The umbrella actually re-exports something. A crate that exists only to
    /// satisfy a flake's `defaultMember` and re-exports nothing is a lie told
    /// to the build system.
    #[test]
    fn the_umbrella_reaches_the_border() {
        let seat = crate::SeatId::parse("seat0").unwrap();
        assert!(seat.as_seat0().is_some());
    }
}
