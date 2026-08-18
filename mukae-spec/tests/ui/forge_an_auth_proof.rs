//! ILLEGAL STATE [1], THE MECHANISM — an `AuthProof` cannot be constructed.
//!
//! `start_session_without_a_capability.rs` proves the SYMPTOM: a caller with
//! no capability cannot supply the argument (E0061). This case proves the
//! CAUSE, and the distinction was found by the anti-vacuity harness — the
//! arity case still fails when the capability requirement is removed, so on
//! its own it does not establish that a proof is unforgeable.
//!
//! Every constructor on `AuthProof` is `pub(crate)`. A consumer holding no
//! completed conversation has no way to make one, so the whole chain
//! downstream of it is unreachable rather than merely inconvenient.
use mukae_spec::capability::{AuthProof, Passphrase};
use mukae_spec::ids::Uid;

fn main() {
    let _ = AuthProof::password(Uid(0), Passphrase::new("root".into()));
}
