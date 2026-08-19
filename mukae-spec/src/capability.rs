//! The capability chain — the centrepiece.
//!
//! Five of the sixteen illegal states in `theory/MUKAE.md` §4.4 are closed
//! here, and all five are closed the same way: **the caller cannot name the
//! argument**. Not a runtime check that returns `Err`, not a lint, not a
//! review item — an expression that does not compile.
//!
//! | # | illegal state | mechanism | code |
//! |---|---|---|---|
//! | 1 | start a session that was never authenticated | `start_session` names `SeatCapability<Authenticated>`; the only constructor is `mint(AuthProof, …)`; `AuthProof` has no public constructor and a private payload | E0061 / E0425 |
//! | 2 | reuse one authentication for two sessions | `mint` consumes the proof BY VALUE; `start_session` consumes the capability BY VALUE; neither is `Clone` | E0382 |
//! | 3 | a failed attempt upgraded to success by a later call | there is NO `Denied -> Authenticated` transition on any type | E0599 |
//! | 4 | a downstream crate inventing a third auth state | `SeatState: sealed::Sealed`, and `sealed` is private | E0277 |
//! | 11 | "we autologged in and the keyring is unlocked" | `KeyringUnlock::from` matches the private payload; only the password arm returns `Some` | truly-unrep |
//!
//! Illegal state 3 is the one worth dwelling on, because it is the classic
//! greeter bug rather than a theoretical one: a retry loop where a stale
//! `authenticated = true` survives a failed attempt. It is not defended
//! against here. It is **not expressible** — no method anywhere takes a
//! `SeatCapability<Denied>` and returns a `SeatCapability<Authenticated>`.

use crate::ids::{CredentialId, PamHandleId, RunFileConsumed, SeatId, SlotId, Uid};
use std::marker::PhantomData;

/// A passphrase. Never `Debug`-printed, never `Display`, never in argv.
///
/// This is deliberately a thin local type rather than a dependency: at M0 the
/// crate has no dependencies beyond serde and thiserror (see Cargo.toml's
/// comment on why that list is an invariant). The fleet's `cofre::Secret` is
/// the destination and is named in MUKAE.md illegal state [9]; wiring it is a
/// later rung, and claiming it here would be a round-up.
pub struct Passphrase(String);

impl Passphrase {
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// The only reader inside the border. `pub(crate)` so a consumer cannot
    /// get the plaintext back out by reading it.
    #[must_use]
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// ★ A secret that prints itself is a secret in the logs. The redaction is
/// the whole impl, so there is no path that renders the plaintext.
/// Surrender a passphrase to the authenticator that will check it.
///
/// ── ★ WHY THIS EXISTS, AND WHY IT IS THE ONLY ONE ─────────────────────────
/// A passphrase has to LEAVE this program to be checked — there is no
/// authenticator inside it. libpam takes a `malloc`'d C string; greetd takes a
/// JSON field on a socket. Both live in other crates, and `expose` is
/// `pub(crate)`, so before this existed neither could send one.
///
/// That was not a safe design, it was a broken one. Measured 2026-08-19:
/// `bridging_conv` matched `PamAnswer::Secret(_)` and returned `PAM_CONV_ERR`
/// — so a password typed into mukae was never handed to PAM, and **every PAM
/// login failed, always**. The comment there claimed "the answer arrives
/// already reduced to what libpam needs", describing a conversion that nothing
/// performed. A guarantee enforced by making the program not work is not a
/// guarantee; it is a bug with a security-shaped rationale.
///
/// ── ★ WHAT KEEPS IT NARROW ────────────────────────────────────────────────
/// It **consumes**. The `Passphrase` is destroyed in the act, so there is no
/// read-it-twice, no read-then-log, and no accidental capture of a value the
/// caller still holds. It is one function with one name, so the audit question
/// "where can a passphrase leave?" is a grep with a small, countable answer —
/// which is what the `pub(crate)` reader was reaching for and could not deliver
/// while it also made the program unable to log anyone in.
#[must_use]
pub fn into_wire(p: Passphrase) -> String {
    p.0
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// How a principal proved who they are.
///
/// The PUBLIC projection of the private [`Evidence`] payload — breathe's
/// `WitnessKind` shape. A consumer may branch on the method; it may not
/// reconstruct the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    Fido2,
    Smartcard,
    Autologin,
}

/// The evidence itself. **Deliberately not `pub`.**
///
/// A `pub enum`'s variants are always public, so a `pub enum Evidence` would
/// hand every downstream crate a constructor for `AuthProof` and delete
/// illegal state [1] entirely. The reasoning is breathe's, at
/// `breathe/breathe-provider/src/gate.rs:79-81`.
enum Evidence {
    Password { uid: Uid, authtok: Passphrase },
    Fido2 { uid: Uid, cred: CredentialId },
    Smartcard { uid: Uid, slot: SlotId },
    Autologin { uid: Uid, once: RunFileConsumed },
}

/// Proof that an authentication actually happened.
///
/// Non-`Clone`, non-`Default`, no public constructor, private payload.
/// Produced ONLY by [`crate::conversation::Conversation::run`] — which is to
/// say, only by actually running a PAM conversation to completion.
#[derive(Debug)]
pub struct AuthProof(Evidence);

impl std::fmt::Debug for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The uid and the method, never the authtok. `Passphrase`'s own Debug
        // is already redacted; this is belt and braces on the enum that holds
        // it, because a derived Debug here would be one field away from
        // leaking regardless.
        match self {
            Self::Password { uid, .. } => write!(f, "Password {{ uid: {uid} }}"),
            Self::Fido2 { uid, .. } => write!(f, "Fido2 {{ uid: {uid} }}"),
            Self::Smartcard { uid, slot } => {
                write!(f, "Smartcard {{ uid: {uid}, slot: {slot:?} }}")
            }
            Self::Autologin { uid, .. } => write!(f, "Autologin {{ uid: {uid} }}"),
        }
    }
}

impl AuthProof {
    pub(crate) fn password(uid: Uid, authtok: Passphrase) -> Self {
        Self(Evidence::Password { uid, authtok })
    }

    pub(crate) fn fido2(uid: Uid, cred: CredentialId) -> Self {
        Self(Evidence::Fido2 { uid, cred })
    }

    pub(crate) fn smartcard(uid: Uid, slot: SlotId) -> Self {
        Self(Evidence::Smartcard { uid, slot })
    }

    pub(crate) fn autologin(uid: Uid, once: RunFileConsumed) -> Self {
        Self(Evidence::Autologin { uid, once })
    }

    #[must_use]
    pub fn uid(&self) -> Uid {
        match &self.0 {
            Evidence::Password { uid, .. }
            | Evidence::Fido2 { uid, .. }
            | Evidence::Smartcard { uid, .. }
            | Evidence::Autologin { uid, .. } => *uid,
        }
    }

    #[must_use]
    pub fn method(&self) -> AuthMethod {
        match &self.0 {
            Evidence::Password { .. } => AuthMethod::Password,
            Evidence::Fido2 { .. } => AuthMethod::Fido2,
            Evidence::Smartcard { .. } => AuthMethod::Smartcard,
            Evidence::Autologin { .. } => AuthMethod::Autologin,
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// The two states a seat's authentication can be in. **Sealed.**
///
/// A downstream crate writing `impl SeatState for Maybe {}` fails: `Sealed`
/// lives in a private module, so the bound cannot be satisfied from outside.
/// That is illegal state [4] — nobody invents a third state such as
/// "probably" or "cached".
pub trait SeatState: sealed::Sealed {}

/// Authentication completed.
#[derive(Debug)]
pub struct Authenticated;
impl sealed::Sealed for Authenticated {}
impl SeatState for Authenticated {}

/// Authentication failed. **There is no method on this type that returns
/// `SeatCapability<Authenticated>`.** Read the impl blocks below: the absence
/// is the mechanism.
#[derive(Debug)]
pub struct Denied;
impl sealed::Sealed for Denied {}
impl SeatState for Denied {}

/// The right to start a session on one seat, as one principal.
///
/// **NOT `Clone`. NOT `Copy`.** One authentication must not start two
/// sessions, so both `mint` and [`crate::session::start_session`] take their
/// input by value and there is no way to get a second one.
#[derive(Debug)]
pub struct SeatCapability<S: SeatState> {
    uid: Uid,
    seat: SeatId,
    pam: PamHandleId,
    _s: PhantomData<S>,
}

impl SeatCapability<Authenticated> {
    /// The SOLE ingress to the authenticated state.
    ///
    /// Consumes the proof by value: after this call the proof is gone, so a
    /// caller cannot mint twice from one authentication (illegal state [2],
    /// E0382).
    #[must_use]
    pub fn mint(proof: AuthProof, seat: SeatId, pam: PamHandleId) -> Self {
        Self {
            uid: proof.uid(),
            seat,
            pam,
            _s: PhantomData,
        }
    }
}

impl SeatCapability<Denied> {
    /// A denial is a fact, and this is the only thing you can do with one:
    /// look at it. Note what is NOT here — no `retry`, no `authenticate`, no
    /// `into_authenticated`, no `assume`. Illegal state [3] is closed by that
    /// absence, not by a guard.
    #[must_use]
    pub fn denied_for(seat: SeatId, pam: PamHandleId) -> Self {
        Self {
            uid: Uid(u32::MAX),
            seat,
            pam,
            _s: PhantomData,
        }
    }
}

impl<S: SeatState> SeatCapability<S> {
    #[must_use]
    pub fn uid(&self) -> Uid {
        self.uid
    }

    #[must_use]
    pub fn seat(&self) -> &SeatId {
        &self.seat
    }

    #[must_use]
    pub fn pam_handle(&self) -> PamHandleId {
        self.pam
    }
}

/// The right to unlock a password-derived keyring.
///
/// World-fact W6: a keyring sealed by a login password can only be unlocked
/// with the plaintext, at authentication time. So this is mintable only from
/// a password proof — [`KeyringUnlock::from`] pattern-matches the private
/// `Evidence` and returns `None` for every other arm.
///
/// The consequence is stated rather than discovered: **an autologin session
/// has a locked keyring, and that is a fact about cryptography, not a
/// misconfiguration.** A system that claims otherwise is lying.
#[derive(Debug)]
pub struct KeyringUnlock(String);

impl KeyringUnlock {
    /// `pub(crate)`: minting this is the conversation's privilege.
    #[must_use]
    pub(crate) fn from(p: &AuthProof) -> Option<Self> {
        match &p.0 {
            Evidence::Password { authtok, .. } => Some(Self(authtok.expose().to_owned())),
            Evidence::Fido2 { .. } | Evidence::Smartcard { .. } | Evidence::Autologin { .. } => {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seat() -> SeatId {
        SeatId::parse("seat0").unwrap()
    }

    #[test]
    fn a_proof_projects_its_uid_and_method_but_not_its_evidence() {
        let p = AuthProof::password(Uid(1000), Passphrase::new("hunter2".into()));
        assert_eq!(p.uid(), Uid(1000));
        assert_eq!(p.method(), AuthMethod::Password);
    }

    /// ★ A SECRET THAT PRINTS ITSELF IS A SECRET IN THE LOGS. Both the
    /// passphrase and the proof that carries it must be safe to `{:?}` in an
    /// error path, because that is exactly where they end up.
    #[test]
    fn neither_a_passphrase_nor_a_proof_leaks_through_debug() {
        let s = Passphrase::new("hunter2".into());
        assert!(!format!("{s:?}").contains("hunter2"));

        let p = AuthProof::password(Uid(1000), Passphrase::new("hunter2".into()));
        let rendered = format!("{p:?}");
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
        assert!(rendered.contains("1000"), "should still identify the uid");
    }

    #[test]
    fn minting_carries_the_proofs_uid() {
        let p = AuthProof::password(Uid(1000), Passphrase::new("x".into()));
        let cap = SeatCapability::mint(p, seat(), PamHandleId(7));
        assert_eq!(cap.uid(), Uid(1000));
        assert_eq!(cap.seat().as_str(), "seat0");
    }

    /// ★ WORLD-FACT W6, AS A TYPE. Only a password proof can unlock a
    /// password-derived keyring — every other method returns `None`, so an
    /// autologin session simply has no path to a `KeyringUnlock`.
    #[test]
    fn only_a_password_proof_unlocks_a_keyring() {
        let pw = AuthProof::password(Uid(1), Passphrase::new("x".into()));
        assert!(KeyringUnlock::from(&pw).is_some());

        for other in [
            AuthProof::fido2(Uid(1), CredentialId(vec![1, 2, 3])),
            AuthProof::smartcard(Uid(1), SlotId(0)),
            AuthProof::autologin(Uid(1), RunFileConsumed::mint()),
        ] {
            assert!(
                KeyringUnlock::from(&other).is_none(),
                "{:?} must not unlock a password keyring",
                other.method()
            );
        }
    }

    /// A denial is inspectable and nothing else. The compile-fail suite proves
    /// the absence; this proves the denial still carries enough to report on.
    #[test]
    fn a_denial_is_inspectable_and_goes_nowhere() {
        let d = SeatCapability::<Denied>::denied_for(seat(), PamHandleId(3));
        assert_eq!(d.pam_handle(), PamHandleId(3));
        assert_eq!(d.seat().as_str(), "seat0");
    }
}
