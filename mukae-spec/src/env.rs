//! `SeatEnv` — the seam that makes a login testable with no machine.
//!
//! The landscape survey behind `theory/MUKAE.md` found that **no harness
//! anywhere runs a full login flow against a mock PAM.** Every login manager
//! in the field tests its UI and its config parser, and tests the actual
//! authentication by logging in by hand. This trait is that missing harness.
//!
//! ## Scope at M0, stated rather than implied
//!
//! `MUKAE.md` §4.3 defines the whole trait: PAM, seat/device brokering, VT
//! control, process control, identity, handoff and clock. **This is the PAM +
//! process + identity + clock subset**, which is what M0 needs to drive a
//! conversation to a session.
//!
//! The seat/VT half is deliberately ABSENT rather than stubbed. Stubbing it
//! would put `todo!()` behind a signature that reads as implemented — a method
//! that exists and panics is worse than a method that does not exist, because
//! only one of those is a compile error at the call site. It lands at M4 with
//! its typestate (`Controlled` / `Disabling` / `Disabled`), which is the whole
//! point of that phase.
//!
//! ## The PAM conversation is a PULL, and that is world-fact W1
//!
//! PAM does not hand you a form to fill in. It asks one thing at a time, and
//! what it asks depends on what you answered — a password prompt may be
//! followed by a 2FA prompt, or by `NewAuthTokRequired`, or by nothing. So
//! [`SeatEnv::pam_next`] returns a step and the caller loops. A greeter that
//! assumes "username then password" is a greeter that cannot do 2FA, and that
//! assumption is unrepresentable here because there is no method that takes
//! both at once.

use crate::ids::{PamHandleId, ServiceName, Uid, UserName};
use std::collections::BTreeMap;

/// What PAM is asking for right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PamStep {
    /// PAM wants an answer. `style` decides whether the face masks it.
    Prompt { style: MsgStyle, msg: PromptText },
    /// PAM is telling the user something and wants no answer.
    Info { style: MsgStyle, msg: PromptText },
    /// The conversation succeeded.
    Complete,
    /// The conversation failed, and `class` says how.
    Failed { class: PamClass },
}

/// PAM's message styles, and the reason the distinction is load-bearing:
/// `PromptEchoOff` is the ONLY one a face may render masked, and
/// `PromptEchoOn` is the only one it may echo. Collapsing them is how a
/// greeter echoes a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgStyle {
    PromptEchoOff,
    PromptEchoOn,
    ErrorMsg,
    TextInfo,
}

impl MsgStyle {
    /// Whether a face must mask the input for this style.
    ///
    /// A method rather than a caller-side `== PromptEchoOff`, so the rule has
    /// one home and a new style cannot silently default to echoing.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::PromptEchoOff)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptText(pub String);

/// The answer a face gives back.
///
/// `Secret` and `Visible` are distinct arms rather than one `String` because
/// the environment logs one and never the other.
pub enum PamAnswer {
    Secret(crate::capability::Passphrase),
    Visible(String),
}

impl std::fmt::Debug for PamAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secret(_) => f.write_str("Secret(<redacted>)"),
            Self::Visible(v) => write!(f, "Visible({v:?})"),
        }
    }
}

/// Why a conversation failed.
///
/// `MaxTries` is separate from `AuthError` deliberately: one means "wrong
/// password", the other means "stop asking", and a greeter that retries on the
/// second is a greeter that locks the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamClass {
    AuthError,
    UserUnknown,
    MaxTries,
    CredInsufficient,
    AuthInfoUnavail,
    Abort,
}

/// The account-management verdict, AFTER authentication succeeded.
///
/// ★ `NewAuthTokRequired` is an ARM, not an error. An expired password is a
/// successful authentication that must be followed by a token change — every
/// greeter that treats it as a failure locks the user out of their own
/// account on the day their password expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcctVerdict {
    Ok,
    NewAuthTokRequired,
    AcctExpired,
    PermDenied,
}

/// Which way credentials are being moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredFlag {
    Establish,
    Delete,
    Reinitialize,
    Refresh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPair {
    pub key: String,
    pub value: String,
}

/// The environment PAM built for the session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvSet(pub BTreeMap<String, String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PamError {
    #[error("no such pam handle")]
    NoSuchHandle,
    #[error("pam call out of order: {0}")]
    OutOfOrder(&'static str),
    #[error("pam refused: {0:?}")]
    Refused(PamClass),
}

/// A monotonic instant, supplied by the environment so tests need no sleep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub u64);

/// A spawned session's pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildPid(pub i32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    #[error("fork refused")]
    Refused,
}

/// The four answers an identity lookup can give.
///
/// Shape taken from the fleet's `kotae`, and the distinction is exactly what a
/// greeter needs: "there is no such user" (`Empty`), "I do not enumerate LDAP
/// users" (`Refused`, with what IS legal), and "NSS timed out" (`Blind`) are
/// three different facts that every existing greeter collapses into one blank
/// user list. **`Empty` is a finding, not an error.**
///
/// Defined locally at M0 for the same reason `Passphrase` is: this crate's
/// dependency list is an invariant. Consuming `kotae` proper is a later rung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer<T> {
    Found(T),
    Empty { of: &'static str },
    Refused { because: String, legal: Vec<String> },
    Blind { because: String },
}

impl<T> Answer<T> {
    /// ★ `Blind` is NOT `Empty`. A caller that treats an unreachable directory
    /// as "no such user" tells the operator their account was deleted.
    #[must_use]
    pub const fn is_finding(&self) -> bool {
        matches!(self, Self::Found(_) | Self::Empty { .. })
    }
}

/// A principal, as far as the greeter is allowed to know before login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProfile {
    pub uid: Uid,
    pub name: UserName,
    pub display_name: Option<String>,
}

/// The environment a login runs against.
///
/// Two implementations are intended: `HostSeatEnv` (libpam + logind, the only
/// crate in the tree that names `libc`) at M3, and [`crate::mock::MockSeatEnv`]
/// now.
pub trait SeatEnv {
    // ── PAM: a PULL conversation (world-fact W1) ──────────────────────
    /// # Errors
    /// [`PamError`] if the service cannot be opened.
    fn pam_start(
        &mut self,
        svc: &ServiceName,
        user: Option<&UserName>,
    ) -> Result<PamHandleId, PamError>;

    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown or already-ended handle.
    fn pam_next(&mut self, h: PamHandleId) -> Result<PamStep, PamError>;

    /// # Errors
    /// [`PamError::OutOfOrder`] when nothing was being asked.
    fn pam_answer(&mut self, h: PamHandleId, a: PamAnswer) -> Result<(), PamError>;

    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    fn pam_acct_mgmt(&mut self, h: PamHandleId) -> Result<AcctVerdict, PamError>;

    /// # Errors
    /// [`PamError`] if the token change is refused.
    fn pam_chauthtok(&mut self, h: PamHandleId) -> Result<(), PamError>;

    /// # Errors
    /// [`PamError`] if credentials cannot be established.
    fn pam_setcred(&mut self, h: PamHandleId, f: CredFlag) -> Result<(), PamError>;

    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    fn pam_putenv(&mut self, h: PamHandleId, kv: EnvPair) -> Result<(), PamError>;

    /// # Errors
    /// [`PamError`] if the session cannot be opened.
    fn pam_open_session(&mut self, h: PamHandleId) -> Result<(), PamError>;

    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    fn pam_getenvlist(&mut self, h: PamHandleId) -> Result<EnvSet, PamError>;

    /// # Errors
    /// [`PamError`] if the session cannot be closed.
    fn pam_close_session(&mut self, h: PamHandleId) -> Result<(), PamError>;

    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    fn pam_end(&mut self, h: PamHandleId) -> Result<(), PamError>;

    // ── process ───────────────────────────────────────────────────────
    /// # Errors
    /// [`SpawnError`] if the child cannot be started.
    fn fork_session(
        &mut self,
        plan: &crate::session::SessionPlan,
        env: &EnvSet,
        to: Uid,
    ) -> Result<ChildPid, SpawnError>;

    // ── identity: NSS, never /etc/passwd ──────────────────────────────
    fn resolve_principal(&self, n: &UserName) -> Answer<PublicProfile>;
    fn enumerate_principals(&self) -> Answer<Vec<PublicProfile>>;

    // ── minting: the environment's privilege, not a caller's ──────────
    // These are what turn a COMPLETED transaction into evidence, and they
    // live here rather than as a free function because only the thing that
    // holds the PAM transaction can honestly answer them. A caller cannot
    // call them usefully without a handle from a finished conversation.
    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    fn uid_for_handle(&self, h: PamHandleId) -> Result<Uid, PamError>;

    /// # Errors
    /// [`PamError::OutOfOrder`] when the conversation has not completed —
    /// which is the seal that a proof cannot be minted from a failed attempt.
    fn mint_proof(
        &mut self,
        h: PamHandleId,
        uid: Uid,
    ) -> Result<crate::capability::AuthProof, PamError>;

    // ── time ──────────────────────────────────────────────────────────
    fn clock(&self) -> Instant;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The masking rule has ONE home. A face asking "should I hide this?" gets
    /// the same answer everywhere, and a new style cannot default to echoing.
    #[test]
    fn only_echo_off_is_secret() {
        assert!(MsgStyle::PromptEchoOff.is_secret());
        for s in [
            MsgStyle::PromptEchoOn,
            MsgStyle::ErrorMsg,
            MsgStyle::TextInfo,
        ] {
            assert!(!s.is_secret(), "{s:?} must not be masked");
        }
    }

    /// ★ AN ANSWER SAYS WHICH OF FOUR THINGS HAPPENED. `Blind` is not `Empty`
    /// — reporting an unreachable directory as "no such user" tells an
    /// operator their account was deleted.
    #[test]
    fn blind_is_not_a_finding_but_empty_is() {
        let empty: Answer<u8> = Answer::Empty { of: "principals" };
        let blind: Answer<u8> = Answer::Blind {
            because: "nss timeout".into(),
        };
        assert!(empty.is_finding(), "empty IS a finding");
        assert!(!blind.is_finding(), "blind is NOT a finding");
    }

    #[test]
    fn an_answer_never_renders_a_secret() {
        let a = PamAnswer::Secret(crate::capability::Passphrase::new("hunter2".into()));
        assert!(!format!("{a:?}").contains("hunter2"));
    }
}
