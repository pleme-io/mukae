//! The conversation — the ONLY thing in the fleet that produces an `AuthProof`.
//!
//! ## Why this is a loop and not a form
//!
//! World-fact W1: PAM is a *pull*. It asks one thing at a time and what it
//! asks next depends on what you answered. A password prompt may be followed
//! by a 2FA prompt, or by `NewAuthTokRequired`, or by nothing at all. So the
//! driver loops on [`SeatEnv::pam_next`] until PAM says `Complete`, and the
//! face answers whatever it is asked.
//!
//! The consequence is structural rather than stylistic: **there is no method
//! anywhere that takes a username and a password together.** A greeter built
//! on this cannot assume the two-field form, which is why it can do 2FA,
//! expired-password changes and smartcards without a redesign. Every login
//! manager that hardcoded the form had to grow a special case for each of
//! those; this one has none.
//!
//! ## Where the account check goes, and why the order matters
//!
//! `pam_acct_mgmt` runs AFTER authentication succeeds and BEFORE a proof is
//! minted. `NewAuthTokRequired` is an ARM of its verdict, not an error:
//! an expired password is a *successful authentication that must be followed
//! by a token change*. A greeter that treats it as a failure locks the user
//! out of their own account on the day their password expires — which is the
//! single most common day for a person to need to log in and change it.

use crate::capability::{AuthProof, Authenticated, Denied, KeyringUnlock, SeatCapability};
use crate::env::{AcctVerdict, PamAnswer, PamClass, PamError, PamStep, PromptText, SeatEnv};
use crate::ids::{PamHandleId, SeatId, ServiceName, UserName};

/// What a face is being asked, in mukae's vocabulary rather than PAM's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// Answer this, masked.
    Secret(PromptText),
    /// Answer this, echoed.
    Visible(PromptText),
    /// Show this; no answer wanted.
    Tell(PromptText),
}

/// A face: the thing that talks to a human.
///
/// One trait for the TTY face, the GPU face and the test harness. A face that
/// cannot render a `Tell` is a face that swallows "your password expires
/// tomorrow", so all three arms are required rather than defaulted.
pub trait Face {
    /// Answer an ask. `None` means the human gave up — a distinct outcome from
    /// a wrong password, and it must not consume a retry.
    fn respond(&mut self, ask: &Ask) -> Option<PamAnswer>;
}

/// The outcome of one conversation.
///
/// A sum, not a `Result<AuthProof, E>`, because "the human pressed escape" is
/// not an error and must not be counted against the retry budget.
#[derive(Debug)]
pub enum Outcome {
    /// Authenticated. Carries the proof and, when the method allows it, the
    /// keyring unlock (world-fact W6).
    Authenticated {
        proof: AuthProof,
        keyring: Option<KeyringUnlock>,
    },
    /// PAM said no.
    Denied {
        cap: SeatCapability<Denied>,
        class: PamClass,
    },
    /// The human walked away. NOT a denial, NOT a retry.
    Abandoned,
    /// Authentication worked; the account needs a new token before a session
    /// may start. An ARM, deliberately — see this module's header.
    TokenChangeRequired { handle: PamHandleId },
}

/// Drives one PAM conversation to a verdict.
pub struct Conversation<'a, E: SeatEnv, F: Face> {
    env: &'a mut E,
    face: &'a mut F,
    seat: SeatId,
}

impl<'a, E: SeatEnv, F: Face> Conversation<'a, E, F> {
    pub fn new(env: &'a mut E, face: &'a mut F, seat: SeatId) -> Self {
        Self { env, face, seat }
    }

    /// Run the conversation.
    ///
    /// `user` is `Option` because PAM may ask for the username itself
    /// (`PromptEchoOn`) — a greeter that always supplies it cannot support a
    /// no-user-list login, which is the posture a multi-thousand-user host
    /// needs.
    ///
    /// # Errors
    /// [`PamError`] for a protocol-level failure. A *rejected* login is not an
    /// error — it is [`Outcome::Denied`].
    ///
    /// # Panics
    /// Never. The loop is bounded by `max_steps`.
    pub fn run(
        &mut self,
        svc: &ServiceName,
        user: Option<&UserName>,
        max_steps: usize,
    ) -> Result<Outcome, PamError> {
        let h = self.env.pam_start(svc, user)?;

        // ★ BOUNDED. An unbounded loop over a pull conversation is a hang, and
        // a hung greeter is an unusable machine with no console fallback. The
        // fleet's reconciler-liveness rule in one line: bound every loop so a
        // hang degrades into a typed failure.
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > max_steps {
                return Err(PamError::OutOfOrder("conversation exceeded max_steps"));
            }

            match self.env.pam_next(h)? {
                PamStep::Prompt { style, msg } => {
                    let ask = if style.is_secret() {
                        Ask::Secret(msg)
                    } else {
                        Ask::Visible(msg)
                    };
                    let Some(answer) = self.face.respond(&ask) else {
                        // The human walked away. End the transaction cleanly;
                        // this must not count as a failed attempt.
                        self.env.pam_end(h)?;
                        return Ok(Outcome::Abandoned);
                    };
                    self.env.pam_answer(h, answer)?;
                }
                PamStep::Info { msg, .. } => {
                    // Told, not asked. A face that drops these swallows
                    // "your password expires tomorrow".
                    let _ = self.face.respond(&Ask::Tell(msg));
                }
                PamStep::Failed { class } => {
                    return Ok(Outcome::Denied {
                        cap: SeatCapability::denied_for(self.seat.clone(), h),
                        class,
                    });
                }
                PamStep::Complete => break,
            }
        }

        // Authentication succeeded. The ACCOUNT may still say no, and that is
        // a different question with a different answer set.
        match self.env.pam_acct_mgmt(h)? {
            AcctVerdict::Ok => {}
            AcctVerdict::NewAuthTokRequired => {
                return Ok(Outcome::TokenChangeRequired { handle: h });
            }
            AcctVerdict::AcctExpired => {
                return Ok(Outcome::Denied {
                    cap: SeatCapability::denied_for(self.seat.clone(), h),
                    class: PamClass::CredInsufficient,
                });
            }
            AcctVerdict::PermDenied => {
                return Ok(Outcome::Denied {
                    cap: SeatCapability::denied_for(self.seat.clone(), h),
                    class: PamClass::AuthError,
                });
            }
        }

        let uid = self.env.uid_for_handle(h)?;
        let proof = self.env.mint_proof(h, uid)?;
        let keyring = KeyringUnlock::from(&proof);
        Ok(Outcome::Authenticated { proof, keyring })
    }
}

/// Mint a capability from an outcome, if it is one that permits a session.
///
/// A free function rather than a method on `Outcome`, so that reading the call
/// site tells you a capability was minted rather than hiding it in a `?`.
#[must_use]
pub fn capability_from(
    outcome: Outcome,
    seat: SeatId,
    pam: PamHandleId,
) -> Option<SeatCapability<Authenticated>> {
    match outcome {
        Outcome::Authenticated { proof, .. } => Some(SeatCapability::mint(proof, seat, pam)),
        // Every other arm yields None. Note there is no arm that could yield a
        // capability from a Denied — the constructor is not reachable from it.
        Outcome::Denied { .. } | Outcome::Abandoned | Outcome::TokenChangeRequired { .. } => None,
    }
}
