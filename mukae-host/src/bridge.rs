//! The push↔pull bridge: libpam's callback world, made steppable.
//!
//! ── THE IMPEDANCE MISMATCH, AND WHY IT NEEDS A THREAD ──────────────────────
//! `conv.rs` states the problem exactly and this module is its answer:
//!
//!   libpam PUSHES — it calls the conversation function synchronously from
//!   inside `pam_authenticate`, on its own stack.
//!   `SeatEnv` PULLS — `pam_next` returns one step and the caller answers at
//!   its leisure.
//!
//! Those cannot be reconciled on one thread. `pam_authenticate` does not
//! return until the whole conversation is over, so a single-threaded greeter
//! would have to render a prompt from inside a C callback and pump its own
//! event loop there — which is how a login screen deadlocks.
//!
//! So: `pam_authenticate` runs on a worker, the callback sends the prompt down
//! one channel and BLOCKS on another waiting for the answer, and the face calls
//! `pam_next`/`pam_answer` at whatever pace a human types.
//!
//! ── ★ WHY THE BLOCKING IS THE POINT, NOT A COMPROMISE ─────────────────────
//! The callback blocking is what preserves PAM's semantics. libpam is entitled
//! to assume the conversation answered *this* prompt before it proceeds, and a
//! bridge that returned a placeholder to keep the C side moving would be
//! answering questions it had not asked a human yet. The whole safety property
//! of a login screen is that the password reaching `pam_authenticate` is the
//! one the person typed for that prompt.
//!
//! ── WHAT A MISTAKE LOOKS LIKE HERE ────────────────────────────────────────
//! `conv.rs` also warns that a mistake in this shape is "a hung login rather
//! than a compile error". That is why every channel operation below is
//! explicit about which side may block and for how long, and why a dropped
//! worker is turned into a typed `Failed` step instead of a silent hang: a
//! greeter that stops responding is indistinguishable, to the person in front
//! of it, from a machine that has died.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::Duration;

use mukae_spec::env::{MsgStyle, PamAnswer, PamClass, PamError, PamStep, PromptText};

/// How long `pam_next` waits for the worker to produce a step before deciding
/// the transaction is wedged.
///
/// Not a tuning knob: it is the difference between a login screen that reports
/// a stuck PAM stack and one that appears frozen. A PAM module doing real work
/// (a network directory, a hardware token) can legitimately take seconds, so
/// this is generous — but it is finite, because "wait forever" is the failure
/// mode a person cannot distinguish from a dead machine.
const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// One side of the bridge, held by the face.
///
/// Owns the channels, not the worker: the worker is detached deliberately, so
/// dropping the handle mid-conversation cannot leave `pam_authenticate` half
/// executed on a thread nobody is joining.
pub struct Bridge {
    steps: Receiver<PamStep>,
    answers: SyncSender<PamAnswer>,
    /// Set once a terminal step has been observed. `pam_next` after completion
    /// is a caller bug rather than a PAM state, and saying so beats returning a
    /// second `Complete` that the caller may act on twice.
    finished: bool,
}

/// The other side, moved onto the worker and called from the C callback.
pub struct ConvSide {
    steps: SyncSender<PamStep>,
    answers: Receiver<PamAnswer>,
}

impl ConvSide {
    /// Called from inside libpam's conversation callback. Sends the prompt to
    /// the face and BLOCKS until an answer arrives.
    ///
    /// # Errors
    /// Returns `PamError` when the face has gone away — which is a real
    /// outcome, not a bug: a greeter can be killed mid-login, and libpam must
    /// be told the conversation failed rather than handed a fabricated answer.
    pub fn ask(&self, style: MsgStyle, msg: PromptText) -> Result<PamAnswer, PamError> {
        self.steps
            .send(PamStep::Prompt { style, msg })
            .map_err(|_| PamError::Refused(PamClass::Abort))?;
        self.answers
            .recv()
            .map_err(|_| PamError::Refused(PamClass::Abort))
    }

    /// Tell the face something without asking for an answer.
    ///
    /// # Errors
    /// Same as [`ask`]: a vanished face is a conversation error.
    pub fn tell(&self, style: MsgStyle, msg: PromptText) -> Result<(), PamError> {
        self.steps
            .send(PamStep::Info { style, msg })
            .map_err(|_| PamError::Refused(PamClass::Abort))
    }

    /// Publish the transaction's outcome. Consumes self so a worker cannot
    /// report twice.
    pub fn finish(self, step: PamStep) {
        // A failed send here means the face already left, which is fine: there
        // is nobody to tell and nothing to clean up.
        let _ = self.steps.send(step);
    }
}

impl Bridge {
    /// Build both halves.
    ///
    /// The channels are RENDEZVOUS (`sync_channel(0)`), deliberately. A buffered
    /// channel would let the worker run ahead and queue a second prompt before
    /// the first was answered, which silently reorders a conversation whose
    /// whole meaning is sequential — PAM asks for a username, THEN a password,
    /// and a face that received both at once has no way to know which is which.
    #[must_use]
    pub fn new() -> (Self, ConvSide) {
        let (step_tx, step_rx) = sync_channel(0);
        let (ans_tx, ans_rx) = sync_channel(0);
        (
            Self {
                steps: step_rx,
                answers: ans_tx,
                finished: false,
            },
            ConvSide {
                steps: step_tx,
                answers: ans_rx,
            },
        )
    }

    /// The next thing PAM wants, or what became of the transaction.
    ///
    /// # Errors
    /// Never — a wedged or vanished worker is reported as a typed `Failed`
    /// step rather than an error, because the face has to render *something*
    /// and "the login failed" is more useful to a person than an error type.
    pub fn next(&mut self) -> PamStep {
        if self.finished {
            return PamStep::Failed {
                class: PamClass::Abort,
            };
        }
        let step = match self.steps.recv_timeout(STEP_TIMEOUT) {
            Ok(s) => s,
            // The worker is gone. Its thread panicked, or the transaction was
            // dropped — either way there will never be another step, and
            // waiting longer only makes the screen look dead.
            Err(RecvTimeoutError::Disconnected) => PamStep::Failed {
                class: PamClass::Abort,
            },
            // Still alive but not producing. A PAM module is stuck; say so
            // rather than hang.
            Err(RecvTimeoutError::Timeout) => PamStep::Failed {
                class: PamClass::AuthInfoUnavail,
            },
        };
        if matches!(step, PamStep::Complete | PamStep::Failed { .. }) {
            self.finished = true;
        }
        step
    }

    /// Hand PAM the answer it is blocked on.
    ///
    /// # Errors
    /// Returns `PamError` if the worker is gone, which means the answer has
    /// nowhere to go. The caller should treat that as a failed login, not
    /// retry — the transaction it belonged to no longer exists.
    pub fn answer(&self, a: PamAnswer) -> Result<(), PamError> {
        self.answers
            .send(a)
            .map_err(|_| PamError::Refused(PamClass::Abort))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt(s: &str) -> PromptText {
        PromptText(s.to_string())
    }

    #[test]
    fn a_prompt_crosses_and_the_answer_comes_back() {
        let (mut face, conv) = Bridge::new();
        std::thread::spawn(move || {
            let a = conv
                .ask(MsgStyle::PromptEchoOn, prompt("login:"))
                .expect("face answered");
            match a {
                PamAnswer::Visible(v) => assert_eq!(v, "luis"),
                PamAnswer::Secret(_) => panic!("echo-on prompt got a secret"),
            }
            conv.finish(PamStep::Complete);
        });

        match face.next() {
            PamStep::Prompt { style, .. } => assert_eq!(style, MsgStyle::PromptEchoOn),
            other => panic!("expected a prompt, got {other:?}"),
        }
        face.answer(PamAnswer::Visible("luis".into())).unwrap();
        assert!(matches!(face.next(), PamStep::Complete));
    }

    #[test]
    fn a_dead_worker_becomes_a_typed_failure_not_a_hang() {
        // ★ The property conv.rs warns about: a mistake here is a hung login.
        // A worker that dies without finishing must surface as a Failed step,
        // because a greeter that stops responding is indistinguishable — to the
        // person in front of it — from a machine that has died.
        let (mut face, conv) = Bridge::new();
        drop(conv);
        assert!(matches!(face.next(), PamStep::Failed { .. }));
    }

    #[test]
    fn next_after_a_terminal_step_does_not_reopen_the_conversation() {
        let (mut face, conv) = Bridge::new();
        std::thread::spawn(move || conv.finish(PamStep::Complete));
        assert!(matches!(face.next(), PamStep::Complete));
        // A second next() must not report Complete again — a caller acting on
        // two completions would open two sessions for one login.
        assert!(matches!(face.next(), PamStep::Failed { .. }));
    }
}
