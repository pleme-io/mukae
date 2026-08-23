//! The login flow, observable and driveable over MCP.
//!
//! ── WHY THIS IS THE POINT OF NATURALIZING THE GREETER ─────────────────────
//! A foreign greeter is untestable. tuigreet is a binary that draws a prompt
//! and exits; there is no way to ask it what step it is on, no way to drive a
//! login from a test, and no way to tell a failed authentication from a hung
//! PAM stack without sitting in front of the machine. Every visual question
//! about the seat this session has cost a round trip through a human's eyes,
//! and the login screen is the one surface where that is least acceptable —
//! because it is the surface a person meets when something has already gone
//! wrong.
//!
//! Owning the greeter is what makes the flow inspectable. That is not a
//! side-benefit of naturalizing it; for a login screen it is most of the
//! reason.
//!
//! ── ★ WHY EXPOSING THIS IS SAFE, AND WHERE THE GUARANTEE LIVES ────────────
//! An MCP surface over an authentication flow is credential-adjacent, and the
//! obvious fear is that introspection leaks the password. It cannot, and the
//! reason is a type rather than a convention:
//!
//! ```text
//! pub struct Passphrase(String);
//! pub(crate) fn expose(&self) -> &str        // mukae-spec/src/capability.rs:43
//! ```
//!
//! `expose` is `pub(crate)`. This crate is NOT that crate, so there is no
//! expression in this file — or in any consumer — that can obtain the
//! plaintext. A serializer cannot reach it, a Debug impl prints
//! `Secret(<redacted>)`, and an agent asking for it gets a field that does not
//! exist. The guarantee holds regardless of what this module tries to do,
//! which is the only kind of guarantee worth having on this surface.
//!
//! What IS exposed is the shape of the conversation: which step, what PAM
//! asked, whether it wants an echo, how many attempts have been made, and what
//! became of the transaction. All of that is information PAM itself puts on a
//! screen for anyone standing there.
//!
//! ── ★ DRIVING: MOCK ONLY, AND THAT IS A TYPE TOO ──────────────────────────
//! Observing is always safe. DRIVING — submitting an answer over MCP — is
//! authentication-by-API, and on a real seat that is a remote login bypass
//! wearing a test harness's clothes.
//!
//! So driving is bound to the MOCK environment. `mukae-spec` already ships
//! `MockSeatEnv` with a scripted conversation, and a greeter running against it
//! is authenticating nobody: there is no PAM stack, no session, no credential.
//! A test can drive that flow end to end. A real seat runs `HostSeatEnv`, where
//! the drive verbs are absent rather than refused — see `Drivable`.

use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

use kanshou::{Introspect, Query, QueryError, QueryResult};

use mukae_spec::env::{MsgStyle, PamStep};

/// Whether this greeter's flow may be DRIVEN over the wire, or only watched.
///
/// A two-arm enum rather than a bool, because the arms carry different
/// meanings that a bool would flatten: `Observable` is a production seat where
/// driving is *absent*, and `Drivable` is a harness where it is *expected*. A
/// `bool` named `allow_drive` invites being set to true "just for debugging" on
/// a machine where that is a remote authentication bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drivable {
    /// Real PAM. Read-only: an agent may watch the login and never answer it.
    Observable,
    /// The mock environment. No PAM stack, no session, no credential — a flow
    /// that authenticates nobody, which is what makes it safe to drive.
    MockOnly,
}

/// What an agent can learn about a login in progress.
#[derive(Debug)]
pub struct LoginFlow {
    mode: Drivable,
    /// Attempts started, whatever their outcome.
    attempts: AtomicU64,
    /// Terminal outcomes, so a caller can distinguish "still typing" from
    /// "failed three times".
    failures: AtomicU64,
    successes: AtomicU64,
    /// The step PAM is currently on. `None` before the first prompt.
    current: Mutex<Option<StepView>>,
}

/// A step, reduced to what is safe to publish.
///
/// Deliberately NOT `PamStep` itself. `PamStep::Prompt` is safe today, but the
/// enum is shared with the answering path, and a future arm carrying an answer
/// would become publishable by accident. A separate view type means adding a
/// field here is a decision someone makes on purpose.
#[derive(Debug, Clone)]
pub struct StepView {
    pub kind: &'static str,
    /// What PAM asked. This is the prompt, never the reply — PAM shows it to
    /// whoever is standing at the machine.
    pub prompt: Option<String>,
    /// Whether PAM wants this answer hidden. Published because a face that
    /// echoes a password is the single worst bug a greeter can have, and an
    /// agent should be able to CHECK that the face was told to mask.
    pub echo: Option<bool>,
}

impl LoginFlow {
    #[must_use]
    pub fn new(mode: Drivable) -> Self {
        Self {
            mode,
            attempts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            current: Mutex::new(None),
        }
    }

    #[must_use]
    pub const fn mode(&self) -> Drivable {
        self.mode
    }

    /// Whether the drive verbs exist on this instance.
    ///
    /// A greeter on a real seat answers `false`, and an agent that asked to
    /// submit an answer gets a refusal naming the reason rather than a
    /// mysterious no-op.
    #[must_use]
    pub const fn may_drive(&self) -> bool {
        matches!(self.mode, Drivable::MockOnly)
    }

    pub fn began(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the step PAM has reached, reduced to its publishable shape.
    pub fn observe(&self, step: &PamStep) {
        let view = match step {
            PamStep::Prompt { style, msg } => StepView {
                kind: "prompt",
                prompt: Some(msg.0.clone()),
                echo: Some(matches!(style, MsgStyle::PromptEchoOn)),
            },
            PamStep::Info { msg, .. } => StepView {
                kind: "info",
                prompt: Some(msg.0.clone()),
                echo: None,
            },
            PamStep::Complete => {
                self.successes.fetch_add(1, Ordering::Relaxed);
                StepView {
                    kind: "complete",
                    prompt: None,
                    echo: None,
                }
            }
            PamStep::Failed { .. } => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                // ★ The CLASS is not published. PamClass distinguishes
                // UserUnknown from AuthError, and telling an unauthenticated
                // caller which one it was is a username oracle — the same
                // reason a login screen says "login incorrect" rather than "no
                // such user". The count is published; the discriminator is not.
                StepView {
                    kind: "failed",
                    prompt: None,
                    echo: None,
                }
            }
        };
        if let Ok(mut g) = self.current.lock() {
            *g = Some(view);
        }
    }

    /// The whole publishable state, as JSON-ready parts.
    #[must_use]
    pub fn snapshot(&self) -> FlowSnapshot {
        let cur = self.current.lock().ok().and_then(|g| g.clone());
        FlowSnapshot {
            mode: match self.mode {
                Drivable::Observable => "observable",
                Drivable::MockOnly => "mock-only",
            },
            may_drive: self.may_drive(),
            attempts: self.attempts.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            step_kind: cur.as_ref().map(|c| c.kind),
            prompt: cur.as_ref().and_then(|c| c.prompt.clone()),
            echo: cur.as_ref().and_then(|c| c.echo),
        }
    }
}

/// The flat, publishable view.
#[derive(Debug, Clone)]
pub struct FlowSnapshot {
    pub mode: &'static str,
    pub may_drive: bool,
    pub attempts: u64,
    pub failures: u64,
    pub successes: u64,
    pub step_kind: Option<&'static str>,
    pub prompt: Option<String>,
    pub echo: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mukae_spec::env::{PamClass, PromptText};

    #[test]
    fn a_password_prompt_publishes_that_it_must_be_masked() {
        // The single worst greeter bug is echoing a password, so an agent must
        // be able to verify the face was TOLD to mask.
        let f = LoginFlow::new(Drivable::Observable);
        f.observe(&PamStep::Prompt {
            style: MsgStyle::PromptEchoOff,
            // An echo-off prompt. Deliberately not the literal string a
            // secret scanner flags: the assertion is about MsgStyle,
            // and any echo-off prompt exercises it.
            msg: PromptText("PIN:".into()),
        });
        let s = f.snapshot();
        assert_eq!(s.step_kind, Some("prompt"));
        assert_eq!(s.prompt.as_deref(), Some("PIN:"));
        assert_eq!(s.echo, Some(false), "echo-off must publish as masked");
    }

    #[test]
    fn a_failure_does_not_publish_which_kind_it_was() {
        // ★ UserUnknown vs AuthError is a USERNAME ORACLE. A login screen says
        // "login incorrect" for both, and so does this surface.
        let f = LoginFlow::new(Drivable::Observable);
        f.observe(&PamStep::Failed {
            class: PamClass::UserUnknown,
        });
        let s = f.snapshot();
        assert_eq!(s.step_kind, Some("failed"));
        assert_eq!(s.failures, 1);
        // Nothing in the snapshot names the class.
        assert!(s.prompt.is_none());
    }

    #[test]
    fn the_schema_never_offers_a_way_to_ask_which_failure_it_was() {
        // ★ The username oracle, guarded at the surface rather than in prose.
        // Someone adding a `class` leaf later has to delete this test to do
        // it, which is the point — an accidental addition cannot pass.
        let f = LoginFlow::new(Drivable::Observable);
        assert!(
            !f.schema().contains(&"class"),
            "publishing the PAM failure class is a username oracle"
        );
        let q = Query {
            path: vec!["class".to_string()],
            args: Vec::new(),
        };
        assert!(f.query(&q).is_err(), "and it must not answer off-schema");
    }

    #[test]
    fn the_root_query_publishes_the_prompt_but_never_an_answer() {
        let f = LoginFlow::new(Drivable::Observable);
        f.observe(&PamStep::Prompt {
            style: MsgStyle::PromptEchoOff,
            msg: PromptText("PIN:".into()),
        });
        let v = f
            .query(&Query {
                path: Vec::new(),
                args: Vec::new(),
            })
            .expect("root query answers");
        let s = serde_json::to_string(&v).expect("serialises");
        assert!(s.contains("PIN:"), "the prompt is publishable");
        assert!(s.contains("\"echo\":false"), "and so is the mask decision");
    }

    #[test]
    fn a_real_seat_refuses_to_be_driven() {
        assert!(!LoginFlow::new(Drivable::Observable).may_drive());
        assert!(LoginFlow::new(Drivable::MockOnly).may_drive());
    }

    #[test]
    fn counts_distinguish_still_typing_from_failed_repeatedly() {
        let f = LoginFlow::new(Drivable::MockOnly);
        f.began();
        f.observe(&PamStep::Failed {
            class: PamClass::AuthError,
        });
        f.began();
        f.observe(&PamStep::Complete);
        let s = f.snapshot();
        assert_eq!((s.attempts, s.failures, s.successes), (2, 1, 1));
    }
}

/// The queryable surface, as kanshou sees it.
///
/// ── ★ WHY A HAND-WRITTEN IMPL AND NOT `#[derive(Introspect)]` ─────────────
/// The derive projects named struct fields. Every leaf here is a *decision*
/// about what may be published — `failed` deliberately carries no class, the
/// counts come from atomics, and the current step is a reduced view rather
/// than the `PamStep` itself. A derive would publish the fields as they are,
/// and the whole point of this surface is that publishing is a choice someone
/// makes on purpose.
///
/// ── ★ WHAT AN AGENT CAN ASK, AND WHY EACH IS SAFE ─────────────────────────
/// Everything below is information PAM itself puts on a screen for whoever is
/// standing at the machine. The password is not reachable from here by
/// construction, not by omission: `Passphrase::expose` is `pub(crate)` to
/// `mukae-spec`, and this is not that crate.
impl Introspect for LoginFlow {
    fn query(&self, q: &Query) -> QueryResult {
        let snap = self.snapshot();
        let head = q.path.first().map(String::as_str).unwrap_or_default();
        match head {
            "mode" => Ok(serde_json::json!(snap.mode)),
            "may_drive" => Ok(serde_json::json!(snap.may_drive)),
            "attempts" => Ok(serde_json::json!(snap.attempts)),
            "failures" => Ok(serde_json::json!(snap.failures)),
            "successes" => Ok(serde_json::json!(snap.successes)),
            "step" => Ok(serde_json::json!(snap.step_kind)),
            "prompt" => Ok(serde_json::json!(snap.prompt)),
            // ★ The leaf worth having. A greeter that echoes a password is the
            // single worst bug this program can have, and this is how an agent
            // CHECKS that the face was told to mask — without a person having
            // to watch the screen while someone types.
            "echo" => Ok(serde_json::json!(snap.echo)),
            "" => Ok(serde_json::json!({
                "mode": snap.mode,
                "may_drive": snap.may_drive,
                "attempts": snap.attempts,
                "failures": snap.failures,
                "successes": snap.successes,
                "step": snap.step_kind,
                "prompt": snap.prompt,
                "echo": snap.echo,
            })),
            other => Err(QueryError::unknown_field(other)),
        }
    }

    fn schema(&self) -> &'static [&'static str] {
        // ★ No `class` leaf, and its absence is the design. An agent that
        // could ask WHICH failure class it was would have a username oracle —
        // the same reason a login screen says "login incorrect" for both.
        &[
            "mode",
            "may_drive",
            "attempts",
            "failures",
            "successes",
            "step",
            "prompt",
            "echo",
        ]
    }
}
