//! The driver: a face on one side, a real PAM conversation on the other.
//!
//! ── ★ WHY THIS LIVES IN THE BINARY AND NOT IN mukae-face ──────────────────
//! `mukae-face` must build anywhere. It is the half that can be tested without
//! a PAM stack, a seat, or a Linux kernel, and that property is the reason the
//! face has unit tests at all. `mukae-host` is `linux`-only by construction.
//! The binary is where they are allowed to meet, so this module is
//! `cfg(target_os = "linux")` and the face stays portable.
//!
//! ── ★ PAM DECIDES WHICH FIELD, NOT THE LAYOUT ─────────────────────────────
//! A login box looks like username-then-password, and it is tempting to drive
//! it that way: read both fields, hand them over in order. That is wrong, and
//! wrong in the direction that matters — the PAM stack decides what it asks
//! for and in what order. A stack with a second factor asks three times; one
//! with an OTP asks for something that is neither a username nor a password;
//! one configured for autologin asks nothing at all.
//!
//! So the routing key is `MsgStyle`, PAM's own answer to "may this be echoed":
//! `PromptEchoOn` goes to the visible field, `PromptEchoOff` to the masked one.
//! The face keeps its two-field *appearance* — which is what a person expects
//! to see — while what is actually collected is whatever PAM asked for.
//! Collapsing the two styles is the mechanism by which a greeter echoes a
//! password, which is why `MsgStyle` distinguishes them in the first place.

use std::sync::Arc;

use egaku_term::app::App;
use egaku_term::crossterm::event::Event;
use egaku_term::{Buffer, error::Result};
use mukae::introspect::LoginFlow;
use mukae_face::{Action, Face, Field};
#[cfg(feature = "pam")]
use mukae_host::authenticate::authenticate;
// ★ From mukae-spec, not mukae-host. That move is what lets the greeter drop
// libpam entirely: the conversation type never needed it.
use mukae_spec::bridge::Bridge;
use mukae_spec::capability::Passphrase;
use mukae_spec::env::{MsgStyle, PamAnswer, PamStep};
use mukae_spec::ids::ServiceName;

/// What became of the login, once the loop is over.
///
/// Deliberately NOT a `bool`. `Authenticated` is a statement about PAM having
/// returned success; `Abandoned` is a person pressing Escape; `Refused` is a
/// wrong answer. A bool would flatten the last two into "false" and let a
/// caller treat a cancelled login as a failed one — which matters because
/// failed logins get counted and cancelled ones must not be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// PAM authenticated the person. **This is not a session** — see the
    /// binary's help text and `pending-mukae-session`.
    Authenticated,
    /// PAM refused. The class is deliberately not carried: distinguishing
    /// "no such user" from "wrong password" for a caller is a username oracle.
    Refused,
    /// The person walked away. Not a failure and must never be counted as one.
    Abandoned,
}

/// A face driving a live PAM transaction.
pub struct Session {
    face: Face,
    bridge: Bridge,
    /// The style of the prompt PAM is currently blocked on. `None` means PAM
    /// is not waiting for us — the conversation is over.
    awaiting: Option<MsgStyle>,
    verdict: Option<Verdict>,
    service: ServiceName,
    /// ★ The observation surface, shared with the kanshou sidecar thread.
    ///
    /// Every step is reported here as well as drawn. That is what makes the
    /// login flow answerable over MCP — and it is the reason naturalizing the
    /// greeter was worth doing at all: tuigreet draws a prompt and there is no
    /// way to ask it what step it is on, whether it masked the field, or why a
    /// login failed. Those questions have cost a person standing at the
    /// machine every single time.
    flow: Arc<LoginFlow>,
}

impl Session {
    /// Start a transaction and pull PAM's first prompt.
    ///
    /// # Errors
    /// The reason the transaction could not be started at all.
    /// Drive a conversation that some other transport already started.
    ///
    /// ── ★ THE CONSTRUCTOR THAT PROVES THE ABSTRACTION ────────────────────
    /// `Bridge` is the conversation, not the PAM bridge, so a session does not
    /// need to know where its prompts come from. This takes one from anywhere
    /// — libpam via `authenticate`, greetd via `mukae_greetd::connect` — and
    /// everything downstream is byte-identical: the same face, the same
    /// routing by `MsgStyle`, the same undifferentiated failure message, the
    /// same published surface.
    ///
    /// The `service` field is left as a diagnostic label. A greetd
    /// conversation has no PAM service of its own to name — greetd chose one —
    /// so claiming one here would be a fact this program does not have.
    pub fn from_bridge(face: Face, bridge: Bridge, flow: Arc<LoginFlow>) -> Self {
        flow.began();
        let mut s = Self {
            face,
            bridge,
            awaiting: None,
            verdict: None,
            service: ServiceName::parse("greetd").unwrap_or_else(|_| {
                unreachable!("`greetd` is a bare name and always parses")
            }),
            flow,
        };
        s.pump();
        s
    }

    #[cfg(feature = "pam")]
    pub fn start(
        face: Face,
        service: ServiceName,
        flow: Arc<LoginFlow>,
    ) -> std::result::Result<Self, String> {
        // ★ No username is passed in. PAM asks for it, through the same
        // conversation as everything else — which is what lets a stack that
        // wants no username, or three factors, work without this code knowing.
        let bridge = authenticate(&service, None)?;
        flow.began();
        let mut s = Self {
            face,
            bridge,
            awaiting: None,
            verdict: None,
            service,
            flow,
        };
        s.pump();
        Ok(s)
    }

    /// The verdict, once the loop has exited.
    #[must_use]
    pub const fn verdict(&self) -> Option<Verdict> {
        self.verdict
    }

    /// Take one step of the conversation and reflect it on the face.
    ///
    /// Called after every answer. Loops over `Info` steps rather than
    /// returning on them, because PAM emits messages between prompts and a
    /// face that stopped on each would need a keypress to acknowledge
    /// something the person did not ask about.
    fn pump(&mut self) {
        loop {
            let step = self.bridge.next();
            // ★ Observed BEFORE it is rendered. An agent watching a login that
            // is failing to come up must see the step the face is stuck on,
            // and a surface updated after the draw would be one step behind
            // exactly when that matters.
            self.flow.observe(&step);
            match step {
                PamStep::Prompt { style, msg } => {
                    self.face.prompt = Some(msg.0);
                    self.awaiting = Some(style);
                    // The field follows PAM's echo decision, not the layout.
                    self.face.focus = match style {
                        MsgStyle::PromptEchoOff => Field::Secret,
                        _ => Field::User,
                    };
                    return;
                }
                PamStep::Info { msg, .. } => {
                    // Shown and stepped past. A person reads it; nothing is
                    // owed in reply.
                    self.face.notice = Some(msg.0);
                }
                PamStep::Complete => {
                    self.verdict = Some(Verdict::Authenticated);
                    self.awaiting = None;
                    self.face.quit = true;
                    return;
                }
                PamStep::Failed { .. } => {
                    // ★ One message for every failure class. PAM knows whether
                    // the user existed; the screen must not say so, and neither
                    // must the notice, because a person watching the difference
                    // learns which usernames are real.
                    self.face.notice = Some("Login incorrect".to_string());
                    self.verdict = Some(Verdict::Refused);
                    self.awaiting = None;
                    self.face.quit = true;
                    return;
                }
            }
        }
    }

    /// Hand PAM the answer for the prompt it is blocked on.
    fn submit(&mut self) {
        let Some(style) = self.awaiting else { return };

        let answer = match style {
            // ★ THE ONE PLACE A SECRET IS READ, IN THE WHOLE PROGRAM.
            // `expose_secret` is called here and nowhere else, and its result
            // moves straight into a `Passphrase` — whose only reader is
            // `pub(crate)` to mukae-spec. So the plaintext exists as a `&str`
            // for the length of one expression and is unreachable on either
            // side of it. The face never calls this; that is why a screenshot
            // or a panic backtrace from the drawing code cannot contain a
            // password.
            MsgStyle::PromptEchoOff => {
                PamAnswer::Secret(Passphrase::new(self.face.masked.expose_secret().to_string()))
            }
            _ => PamAnswer::Visible(self.face.username().to_string()),
        };

        if self.bridge.answer(answer).is_err() {
            // The worker is gone, so there is nothing to answer. Same
            // undifferentiated message as any other failure.
            self.face.notice = Some("Login incorrect".to_string());
            self.verdict = Some(Verdict::Refused);
            self.awaiting = None;
            self.face.quit = true;
            return;
        }

        // Clear the masked field the instant it has been handed over. A
        // Zeroizing buffer only helps if something drops it, and leaving an
        // answered password on screen-state until the next reset is exactly
        // the window a core dump lands in.
        if style == MsgStyle::PromptEchoOff {
            self.face.masked = egaku::SecretInput::new();
        }
        self.pump();
    }
}

impl App for Session {
    type Action = Action;

    fn keymap(&self) -> &egaku::KeyMap<Self::Action> {
        self.face.keymap()
    }

    fn handle(&mut self, action: &Self::Action) {
        match action {
            // Submit means "answer PAM", not "move focus". The face's own
            // advance-on-enter behaviour is for the standalone, PAM-less run;
            // here the conversation decides what comes next.
            Action::Submit => self.submit(),
            Action::Reset => {
                // Escape abandons. NOT a refusal — a person who walked away
                // has not failed a login, and counting it as one is how a
                // lockout policy punishes someone for changing their mind.
                self.verdict = Some(Verdict::Abandoned);
                self.face.reset();
                self.face.quit = true;
            }
            other => self.face.handle(other),
        }
    }

    fn draw(&self, frame: &mut Buffer) -> Result<()> {
        self.face.draw(frame)
    }

    fn should_quit(&self) -> bool {
        self.face.should_quit()
    }

    fn on_unhandled(&mut self, event: &Event) {
        self.face.on_unhandled(event);
    }
}

impl Session {
    /// The service this transaction runs against — for diagnostics only.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }
}
