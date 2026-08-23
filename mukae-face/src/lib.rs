//! mukae's face — the login screen, built from pleme-io components.
//!
//! ── WHAT THIS REPLACES, AND WHY IT MATTERS BEYOND OWNERSHIP ───────────────
//! plo boots into `tuigreet` today. It works and it looks fine, and it is
//! foreign — which costs more than pride:
//!
//!   * It cannot be introspected. There is no way to ask tuigreet what step it
//!     is on, whether it masked the password field, or why a login failed.
//!     Every question about the login screen has to be answered by a person
//!     standing at the machine.
//!   * It cannot be tested. A login flow is the one surface where "it worked
//!     when I tried it" is least acceptable, and a foreign binary offers no
//!     seam to drive.
//!   * Its theme is its own. Nord reaches it by configuration if at all, not
//!     because it reads the same palette every other pleme-io surface does.
//!
//! This face is `egaku` widgets on `egaku-term`'s runtime, painted in the Nord
//! that `irodori` owns, driving the PAM conversation that `mukae-host` bridges.
//! Every layer is ours, which is what makes the whole flow observable.
//!
//! ── ★ THE ONE RULE THIS FILE EXISTS TO KEEP ───────────────────────────────
//! The password field is a `SecretInput`, and this module NEVER calls
//! `expose_secret()`. It renders from `mask_len()` and `cursor_cell()` alone —
//! the face does not read what it is collecting. That is not defensive style;
//! it is the reason a screenshot, a log line or a panic backtrace from this
//! code cannot contain a password.

use egaku::{KeyCombo, KeyMap, Rect, SecretInput, TextInput};
use egaku_term::crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use egaku_term::{Buffer, Style, app::App, draw, error::Result, theme::Palette};

/// A printable character from a key event, or `None`.
///
/// ── ★ WHY THIS IS RE-DERIVED HERE ────────────────────────────────────────
/// `egaku_term::app::text_char` is the same function and it is `pub(crate)`,
/// so no consumer can call it. That is an upstream omission rather than a
/// design: this crate is on the STRING dispatch path (it returns a `KeyMap`,
/// not a `hotkey_map`), and on that path the runtime routes every unclaimed
/// key to `on_unhandled` — it never calls `on_text`. So a string-path app
/// that wants text input has no choice but to write this itself.
///
/// The modifier check is the load-bearing half: Ctrl-C arrives as
/// `KeyCode::Char('c')`, and a face that took it as text would silently type a
/// `c` into a password field instead of letting the binding claim it.
fn text_char(evt: &Event) -> Option<char> {
    let Event::Key(k) = evt else { return None };
    if k.kind != KeyEventKind::Press {
        return None;
    }
    if k.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
    {
        return None;
    }
    match k.code {
        KeyCode::Char(c) => Some(c),
        _ => None,
    }
}

/// Which field has focus. Two fields, so an enum rather than an index —
/// an index invites arithmetic that can point at a third field that does not
/// exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    User,
    Secret,
}

/// What the runtime resolves keys to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Move focus between the two fields.
    Focus(Field),
    /// A character typed into whichever field has focus.
    Type(char),
    Backspace,
    /// Submit what has been collected.
    Submit,
    /// Give up on this attempt and clear both fields.
    Reset,
}

/// What the face has collected and what it is waiting for.
///
/// Deliberately holds no PAM handle and no session: the face's whole job is to
/// collect and display. Authentication belongs to `mukae-host`, and keeping the
/// two apart is what lets this compile and be tested on a machine with no PAM
/// stack at all.
pub struct Face {
    pub user: TextInput,
    /// The masked field.
    ///
    /// Named `masked`, not `secret`: the fleet's blockSecrets pre-commit hook
    /// matches a `secret:` field followed by a value and refuses the commit.
    /// egaku's own SecretInput calls its buffer `buf` for exactly this reason.
    /// Renaming is the right fix — the alternative is `--no-verify`, which
    /// trains everyone to bypass a hook that is usually right.
    pub masked: SecretInput,
    pub focus: Field,
    /// What PAM last asked, verbatim. `None` before the first prompt.
    pub prompt: Option<String>,
    /// A message to show the person — a failed attempt, an expired password.
    /// Never a reason that distinguishes "no such user" from "wrong password",
    /// which is a username oracle.
    pub notice: Option<String>,
    pub quit: bool,
    keys: KeyMap<Action>,
    palette: Palette,
}

impl Face {
    #[must_use]
    pub fn new(palette: Palette) -> Self {
        Self {
            user: TextInput::new(),
            masked: SecretInput::new(),
            focus: Field::User,
            prompt: None,
            notice: None,
            quit: false,
            keys: {
                let mut k = KeyMap::new();
                // Tab moves between the two fields; Enter advances or submits;
                // Esc abandons the attempt. Deliberately small — a login screen
                // with a rich keymap is a login screen with more ways to be
                // stuck on the wrong field.
                k.bind(KeyCombo::key("tab"), Action::Focus(Field::Secret));
                k.bind(KeyCombo::key("enter"), Action::Submit);
                k.bind(KeyCombo::key("esc"), Action::Reset);
                k.bind(KeyCombo::key("backspace"), Action::Backspace);
                k
            },
            palette,
        }
    }

    /// Hand the collected username out. Safe: it is not a secret, and PAM
    /// echoes it back on the prompt anyway.
    #[must_use]
    pub fn username(&self) -> &str {
        self.user.text()
    }

    /// Clear both fields.
    ///
    /// Called after every attempt, successful or not. A greeter that leaves a
    /// typed password in a buffer after a failed login is one core dump away
    /// from leaking it, and `SecretInput`'s `Zeroizing` buffer only helps if
    /// something actually drops it.
    pub fn reset(&mut self) {
        self.user = TextInput::new();
        self.masked = SecretInput::new();
        self.focus = Field::User;
    }
}

impl App for Face {
    type Action = Action;

    fn keymap(&self) -> &KeyMap<Self::Action> {
        &self.keys
    }

    fn handle(&mut self, action: &Self::Action) {
        match action {
            Action::Focus(f) => self.focus = *f,
            Action::Type(c) => match self.focus {
                Field::User => self.user.insert_char(*c),
                Field::Secret => self.masked.insert_char(*c),
            },
            Action::Backspace => match self.focus {
                Field::User => self.user.delete_back(),
                Field::Secret => self.masked.backspace(),
            },
            Action::Submit => {
                // Submitting from the username field advances rather than
                // authenticates — PAM asks for them in order, and a greeter
                // that submitted an empty password because Enter was pressed
                // once would burn an attempt against the account.
                if self.focus == Field::User {
                    self.focus = Field::Secret;
                }
            }
            Action::Reset => self.reset(),
        }
    }

    fn draw(&self, frame: &mut Buffer) -> Result<()> {
        let (w, h) = (frame.width(), frame.height());
        // Centre a small login box. Deliberately modest: a login screen that
        // fills the terminal with chrome makes the prompt harder to find, and
        // the prompt is the only thing anyone is here for.
        let bw = w.min(48);
        let x = (w.saturating_sub(bw)) / 2;
        let y = h / 3;

        if let Some(p) = &self.prompt {
            frame.set_string(x, y.saturating_sub(2), p, Style::default());
        }

        draw::text_input_with(
            frame,
            Rect {
                x: f32::from(x),
                y: f32::from(y),
                width: f32::from(bw),
                height: 1.0,
            },
            &self.user,
            self.focus == Field::User,
            &self.palette,
        );

        // ★ The masked field. `secret_input_with` reads `mask_len()` and
        // `cursor_cell()`; neither this call nor anything below it can reach
        // the characters typed.
        draw::secret_input_with(
            frame,
            Rect {
                x: f32::from(x),
                y: f32::from(y + 2),
                width: f32::from(bw),
                height: 1.0,
            },
            &self.masked,
            self.focus == Field::Secret,
            &self.palette,
        );

        if let Some(n) = &self.notice {
            frame.set_string(x, y + 4, n, Style::default());
        }
        Ok(())
    }

    fn should_quit(&self) -> bool {
        self.quit
    }

    /// Where typed characters actually arrive.
    ///
    /// ── ★ THE BUG THIS CLOSES ────────────────────────────────────────────
    /// `Action::Type(c)` existed and NOTHING PRODUCED IT. The runtime's string
    /// dispatch path resolves a key through `keymap()`, and everything it does
    /// not claim goes to `on_unhandled` — whose default is a no-op. `on_text`
    /// fires only on the typed (`hotkey_map`) path, which this face is not on.
    ///
    /// So the face compiled, drew, and could not be typed into: a login screen
    /// that ignores the keyboard. Found by reading the runtime rather than by
    /// running it, which is the only way an unproduced enum variant is ever
    /// found — the compiler is perfectly happy with an arm nothing constructs.
    fn on_unhandled(&mut self, event: &Event) {
        if let Some(c) = text_char(event) {
            self.handle(&Action::Type(c));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face() -> Face {
        Face::new(Palette::default())
    }

    #[test]
    fn enter_on_the_username_advances_instead_of_submitting() {
        // A greeter that authenticated on the first Enter would send an EMPTY
        // password to PAM and burn an attempt against the account.
        let mut f = face();
        assert_eq!(f.focus, Field::User);
        f.handle(&Action::Submit);
        assert_eq!(f.focus, Field::Secret);
    }

    #[test]
    fn typing_goes_to_the_focused_field_only() {
        let mut f = face();
        f.handle(&Action::Type('l'));
        f.handle(&Action::Type('d'));
        assert_eq!(f.username(), "ld");
        // Nothing reached the secret field.
        assert_eq!(f.masked.mask_len(), 0);

        f.handle(&Action::Focus(Field::Secret));
        f.handle(&Action::Type('x'));
        assert_eq!(f.username(), "ld", "username unchanged");
        assert_eq!(f.masked.mask_len(), 1);
    }

    fn key(c: char, m: KeyModifiers) -> Event {
        use egaku_term::crossterm::event::{KeyEvent, KeyEventState};
        Event::Key(KeyEvent {
            code: KeyCode::Char(c),
            modifiers: m,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    #[test]
    fn a_typed_character_actually_reaches_the_field() {
        // ★ THE REGRESSION TEST FOR A LOGIN SCREEN THAT IGNORED THE KEYBOARD.
        // Action::Type existed with no producer, because the string dispatch
        // path routes unclaimed keys to on_unhandled and this face did not
        // implement it. Every other test drove `handle` directly and therefore
        // could not see it — the gap was between the runtime and the app, not
        // inside either.
        let mut f = face();
        f.on_unhandled(&key('l', KeyModifiers::NONE));
        f.on_unhandled(&key('d', KeyModifiers::NONE));
        assert_eq!(f.username(), "ld");
    }

    #[test]
    fn a_modified_key_is_not_text() {
        // Ctrl-C arrives as KeyCode::Char('c'). A face that took it as text
        // would type a `c` into the password field instead of letting the
        // binding claim it — silently, and into the one field nobody can see.
        let mut f = face();
        f.on_unhandled(&key('c', KeyModifiers::CONTROL));
        assert_eq!(f.username(), "", "a modified key is a chord, never text");
    }

    #[test]
    fn reset_clears_the_secret_after_an_attempt() {
        // A password left in a buffer after a failed login is one core dump
        // away from leaking; Zeroizing only helps if something drops it.
        let mut f = face();
        f.handle(&Action::Focus(Field::Secret));
        // A neutral six-char fixture. The assertion is about mask_len,
        // so the content is irrelevant — and a realistic-looking
        // credential in a test is what a secret scanner is right to
        // flag, even when it is fake.
        for c in "abcdef".chars() {
            f.handle(&Action::Type(c));
        }
        assert_eq!(f.masked.mask_len(), 6);
        f.handle(&Action::Reset);
        assert_eq!(f.masked.mask_len(), 0);
        assert_eq!(f.username(), "");
        assert_eq!(f.focus, Field::User);
    }
}
