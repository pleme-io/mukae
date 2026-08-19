//! # `(defmukae …)` — a login manager's configuration as data
//!
//! `theory/MUKAE.md` §4.2 designs this surface. This is it, written against
//! tatara-lisp's **measured** behaviour rather than its documented behaviour —
//! the two differ in three places, each recorded below where it bites.
//!
//! ## The shape
//!
//! ```lisp
//! (defmukae fleet-entrance
//!   :seats ((defseat :id "seat0"
//!             :console (defconsole :kind :vt :number 1 :switch :required
//!                                  :conflicts "getty@tty1.service")
//!             :greeter-user "mukae"
//!             :pam (defpam :user "mukae" :greeter "mukae-greeter"
//!                          :autologin "mukae-autologin")))
//!   :auth (defauthpolicy :name "default"
//!           :startup (defstartup :mode :greeter :restart :always)
//!           :retry (defretry :attempts 5 :window-secs 60 :backoff :exponential)))
//! ```
//!
//! ## Three measured corrections to §4.2's sketch
//!
//! **1. Every enum variant must be a SINGLE WORD.** `DeriveKeywordSexp`
//! lowercases the identifier with *no separator*, so `SealedMemfd` is
//! `:sealedmemfd` and never `:sealed-memfd`. Field names take the opposite
//! rule — `window_secs` IS `:window-secs`. §4.2's sketch uses
//! `:sealed-memfd`, `:physical-presence` and `:no-display` as *values*, and
//! none of those would parse. Two opposite conventions in one language, and a
//! design that assumes one rule for both produces forms that do not load.
//!
//! **2. A typo'd kwarg IS rejected on the derive path.** §4.2 says the silent
//! empty-`Vec` trap makes a lint "not optional here", and that is true of the
//! *manual* extraction path — but `DeriveTataraDomain` emits a
//! `__TATARA_ALLOWED_KEYWORDS` gate that errors with a did-you-mean. Measured
//! upstream in `tatara-lisp/tests/phase_f_constructs.rs`, and re-asserted here
//! for this domain because the claim is load-bearing: this spec has 20+
//! optional keywords, and a partial-but-green parse of a login config is a
//! machine nobody can log into.
//!
//! **3. There is no map and no vector.** A collection is a bare parenthesised
//! run of forms, which is why `:seats` holds `(defseat …)` forms rather than
//! anything list-shaped, and why every nested value is its own named domain.
//!
//! ## What lowering enforces that the lisp cannot
//!
//! A `(def…)` form is data; the invariants live in the lowering. Two matter:
//!
//! - **A VT console on a non-`seat0` seat is refused.** VTs exist only on
//!   seat0 (world-fact W8), and `mukae_spec::ConsoleBinding::vt` demands a
//!   `Seat0Witness` that only `SeatId::as_seat0()` mints. Lisp has no way to
//!   carry a witness, so the check happens exactly where the witness is
//!   obtained — at the boundary, as a typed error, not a runtime branch later.
//! - **Autologin cannot co-exist with restart-on-exit.** greetd ships these as
//!   a boolean pair that must not both be set; here `Startup` is a sum whose
//!   autologin arm has no `restart` field, so the illegal combination has no
//!   representation to lower FROM.

pub mod catalog;
pub use catalog::{
    Absence, CatalogError, Epoch, FaceForm, FaceKind, FactForm, Handoff, HandoffForm, HonorForm,
    Honored, Resolution, SessionCatalog, SessionsForm, Transport, Volatility,
};

use mukae_spec::ids::{IdError, SeatId, ServiceName, UserName};
use tatara_lisp::{DeriveKeywordSexp, DeriveTataraDomain, KeywordSexp, TataraDomain};

/// What kind of console a seat has.
///
/// Single-word variants, deliberately — see this module's correction 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum ConsoleKind {
    /// A virtual terminal. Legal only on `seat0`.
    Vt,
    /// No console at all — the shape every non-seat0 seat has.
    Seatless,
}

/// Whether the entrance may take the VT from whatever holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum SwitchPolicy {
    /// Take it; a getty holding the VT is stopped.
    Required,
    /// Use it only if free.
    Opportunistic,
}

/// What starts on a seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum StartupMode {
    Greeter,
    Autologin,
}

/// When a greeter that exits is started again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum RestartPolicy {
    Always,
    Never,
}

/// How the delay between attempts grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum Backoff {
    Fixed,
    Exponential,
}

/// A seat's console binding, as authored.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defconsole")]
pub struct ConsoleForm {
    #[tatara(keyword_enum)]
    pub kind: ConsoleKind,
    /// The VT number. Meaningless unless `kind` is `:vt`, and the lowering
    /// says so rather than ignoring it — a config with a VT number on a
    /// seatless console is a config whose author believed something false.
    pub number: Option<u32>,
    #[tatara(keyword_enum)]
    pub switch: Option<SwitchPolicy>,
    /// The systemd unit that must not hold this VT.
    pub conflicts: Option<String>,
}

/// The three PAM services, which are three DIFFERENT services.
///
/// Authored as one form because they belong together; lowered into three
/// distinct types so that passing the greeter service where the user service
/// belongs is a compile error rather than a config review.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defpam")]
pub struct PamForm {
    pub user: String,
    pub greeter: String,
    pub autologin: String,
}

/// One seat.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defseat")]
pub struct SeatForm {
    pub id: String,
    #[tatara(domain)]
    pub console: ConsoleForm,
    pub greeter_user: String,
    #[tatara(domain)]
    pub pam: PamForm,
}

/// What starts, and what happens when it stops.
///
/// ★ THE greetd BUG, TYPED AWAY — as far as a data language can. greetd's
/// `restart` defaults to `!(initial_session)`, a boolean pair that must not
/// both be set, and its own nix module carries the coupling by hand. Here
/// `restart` is meaningful only when `mode` is `:greeter`, and the LOWERING
/// refuses the other combination outright, because `mukae_spec`'s `Startup` is
/// a sum whose autologin arm has no `restart` field to lower into.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defstartup")]
pub struct StartupForm {
    #[tatara(keyword_enum)]
    pub mode: StartupMode,
    #[tatara(keyword_enum)]
    pub restart: Option<RestartPolicy>,
    /// Who is logged in automatically. Required when mode is `:autologin`.
    pub user: Option<String>,
}

/// How many attempts, how fast.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defretry")]
pub struct RetryForm {
    pub attempts: u32,
    pub window_secs: u32,
    #[tatara(keyword_enum)]
    pub backoff: Backoff,
}

/// The authentication policy.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defauthpolicy")]
pub struct AuthPolicyForm {
    pub name: String,
    #[tatara(domain)]
    pub startup: StartupForm,
    #[tatara(domain)]
    pub retry: RetryForm,
}

/// A whole entrance.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defmukae")]
pub struct MukaeForm {
    pub name: String,
    /// `Vec<T>` is a bare parenthesised run of forms — the only table
    /// construct the language has, since it offers neither a map nor a vector.
    #[tatara(domain)]
    pub seats: Vec<SeatForm>,
    #[tatara(domain)]
    pub auth: AuthPolicyForm,
    /// Where sessions come from. Optional: a machine with a single fixed
    /// session needs no catalog, and demanding one would make the simple
    /// case verbose to no purpose.
    #[tatara(domain)]
    pub catalog: Option<catalog::SessionsForm>,
    /// The greeter -> session handoff. Optional, and its absence is a
    /// SUPPORTED configuration rather than a degraded one — see
    /// `catalog::Absence`, where every path resolves to an empty dict and the
    /// session simply probes for itself.
    #[tatara(domain)]
    pub handoff: Option<catalog::HandoffForm>,
    /// Which faces render. Optional; a headless CI entrance declares one.
    #[tatara(domain)]
    pub faces: Vec<catalog::FaceForm>,
}

// ── The lowered, typed shapes ─────────────────────────────────────────

/// A console binding after lowering, with world-fact W8 enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Console {
    /// A VT. Reachable only for `seat0`, and the `SeatId` that proved it is
    /// kept so a later consumer does not have to re-derive the fact.
    Vt {
        number: u32,
        switch: SwitchPolicy,
        conflicts: Option<String>,
    },
    Seatless,
}

/// What starts on a seat, as a SUM.
///
/// The autologin arm has no `restart` field. That is the whole mechanism for
/// illegal state [10]: the combination greetd has to guard against by hand has
/// no representation here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    Greeter { restart: RestartPolicy },
    Autologin { user: UserName },
}

/// A lowered seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    pub id: SeatId,
    pub console: Console,
    pub greeter_user: UserName,
    pub pam_user: ServiceName,
    pub pam_greeter: ServiceName,
    pub pam_autologin: ServiceName,
}

/// A lowered entrance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mukae {
    pub name: String,
    pub seats: Vec<Seat>,
    pub startup: Startup,
    pub retry_attempts: u32,
    pub retry_window_secs: u32,
    pub backoff: Backoff,
}

#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    #[error("reading the form: {0}")]
    Read(String),
    #[error("no forms in source")]
    Empty,
    #[error("{0}")]
    Id(#[from] IdError),
    /// ★ World-fact W8. Lisp cannot carry a `Seat0Witness`, so this is where
    /// the fact is checked — at the one boundary where the witness is minted.
    #[error(
        "seat {seat:?} declares a VT console, but VTs exist only on seat0; \
         use (defconsole :kind :seatless) on a non-seat0 seat"
    )]
    VtOnNonSeat0 { seat: String },
    #[error("seat {seat:?} declares :kind :vt without a :number")]
    VtWithoutNumber { seat: String },
    #[error(
        "seat {seat:?} declares :kind :seatless but also a VT :number — a \
         seatless console has no VT, so one of the two is a mistaken belief"
    )]
    SeatlessWithVtFields { seat: String },
    #[error(
        ":startup declares :mode :autologin with a :restart policy. greetd \
         ships these as a boolean pair that must not both be set; here the \
         autologin arm has no restart field, so drop one"
    )]
    AutologinWithRestart,
    #[error(":startup declares :mode :autologin without a :user")]
    AutologinWithoutUser,
    #[error(":startup declares :mode :greeter with a :user; greeters have none")]
    GreeterWithUser,
    #[error("a mukae declaration must have at least one seat")]
    NoSeats,
    #[error("seat {0:?} is declared twice")]
    DuplicateSeat(String),
}

impl MukaeForm {
    /// Parse one `(defmukae …)` form.
    ///
    /// # Errors
    /// [`LowerError::Read`] on a parse or compile failure — including a typo'd
    /// keyword, which the derive rejects with a did-you-mean rather than
    /// silently producing an empty field.
    pub fn from_source(src: &str) -> Result<Self, LowerError> {
        let forms = tatara_lisp::read(src).map_err(|e| LowerError::Read(e.to_string()))?;
        let first = forms.first().ok_or(LowerError::Empty)?;
        Self::compile_from_sexp(first).map_err(|e| LowerError::Read(e.to_string()))
    }

    /// Lower to the typed shape, enforcing what the data language cannot.
    ///
    /// # Errors
    /// [`LowerError`] naming the exact seat or field at fault.
    pub fn lower(&self) -> Result<Mukae, LowerError> {
        if self.seats.is_empty() {
            return Err(LowerError::NoSeats);
        }

        let mut seats = Vec::with_capacity(self.seats.len());
        let mut seen: Vec<String> = Vec::new();
        for s in &self.seats {
            if seen.contains(&s.id) {
                return Err(LowerError::DuplicateSeat(s.id.clone()));
            }
            seen.push(s.id.clone());
            seats.push(Self::lower_seat(s)?);
        }

        let startup = match (self.auth.startup.mode, &self.auth.startup.user) {
            (StartupMode::Greeter, Some(_)) => return Err(LowerError::GreeterWithUser),
            (StartupMode::Greeter, None) => Startup::Greeter {
                // A greeter with no declared restart policy restarts. A
                // greeter that exits and stays gone is a machine with no way
                // in, so the default has to be the recoverable one.
                restart: self.auth.startup.restart.unwrap_or(RestartPolicy::Always),
            },
            (StartupMode::Autologin, _) if self.auth.startup.restart.is_some() => {
                return Err(LowerError::AutologinWithRestart);
            }
            (StartupMode::Autologin, None) => return Err(LowerError::AutologinWithoutUser),
            (StartupMode::Autologin, Some(u)) => Startup::Autologin {
                user: UserName::parse(u)?,
            },
        };

        Ok(Mukae {
            name: self.name.clone(),
            seats,
            startup,
            retry_attempts: self.auth.retry.attempts,
            retry_window_secs: self.auth.retry.window_secs,
            backoff: self.auth.retry.backoff,
        })
    }

    fn lower_seat(s: &SeatForm) -> Result<Seat, LowerError> {
        let id = SeatId::parse(&s.id)?;
        let console = match s.console.kind {
            ConsoleKind::Vt => {
                // ★ The witness IS the check. `as_seat0` is the only producer,
                // and it returns None for every other seat.
                if id.as_seat0().is_none() {
                    return Err(LowerError::VtOnNonSeat0 { seat: s.id.clone() });
                }
                let number = s
                    .console
                    .number
                    .ok_or(LowerError::VtWithoutNumber { seat: s.id.clone() })?;
                Console::Vt {
                    number,
                    switch: s.console.switch.unwrap_or(SwitchPolicy::Opportunistic),
                    conflicts: s.console.conflicts.clone(),
                }
            }
            ConsoleKind::Seatless => {
                // A seatless console carrying VT fields is not harmless — it
                // is an author who believes this seat has a VT. Say so.
                if s.console.number.is_some() || s.console.conflicts.is_some() {
                    return Err(LowerError::SeatlessWithVtFields { seat: s.id.clone() });
                }
                Console::Seatless
            }
        };
        Ok(Seat {
            id,
            console,
            greeter_user: UserName::parse(&s.greeter_user)?,
            pam_user: ServiceName::parse(&s.pam.user)?,
            pam_greeter: ServiceName::parse(&s.pam.greeter)?,
            pam_autologin: ServiceName::parse(&s.pam.autologin)?,
        })
    }
}
