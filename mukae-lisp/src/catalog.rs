//! `(defsessions …)`, `(defhandoff …)` and `:faces` — the three forms
//! `theory/MUKAE.md` §4.2 sketches and the last pass did not ship.
//!
//! ## What is real here and what is a declaration
//!
//! - **`(defsessions …)`** — session discovery. The *rules* are typed and the
//!   *reader* is a mockable seam, so this is live in the same sense the login
//!   conversation is: the logic is proven, the real filesystem impl is M3.
//! - **`:faces`** — which face renders at which tier. Pure data, fully live.
//! - **`(defhandoff …)`** — **a DECLARATION.** The envelope's typed shape and
//!   its invariants are here; the layer that feeds it into a config fold is
//!   NOT, and cannot be until shikumi grows an `Attested` tier (§5.5's S1,
//!   measured at ~1453 `ConfigTierKind` sites). Saying the handoff is
//!   *declarable* is true; saying it *works* would not be.
//!
//! ## The design's sharpest idea, made unrepresentable rather than discouraged
//!
//! > *A fact whose validity window is shorter than the handoff latency is not
//! > configuration — it is a sensor.*
//!
//! Battery and thermal change between greet and session by construction, so
//! handing them over as resolved config is a category error. §5.2 says the
//! envelope's schema therefore "has no battery field and no thermal field" and
//! calls that truly-unrepresentable.
//!
//! [`Volatility`] is the mechanism: it has **no `Sensor` arm**. A fact that
//! changes faster than the handoff cannot be *described*, so it cannot be
//! declared. That is a closed enum doing the work, not a validation pass.

use mukae_spec::ids::IdError;
use tatara_lisp::{DeriveKeywordSexp, DeriveTataraDomain, KeywordSexp, TataraDomain};

/// Which XDG hints a session catalog honours.
///
/// ★ THREE NAMED FLAGS, NOT A LIST — and that is a modelling correction to
/// §4.2, which writes `:honor (:hidden :no-display :try-exec)`. A list implies
/// an open set that may grow; the XDG Desktop Entry spec defines exactly these
/// three and no more. As a product of three optionals, an unknown hint has no
/// place to go and the same hint cannot be named twice.
///
/// (The derive also refuses `#[tatara(keyword_enum)]` on a `Vec`, which is
/// what surfaced the question — but the flags are the better shape on their
/// own merits, not a workaround.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, DeriveTataraDomain)]
#[tatara(keyword = "defhonor")]
pub struct HonorForm {
    /// `Hidden=true` — the entry is deleted as far as the user is concerned.
    pub hidden: Option<bool>,
    /// `NoDisplay=true` — real, but not offered in a menu.
    pub no_display: Option<bool>,
    /// `TryExec=` — offer only if the named binary resolves.
    pub try_exec: Option<bool>,
}

/// The lowered hint set. Every field decided, no optionals left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Honored {
    pub hidden: bool,
    pub no_display: bool,
    pub try_exec: bool,
}

/// A session catalog: where sessions come from and which hints are obeyed.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defsessions")]
pub struct SessionsForm {
    pub name: String,
    /// ★ A `Vec<String>` IS a bare parenthesised run — measured, because the
    /// surface notes say "no map, no vector" and that is easy to read as "a
    /// list field is impossible". It is not: the language has no vector TYPE,
    /// while a `Vec<T>` FIELD lowers from `("a" "b")`. `tests/vec_of_strings.rs`
    /// is the probe.
    pub dirs: Vec<String>,
    #[tatara(domain)]
    pub honor: Option<HonorForm>,
}

/// Where a face draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum FaceKind {
    /// The GPU face, as a mode of omoya.
    Gpu,
    /// The text face on a VT.
    Tty,
    /// No pixels at all — the CI face.
    Headless,
}

/// One face and the renderer behind it.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defface")]
pub struct FaceForm {
    #[tatara(keyword_enum)]
    pub kind: FaceKind,
    pub renderer: String,
}

/// How the envelope crosses the uid boundary.
///
/// One arm today, and that is the finding rather than a limitation. §5.4
/// evaluates three candidates and **kills two on structural grounds**:
/// `$XDG_RUNTIME_DIR` is destroyed by logind at exactly the moment the session
/// starts, and a shared `/var/lib` path fails *silently in the benign
/// direction* — the session re-probes, so nobody discovers the handoff never
/// worked. A transport enum with three arms would imply two of them are
/// choices. They are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum Transport {
    /// An inherited memfd sealed `WRITE|SHRINK|GROW`, published through
    /// `pam_putenv` before `pam_open_session`.
    ///
    /// Single word on purpose: `DeriveKeywordSexp` lowercases with no
    /// separator, so `:sealed-memfd` (as §4.2 writes it) does not parse.
    Sealedmemfd,
}

/// How fast a fact goes stale.
///
/// ★ **THERE IS NO `Sensor` ARM, AND THAT IS THE MECHANISM.** §5.2: a fact
/// whose validity window is shorter than the handoff latency is not
/// configuration. Battery and thermal change between greet and session by
/// construction, so an envelope carrying them is handing over a value that is
/// already wrong. They are not *discouraged* here — there is no volatility a
/// declarer could give them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveKeywordSexp)]
pub enum Volatility {
    /// Changes when a display is plugged or unplugged.
    Hotplugvolatile,
    /// Fixed until the machine reboots.
    Bootstable,
    /// A human chose it at submit time.
    Decision,
    /// Written by a person in a config.
    Authored,
}

/// The earliest epoch at which a fact may legitimately be read.
///
/// §5.1's whole point: the greeter knows nobody (E0), then knows a *name*
/// (E1), then knows an authenticated identity (E2). Two historical failures —
/// `~/.dmrc` and AccountsService — were "neither wrong because of location.
/// Both wrong because the store's scope was never typed." This is that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, DeriveKeywordSexp)]
pub enum Epoch {
    /// Anonymous. Vendor and admin config only.
    E0,
    /// A username is named but NOT authenticated. The public profile.
    E1,
    /// Authenticated, home mounted.
    E2,
    /// Chosen at the moment of submission.
    Atsubmit,
}

/// One fact the entrance measures and hands over.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "deffact")]
pub struct FactForm {
    /// The dotted config path this fact answers.
    pub path: String,
    #[tatara(keyword_enum)]
    pub volatility: Volatility,
    #[tatara(keyword_enum)]
    pub epoch: Epoch,
}

/// The greeter→session handoff.
#[derive(Debug, Clone, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defhandoff")]
pub struct HandoffForm {
    pub name: String,
    #[tatara(keyword_enum)]
    pub transport: Transport,
    pub env_var: String,
    pub validity_secs: u32,
    #[tatara(domain)]
    pub facts: Vec<FactForm>,
}

// ── Lowered shapes ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCatalog {
    pub name: String,
    pub dirs: Vec<String>,
    pub honor: Honored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub path: String,
    pub volatility: Volatility,
    pub epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    pub name: String,
    pub transport: Transport,
    pub env_var: String,
    pub validity_secs: u32,
    pub facts: Vec<Fact>,
}

/// Every way a handoff can be absent, enumerated.
///
/// ★ §5.4's contract is that absence "degrades correctly BY CONTRACT, not by a
/// fallback branch": every one of these resolves to an empty dict, so the next
/// config tier shows through and the session simply probes for itself. The
/// enum exists so that is *checkable* — a new absence cause added later has to
/// be given an answer, and the exhaustive match is where it gets asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// No `MUKAE_HANDOFF_FD` in the environment at all.
    EnvVarUnset,
    /// The variable is set but is not a number.
    EnvVarMalformed,
    /// The fd number names nothing.
    FdNotOpen,
    /// The bytes do not deserialize.
    EnvelopeCorrupt,
    /// A schema MAJOR this build does not know.
    SchemaTooNew,
    /// `measured_at + validity` is in the past.
    Expired,
    /// The envelope is addressed to a different uid.
    WrongSubject,
}

impl Absence {
    /// Every absence cause. The denominator, carried in code.
    pub const ALL: &'static [Self] = &[
        Self::EnvVarUnset,
        Self::EnvVarMalformed,
        Self::FdNotOpen,
        Self::EnvelopeCorrupt,
        Self::SchemaTooNew,
        Self::Expired,
        Self::WrongSubject,
    ];

    /// What the discovery layer answers. **Always the same thing.**
    ///
    /// Not a simplification — it is the contract. `DiscoveryLayer`'s empty dict
    /// means "undetectable, never a guess", so an absent handoff is
    /// indistinguishable from a machine that never had one, and the session
    /// re-probes exactly as it would have. A fallback that guessed instead
    /// would be worse than no handoff at all.
    #[must_use]
    pub const fn answer(self) -> Resolution {
        match self {
            Self::EnvVarUnset
            | Self::EnvVarMalformed
            | Self::FdNotOpen
            | Self::EnvelopeCorrupt
            | Self::SchemaTooNew
            | Self::Expired
            | Self::WrongSubject => Resolution::EmptyDict,
        }
    }
}

/// What a handoff read resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Facts were found.
    Facts,
    /// Nothing was found, and the next tier shows through.
    EmptyDict,
}

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("{0}")]
    Id(#[from] IdError),
    #[error("a session catalog must name at least one directory")]
    NoDirs,
    #[error("session directory {0:?} is not absolute")]
    RelativeDir(String),
    #[error("the handoff declares no facts, so it would hand over nothing")]
    NoFacts,
    #[error("fact {path:?} is declared twice")]
    DuplicateFact { path: String },
    #[error(
        "fact {path:?} is {volatility:?} but declared at epoch {epoch:?}: a \
         fact that changes on hotplug cannot be resolved at an epoch the \
         session only reaches later — it would hand over a value already stale"
    )]
    VolatileAtLateEpoch {
        path: String,
        volatility: Volatility,
        epoch: Epoch,
    },
    #[error(
        "fact {0:?} names a sensor. A fact whose validity window is shorter \
         than the handoff latency is not configuration — battery and thermal \
         change between greet and session by construction. Consume it as a \
         live input instead."
    )]
    SensorAsConfig(String),
    #[error("the handoff env var must be a NAME, not an assignment: {0:?}")]
    EnvVarNotAName(String),
    #[error("a handoff with zero validity would be stale on arrival")]
    ZeroValidity,
}

/// Paths whose values change faster than a handoff completes.
///
/// A list rather than a type because the *name* is the only signal available
/// at declaration time — `Volatility` already makes the concept
/// unrepresentable, and this catches an author reaching for it anyway under a
/// volatility that does not fit.
const SENSOR_PREFIXES: &[&str] = &["battery.", "thermal.", "power.draw", "fan."];

impl SessionsForm {
    /// # Errors
    /// [`CatalogError`] when the catalog names no directories or a relative one.
    pub fn lower(&self) -> Result<SessionCatalog, CatalogError> {
        if self.dirs.is_empty() {
            return Err(CatalogError::NoDirs);
        }
        for d in &self.dirs {
            if !d.starts_with('/') {
                return Err(CatalogError::RelativeDir(d.clone()));
            }
        }
        // An undeclared hint is HONOURED. Ignoring `Hidden=true` because
        // nobody said to obey it would show a user an entry its packager
        // deliberately deleted, so the safe default is the obedient one.
        let h = self.honor.unwrap_or_default();
        Ok(SessionCatalog {
            name: self.name.clone(),
            dirs: self.dirs.clone(),
            honor: Honored {
                hidden: h.hidden.unwrap_or(true),
                no_display: h.no_display.unwrap_or(true),
                try_exec: h.try_exec.unwrap_or(true),
            },
        })
    }
}

impl HandoffForm {
    /// # Errors
    /// [`CatalogError`] naming the exact fact or field at fault.
    pub fn lower(&self) -> Result<Handoff, CatalogError> {
        if self.facts.is_empty() {
            return Err(CatalogError::NoFacts);
        }
        if self.validity_secs == 0 {
            return Err(CatalogError::ZeroValidity);
        }
        if self.env_var.contains('=') || self.env_var.is_empty() {
            return Err(CatalogError::EnvVarNotAName(self.env_var.clone()));
        }

        let mut facts = Vec::with_capacity(self.facts.len());
        let mut seen: Vec<&str> = Vec::new();
        for f in &self.facts {
            if seen.contains(&f.path.as_str()) {
                return Err(CatalogError::DuplicateFact {
                    path: f.path.clone(),
                });
            }
            seen.push(&f.path);

            if SENSOR_PREFIXES.iter().any(|p| f.path.starts_with(p)) {
                return Err(CatalogError::SensorAsConfig(f.path.clone()));
            }

            // A hotplug-volatile fact resolved at E2 is resolved after the
            // session has already started — by then the entrance's measurement
            // is a historical claim, not a current one.
            if f.volatility == Volatility::Hotplugvolatile && f.epoch >= Epoch::E2 {
                return Err(CatalogError::VolatileAtLateEpoch {
                    path: f.path.clone(),
                    volatility: f.volatility,
                    epoch: f.epoch,
                });
            }

            facts.push(Fact {
                path: f.path.clone(),
                volatility: f.volatility,
                epoch: f.epoch,
            });
        }

        Ok(Handoff {
            name: self.name.clone(),
            transport: self.transport,
            env_var: self.env_var.clone(),
            validity_secs: self.validity_secs,
            facts,
        })
    }
}
