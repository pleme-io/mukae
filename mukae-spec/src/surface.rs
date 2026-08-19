//! The login surface as reconcilable state — desired, observed, and the gap.
//!
//! ## This is an ADAPTER, not a second engine
//!
//! The fleet has one convergence engine: `lava-viggy`'s seven beats, which
//! `bancadad` already runs on. Writing a loop here would be the exact
//! duplication that adoption removed — so there is no loop in this file. What
//! is here is the *shape* a reconciler needs: what the login surface's state
//! keys are, what authority each needs, and what calls would close a gap.
//!
//! When mukae reaches the registry, `bancadad` gains a `World` impl over this
//! in a few lines and the login surface converges on the same engine as the
//! rest of the desktop. Until then this is proven against `MockSeatEnv`, which
//! is the same standing as everything else in M0.
//!
//! ## Why a login surface is NOT like the rest of the desktop
//!
//! Most desktop state is idempotent: setting the theme to nord twice is
//! setting it once. A login is not. Three differences shape everything below:
//!
//! 1. **Most of it is not settable at all.** `login-auth-begin` is not a value
//!    you converge toward — it is an event in a conversation. So the surface
//!    is deliberately SMALL: of mukae's 31 catalog actions, only a handful
//!    describe state a reconciler may hold.
//! 2. **Re-running an action is not free.** Re-authenticating consumes a retry
//!    budget and can lock an account. A reconciler that "just re-applies"
//!    every tick is a reconciler that locks out its operator, which is why
//!    every key here is `Converging` only if reading it is cheap and setting
//!    it is idempotent.
//! 3. **The desired state can be "nobody is logged in".** Session absence is a
//!    legitimate goal, not a failure to reach one.

use crate::env::SeatEnv;
use crate::ids::{SeatId, Uid};

/// A state key on the login surface, and what it takes to move it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Whether a session is open on this seat. Idempotent to read; closing is
    /// idempotent, opening is NOT (it needs an authentication).
    SessionOpen,
    /// Which principal owns the open session.
    SessionOwner,
    /// Whether the seat accepts new logins at all.
    LoginsEnabled,
}

impl Key {
    /// The dotted path a declaration uses.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::SessionOpen => "login.session.open",
            Self::SessionOwner => "login.session.owner",
            Self::LoginsEnabled => "login.enabled",
        }
    }

    /// Every key. The denominator, in code.
    pub const ALL: &'static [Self] = &[Self::SessionOpen, Self::SessionOwner, Self::LoginsEnabled];

    /// ★ Whether a reconciler may DRIVE this key toward a value, as opposed to
    /// only observing it.
    ///
    /// `SessionOpen` is deliberately one-way: a loop may CLOSE a session
    /// (idempotent, needs no secret) and may never OPEN one, because opening
    /// requires an authentication that only a human can supply. A reconciler
    /// that could open sessions would be a reconciler that logs someone in
    /// without them — and the capability chain already makes that
    /// unconstructable, so this is the same fact stated where a planner can
    /// read it.
    #[must_use]
    pub const fn drivable(self) -> Drivable {
        match self {
            Self::SessionOpen => Drivable::CloseOnly,
            Self::SessionOwner => Drivable::ObserveOnly,
            Self::LoginsEnabled => Drivable::Both,
        }
    }
}

/// How far a reconciler may move a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drivable {
    /// Read it; never write it.
    ObserveOnly,
    /// May be driven to `false` but never to `true`.
    ///
    /// The asymmetry is the point. Ending a session needs no secret; starting
    /// one needs an `AuthProof`, which only a human interaction produces.
    CloseOnly,
    /// May be driven either way.
    Both,
}

/// What a declaration asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Desired {
    pub session_open: Option<bool>,
    pub session_owner: Option<Uid>,
    pub logins_enabled: Option<bool>,
}

/// What the world says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    pub session_open: Option<bool>,
    pub session_owner: Option<Uid>,
    pub logins_enabled: Option<bool>,
}

/// One difference between desired and observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub key: Key,
    pub want: String,
    pub have: Option<String>,
    /// What a reconciler may do about it.
    pub verdict: Verdict,
}

/// What can be done about a drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A loop may close this, and here is the action.
    Closeable { action: &'static str },
    /// The gap is real and a loop must NOT close it — it needs a human.
    ///
    /// Distinct from an error: the declaration is honourable, just not by a
    /// machine. A reconciler that reported this as a failure would be crying
    /// wolf every tick on a correctly-configured seat.
    NeedsHuman { because: &'static str },
    /// A loop cannot even see this key.
    Blind { because: &'static str },
}

/// The gap, with its denominator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gap {
    pub drifts: Vec<Drift>,
    /// ★ HOW MANY KEYS WERE LOOKED AT. A gap that found nothing because it
    /// examined nothing must not read as converged — the same denominator rule
    /// the desktop reconciler carries.
    pub examined: usize,
}

impl Gap {
    /// Converged means: examined something, and nothing a loop can act on
    /// remains.
    ///
    /// `NeedsHuman` drifts do NOT block convergence. A seat correctly
    /// declaring "someone should be logged in" is not broken while nobody is —
    /// it is waiting, and a loop that reported that as unconverged forever
    /// would train its operator to ignore it.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        self.examined > 0
            && !self
                .drifts
                .iter()
                .any(|d| matches!(d.verdict, Verdict::Closeable { .. }))
    }

    /// Drifts a loop should act on, in order.
    #[must_use]
    pub fn actionable(&self) -> Vec<&Drift> {
        self.drifts
            .iter()
            .filter(|d| matches!(d.verdict, Verdict::Closeable { .. }))
            .collect()
    }
}

/// Compute the gap. **Pure** — it reads two values and returns a difference,
/// so it can be tested without a world at all.
#[must_use]
pub fn diff(want: &Desired, have: &Observed) -> Gap {
    let mut drifts = Vec::new();
    let mut examined = 0usize;

    if let Some(w) = want.session_open {
        examined += 1;
        if have.session_open != Some(w) {
            drifts.push(Drift {
                key: Key::SessionOpen,
                want: w.to_string(),
                have: have.session_open.map(|b| b.to_string()),
                verdict: if w {
                    // Opening needs an AuthProof, which only a human produces.
                    Verdict::NeedsHuman {
                        because: "opening a session requires an authentication; \
                                  a loop has no way to obtain one",
                    }
                } else {
                    Verdict::Closeable {
                        action: "login-close-session",
                    }
                },
            });
        }
    }

    if let Some(w) = want.session_owner {
        examined += 1;
        if have.session_owner != Some(w) {
            drifts.push(Drift {
                key: Key::SessionOwner,
                want: w.to_string(),
                have: have.session_owner.map(|u| u.to_string()),
                verdict: Verdict::NeedsHuman {
                    because: "who owns a session is decided by who authenticated",
                },
            });
        }
    }

    if let Some(w) = want.logins_enabled {
        examined += 1;
        if have.logins_enabled != Some(w) {
            drifts.push(Drift {
                key: Key::LoginsEnabled,
                want: w.to_string(),
                have: have.logins_enabled.map(|b| b.to_string()),
                verdict: Verdict::Closeable {
                    action: "login-set-credentials",
                },
            });
        }
    }

    Gap { drifts, examined }
}

/// Read the surface from a world.
///
/// Deliberately narrow: this reads only what M0 can actually observe. A key
/// the environment cannot answer stays `None`, which the gap renders as a
/// missing `have` rather than as a false `false` — the same distinction
/// `Answer::Blind` draws for identity.
pub fn observe<E: SeatEnv>(env: &E, _seat: &SeatId) -> Observed {
    let _ = env;
    // M0's SeatEnv has no seat-scoped session query — that arrives with the
    // seat half at M4. Returning an empty observation is the honest answer:
    // every key reads as unknown, and the gap says so rather than inventing a
    // value. This is a stub in the reporting sense, NOT in the `todo!()`
    // sense — it returns a correct, meaningful value today.
    Observed::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_has_a_path_and_they_are_distinct() {
        let paths: Vec<_> = Key::ALL.iter().map(|k| k.path()).collect();
        assert_eq!(paths.len(), 3);
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), paths.len(), "duplicate path");
        assert!(paths.iter().all(|p| p.starts_with("login.")));
    }

    /// ★ A LOOP MAY CLOSE A SESSION AND MAY NEVER OPEN ONE.
    ///
    /// The asymmetry is the whole safety property. Closing needs no secret;
    /// opening needs an `AuthProof`, which only a human interaction produces —
    /// and the capability chain already makes a machine-minted one
    /// unconstructable. This states the same fact where a *planner* can read
    /// it, so the plan never contains an action the type system would refuse.
    #[test]
    fn a_session_may_be_closed_by_a_loop_but_never_opened() {
        assert_eq!(Key::SessionOpen.drivable(), Drivable::CloseOnly);

        let want_closed = Desired {
            session_open: Some(false),
            ..Default::default()
        };
        let open_now = Observed {
            session_open: Some(true),
            ..Default::default()
        };
        let g = diff(&want_closed, &open_now);
        assert_eq!(g.actionable().len(), 1, "closing IS actionable");

        let want_open = Desired {
            session_open: Some(true),
            ..Default::default()
        };
        let closed_now = Observed {
            session_open: Some(false),
            ..Default::default()
        };
        let g = diff(&want_open, &closed_now);
        assert!(
            g.actionable().is_empty(),
            "opening must never be planned by a loop"
        );
        assert!(matches!(g.drifts[0].verdict, Verdict::NeedsHuman { .. }));
    }

    /// ★ WAITING FOR A HUMAN IS NOT BEING UNCONVERGED. A seat declaring
    /// "someone should be logged in" is not broken while nobody is — a loop
    /// reporting that as a failure every tick trains its operator to ignore it.
    #[test]
    fn a_needs_human_drift_does_not_block_convergence() {
        let g = diff(
            &Desired {
                session_open: Some(true),
                ..Default::default()
            },
            &Observed {
                session_open: Some(false),
                ..Default::default()
            },
        );
        assert!(!g.drifts.is_empty(), "the drift is still REPORTED");
        assert!(g.is_converged(), "but it does not block convergence");
    }

    /// ★ THE DENOMINATOR. A gap that found nothing because it examined nothing
    /// must not read as converged.
    #[test]
    fn an_empty_desired_state_is_not_converged() {
        let g = diff(&Desired::default(), &Observed::default());
        assert_eq!(g.examined, 0);
        assert!(
            !g.is_converged(),
            "examining nothing is not the same as being in the right state"
        );
    }

    #[test]
    fn a_matching_state_is_converged() {
        let want = Desired {
            session_open: Some(false),
            logins_enabled: Some(true),
            ..Default::default()
        };
        let have = Observed {
            session_open: Some(false),
            logins_enabled: Some(true),
            ..Default::default()
        };
        let g = diff(&want, &have);
        assert_eq!(g.examined, 2);
        assert!(g.drifts.is_empty());
        assert!(g.is_converged());
    }

    /// An unknown observation renders as a missing `have`, never as a false
    /// `false` — the same distinction `Answer::Blind` draws for identity.
    #[test]
    fn an_unobserved_key_is_unknown_rather_than_false() {
        let g = diff(
            &Desired {
                logins_enabled: Some(true),
                ..Default::default()
            },
            &Observed::default(),
        );
        assert_eq!(g.drifts.len(), 1);
        assert_eq!(g.drifts[0].have, None, "unknown, not `false`");
    }

    /// The surface is SMALL on purpose. Of mukae's 31 catalog actions only a
    /// handful describe state a reconciler may hold; the rest are events in a
    /// conversation, and re-running one costs a retry budget.
    #[test]
    fn the_surface_is_deliberately_much_smaller_than_the_catalog() {
        assert!(
            Key::ALL.len() < crate::coverage::COVERAGE.len() / 4,
            "if this grows, check that each new key is genuinely idempotent \
             to set and cheap to read — most login actions are neither"
        );
    }

    #[test]
    fn observing_an_m0_world_yields_unknowns_rather_than_invented_values() {
        let env = crate::mock::MockSeatEnv::new(crate::mock::Script::password_ok(Uid(1000)));
        let seat = SeatId::parse("seat0").unwrap();
        let o = observe(&env, &seat);
        assert_eq!(o, Observed::default(), "no key may be invented");
    }
}
