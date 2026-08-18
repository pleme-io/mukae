//! Which desktop actions this login surface covers — declared, not implied.
//!
//! `pleme-io/saihai` is the fleet's typed desktop action catalog: 284
//! `(defaction …)` rows, each carrying an authority rung and whether its
//! effect is observable. Thirty-one of those rows are mukae's — 21 `login-*`,
//! 7 `seat-*`, 3 `vt-*` — and they map almost one-to-one onto [`SeatEnv`].
//!
//! ## Why this table exists rather than being obvious
//!
//! Without it, "which login actions are implemented?" is answered by reading
//! two repos and hoping. That is precisely the drift that goes silent: saihai
//! declares `login-auth-next`, mukae's method is `pam_next`, and nothing
//! anywhere notices they are the same verb — or that they have stopped being.
//!
//! So the coverage is a value. A reconciler holding a desktop declaration can
//! ask what a login surface actually provides, and get an answer that is a
//! type rather than a guess.
//!
//! ## The honest limit, stated up front
//!
//! **The action IDs here are hand-maintained against saihai's catalog, and
//! nothing yet checks them against it.** mukae cannot take saihai as a
//! dependency: this crate's dependency list is an invariant that closes
//! illegal state [14], and a cross-repo `path =` dependency is the defect that
//! resolves on one workstation and nowhere else.
//!
//! The gate that closes this is a test in a crate that legitimately sees BOTH
//! — `bancadad` already consumes saihai — and it needs mukae on the registry
//! first. Until then this table is a **declaration**, not a proven mapping.
//! `pending-saihai-coverage-gate: needs mukae published`

/// How far along a catalog action is on this surface.
///
/// A closed enum rather than a bool, because "not implemented" is three
/// different facts with three different owners, and collapsing them is how a
/// roadmap turns into a shrug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// M0 — reachable through [`crate::env::SeatEnv`] today, and exercised by
    /// the mock.
    Implemented,
    /// M3 — needs the real PAM linkage (`HostSeatEnv`).
    NeedsPam,
    /// M4 — needs the seat/device/VT half and its typestate.
    NeedsSeat,
    /// M7 — needs the greeter→session handoff envelope.
    NeedsHandoff,
}

impl Phase {
    /// Whether a caller can actually do this today.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Implemented)
    }

    /// The `theory/MUKAE.md` §7 phase that lands it.
    #[must_use]
    pub const fn milestone(self) -> &'static str {
        match self {
            Self::Implemented => "M0",
            Self::NeedsPam => "M3",
            Self::NeedsSeat => "M4",
            Self::NeedsHandoff => "M7",
        }
    }
}

/// mukae's slice of saihai's catalog.
///
/// Ordered as the catalog orders them, so a diff against
/// `catalog/desktop.saihai.lisp` reads straight down.
pub const COVERAGE: &[(&str, Phase)] = &[
    // ── identity: the greeter's view before anyone has logged in ──────
    ("login-enumerate-principals", Phase::Implemented),
    ("login-resolve-principal", Phase::Implemented),
    // Reads the E1 public-profile store, which does not exist until the
    // handoff does.
    ("login-read-public-profile", Phase::NeedsHandoff),
    // ── the conversation ───────────────────────────────────────────────
    ("login-auth-begin", Phase::Implemented),
    ("login-auth-next", Phase::Implemented),
    ("login-auth-answer", Phase::Implemented),
    ("login-auth-account-check", Phase::Implemented),
    ("login-auth-change-token", Phase::Implemented),
    ("login-auth-end", Phase::Implemented),
    // ── the session ────────────────────────────────────────────────────
    ("login-set-credentials", Phase::Implemented),
    ("login-put-env", Phase::Implemented),
    ("login-get-env", Phase::Implemented),
    ("login-open-session", Phase::Implemented),
    ("login-close-session", Phase::Implemented),
    ("login-mint-capability", Phase::Implemented),
    ("login-start-session", Phase::Implemented),
    ("login-fork-session", Phase::Implemented),
    // ── process control: needs real signals and a real reaper ──────────
    ("login-signal-session", Phase::NeedsPam),
    ("login-reap-session", Phase::NeedsPam),
    // Autologin needs the runfile to actually exist and be removable — the
    // exactly-once token is only meaningful against a filesystem.
    ("login-autologin", Phase::NeedsPam),
    ("login-handoff", Phase::NeedsHandoff),
    // ── seat and device brokering (M4, absent rather than stubbed) ─────
    ("seat-open", Phase::NeedsSeat),
    ("seat-take-control", Phase::NeedsSeat),
    ("seat-open-device", Phase::NeedsSeat),
    ("seat-close-device", Phase::NeedsSeat),
    ("seat-poll", Phase::NeedsSeat),
    ("seat-ack-disable", Phase::NeedsSeat),
    ("seat-reacquire", Phase::NeedsSeat),
    // ── VT: seat0 only, gated by the witness ──────────────────────────
    ("vt-query-free", Phase::NeedsSeat),
    ("vt-set-kd-mode", Phase::NeedsSeat),
    ("vt-set-kb-mode", Phase::NeedsSeat),
];

/// What phase an action is at, or `None` if it is not mukae's.
#[must_use]
pub fn phase_of(action: &str) -> Option<Phase> {
    COVERAGE
        .iter()
        .find(|(id, _)| *id == action)
        .map(|(_, p)| *p)
}

/// Every action a caller can perform today.
#[must_use]
pub fn live_actions() -> Vec<&'static str> {
    COVERAGE
        .iter()
        .filter(|(_, p)| p.is_live())
        .map(|(id, _)| *id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// ★ THE DENOMINATOR, CARRIED INSIDE THE VALUE. saihai's catalog holds 31
    /// rows in mukae's three domains. A table that quietly lost half of them
    /// would still answer every question asked of it — just wrongly, and
    /// always in the direction of claiming less exists than does.
    #[test]
    fn the_table_covers_every_row_saihai_declares_for_mukae() {
        assert_eq!(
            COVERAGE.len(),
            31,
            "saihai declares 21 login-*, 7 seat-* and 3 vt-* rows; \
             re-count against catalog/desktop.saihai.lisp before changing this"
        );
        let logins = COVERAGE
            .iter()
            .filter(|(id, _)| id.starts_with("login-"))
            .count();
        let seats = COVERAGE
            .iter()
            .filter(|(id, _)| id.starts_with("seat-"))
            .count();
        let vts = COVERAGE
            .iter()
            .filter(|(id, _)| id.starts_with("vt-"))
            .count();
        assert_eq!((logins, seats, vts), (21, 7, 3));
    }

    #[test]
    fn no_action_is_listed_twice() {
        let ids: BTreeSet<_> = COVERAGE.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), COVERAGE.len(), "duplicate action id");
    }

    /// Every id is a saihai action id: kebab-case, domain-prefixed. A typo
    /// here is a silent no-match at lookup time rather than an error.
    #[test]
    fn every_id_is_well_formed() {
        for (id, _) in COVERAGE {
            assert!(
                id.starts_with("login-") || id.starts_with("seat-") || id.starts_with("vt-"),
                "{id} is not in one of mukae's three domains"
            );
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{id} is not kebab-case"
            );
        }
    }

    /// ★ THE LIVE SET MATCHES WHAT M0 ACTUALLY SHIPPED. Every seat/VT action
    /// must be NeedsSeat, because that half of `SeatEnv` is absent — a row
    /// claiming otherwise would be a method that does not exist reported as
    /// available.
    #[test]
    fn nothing_in_the_absent_half_claims_to_be_live() {
        for (id, phase) in COVERAGE {
            if id.starts_with("seat-") || id.starts_with("vt-") {
                assert_eq!(
                    *phase,
                    Phase::NeedsSeat,
                    "{id} cannot be live: the seat/VT half of SeatEnv does not exist"
                );
            }
        }
    }

    #[test]
    fn the_live_set_is_what_m0_claims() {
        let live = live_actions();
        assert_eq!(live.len(), 16, "M0 covers 16 of the 31");
        assert!(live.contains(&"login-auth-next"));
        assert!(live.contains(&"login-start-session"));
        assert!(!live.contains(&"login-autologin"), "needs a real runfile");
        assert!(!live.contains(&"seat-open"), "M4");
    }

    #[test]
    fn a_foreign_action_is_not_ours() {
        assert!(phase_of("theme-select").is_none());
        assert_eq!(phase_of("login-open-session"), Some(Phase::Implemented));
        assert_eq!(phase_of("seat-poll").map(Phase::milestone), Some("M4"));
    }
}
