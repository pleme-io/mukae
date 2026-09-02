//! What an agent can learn about the DAEMON — the half of a login that
//! outlives the face.
//!
//! ── ★ WHY THE DAEMON NEEDS ITS OWN SURFACE AT ALL ─────────────────────────
//! `mukae-greeter` already publishes a `LoginFlow` over kanshou, and for
//! months that was the whole story. It has two limits that no amount of work
//! inside the greeter can fix, and both were measured on plo 2026-09-02:
//!
//! 1. **The greeter only exists AT the prompt.** The moment a login succeeds
//!    it is SIGTERMed and its socket goes with it, so every login leaf reads
//!    `blind` on a seat that is logged in — which is exactly the seat an
//!    operator is looking at when they ask what happened. The history is gone
//!    at the instant it becomes interesting.
//! 2. **The greeter runs as its own uid** (982 on plo), whose sockets land in
//!    `/tmp/kanshou-982`. kanshou's discovery only walks the CALLING uid's
//!    directories, and the sockets are `srwxr-xr-x` — a unix connect needs the
//!    WRITE bit. Probed from uid 1001: `Permission denied` on all 39. So the
//!    operator cannot reach it even knowing where it is.
//!
//! `mukaed` has neither problem. It is long-lived, it is root, and it already
//! sees every `Frame` crossing the socketpair — so it can republish the same
//! flow plus the things only the daemon knows.
//!
//! ── ★ WHAT IS PUBLISHED, AND WHAT IS NOT ──────────────────────────────────
//! Every leaf here is a decision, which is why this is a hand-written
//! `Introspect` and not `#[derive(Introspect)]` (same reasoning as
//! `mukae::introspect`, and the derive would project fields as they are).
//!
//! **`pam_class` is absent, exactly as it is absent from the greeter's
//! surface.** `PamClass` separates `UserUnknown` from `AuthError`; an agent
//! that could ask which one occurred would have a username oracle, which is
//! the same reason the console says "login incorrect" for both. The COUNT is
//! published; the discriminator is not.
//!
//! `session_owner` and `last_user` ARE published, by operator decision
//! (2026-09-02). They are not a new disclosure: `loginctl` already reports
//! the owner of an active session to any local user, so the daemon telling an
//! agent the same fact adds no primitive that did not exist.
//!
//! **There is no write surface here and there must never be one.** The
//! greeter's own `mcp.rs` argues the case — a greeter is the authentication
//! boundary and an agent that can type into it can attempt logins at machine
//! speed against a `failures` counter it can also read. That argument covers
//! the daemon a fortiori: this process is root.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use kanshou::{Introspect, Query, QueryError, QueryResult};
use mukae::introspect::{Drivable, LoginFlow};

/// The app name kanshou discovers by. Distinct from the greeter's `mukae`,
/// because they are two processes with two lifetimes and an agent must be
/// able to say which one it is talking to.
pub const APP: &str = "mukaed";

/// Facts the daemon learns as a login proceeds.
///
/// Every field is `Option`, and `None` means *not yet known* rather than
/// absent — a distinction the JSON preserves as `null` so a reader is never
/// handed a plausible default for something that has not happened.
#[derive(Debug, Default)]
struct Facts {
    greeter_pid: Option<i32>,
    greeter_user: Option<String>,
    vt: Option<u32>,
    seat: Option<String>,
    /// The account that most recently AUTHENTICATED. Survives the session
    /// starting, which is the point — it is the answer to "who is on this
    /// machine" after the greeter is gone.
    last_user: Option<String>,
    /// Set when the session is started, cleared when it is reaped. Distinct
    /// from `last_user`, which is sticky.
    session_owner: Option<String>,
    session_open: bool,
    session_path: Option<String>,
}

/// The daemon's queryable state.
///
/// Holds a [`LoginFlow`] rather than re-deriving one: the greeter's flow type
/// already encodes which reductions are safe to publish (a `StepView` instead
/// of a `PamStep`, no class, counters as atomics), and duplicating that logic
/// here would be two answers to one question — the exact drift this fleet
/// treats as a defect rather than a convenience.
#[derive(Debug)]
pub struct DaemonState {
    flow: LoginFlow,
    facts: Mutex<Facts>,
    /// Seconds since the daemon started, as a monotonic count set once.
    started: std::time::Instant,
    /// Greeter processes spawned since this daemon started. A restart of the
    /// GREETER is not a restart of the daemon, and the difference is what
    /// tells a crash-loop from a person retyping a password.
    greeter_spawns: AtomicU64,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonState {
    /// A daemon state observing a real seat.
    ///
    /// `Drivable::Observable` and never `MockOnly`: this process holds root
    /// and drives PAM against the real stack, so the arm that means "safe to
    /// drive because it authenticates nobody" would be a lie here.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flow: LoginFlow::new(Drivable::Observable),
            facts: Mutex::new(Facts::default()),
            started: std::time::Instant::now(),
            greeter_spawns: AtomicU64::new(0),
        }
    }

    /// The flow, so the conversation loop can feed it.
    #[must_use]
    pub fn flow(&self) -> &LoginFlow {
        &self.flow
    }

    /// Record a greeter that was just spawned.
    pub fn greeter_spawned(&self, pid: i32, user: &str) {
        self.greeter_spawns.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut f) = self.facts.lock() {
            f.greeter_pid = Some(pid);
            f.greeter_user = Some(user.to_owned());
        }
    }

    /// Record which console this daemon claimed.
    pub fn console_claimed(&self, seat: &str, vt: Option<u32>) {
        if let Ok(mut f) = self.facts.lock() {
            f.seat = Some(seat.to_owned());
            f.vt = vt;
        }
    }

    /// Record the resolved session PATH.
    ///
    /// ★ There is deliberately no `config_tier` leaf. `MukaeConfig` keeps no
    /// record of WHICH shikumi tier won its fold, so the daemon genuinely does
    /// not know — and a surface whose whole value is being trustworthy must
    /// not answer a question it cannot answer. Publishing a guessed tier would
    /// be indistinguishable from a measured one, which is the failure mode
    /// this file exists to avoid.
    pub fn session_path_resolved(&self, session_path: &str) {
        if let Ok(mut f) = self.facts.lock() {
            f.session_path = Some(session_path.to_owned());
        }
    }

    /// Record a successful authentication. Sticky — `last_user` outlives the
    /// session so the daemon can still answer after everything else is gone.
    pub fn authenticated(&self, user: &str) {
        if let Ok(mut f) = self.facts.lock() {
            f.last_user = Some(user.to_owned());
        }
    }

    /// Record that the session is up.
    pub fn session_started(&self, user: &str) {
        if let Ok(mut f) = self.facts.lock() {
            f.session_owner = Some(user.to_owned());
            f.session_open = true;
        }
    }

    /// Record that the session ended. `last_user` deliberately survives.
    pub fn session_ended(&self) {
        if let Ok(mut f) = self.facts.lock() {
            f.session_owner = None;
            f.session_open = false;
        }
    }

    fn snapshot_json(&self) -> serde_json::Value {
        let snap = self.flow.snapshot();
        let f = self.facts.lock().ok();
        let g = |pick: &dyn Fn(&Facts) -> serde_json::Value| -> serde_json::Value {
            f.as_ref().map_or(serde_json::Value::Null, |f| pick(f))
        };
        serde_json::json!({
            "mode": snap.mode,
            "may_drive": snap.may_drive,
            "attempts": snap.attempts,
            "failures": snap.failures,
            "successes": snap.successes,
            "step": snap.step_kind,
            "prompt": snap.prompt,
            "echo": snap.echo,
            "greeter_pid": g(&|f| serde_json::json!(f.greeter_pid)),
            "greeter_user": g(&|f| serde_json::json!(f.greeter_user)),
            "greeter_spawns": self.greeter_spawns.load(Ordering::Relaxed),
            "vt": g(&|f| serde_json::json!(f.vt)),
            "seat": g(&|f| serde_json::json!(f.seat)),
            "session_open": g(&|f| serde_json::json!(f.session_open)),
            "session_owner": g(&|f| serde_json::json!(f.session_owner)),
            "last_user": g(&|f| serde_json::json!(f.last_user)),
            "session_path": g(&|f| serde_json::json!(f.session_path)),
            // ── static catalogs ────────────────────────────────────────
            // Typed, tested, and until now reachable only from inside the
            // process. Each is published as the constant it already is, not
            // re-derived — `coverage` answers "which milestone is this
            // machine actually running" as a QUERY rather than a doc read,
            // which is the claim theory/MUKAE.md §8 currently gets wrong
            // about plo.
            "coverage": coverage_json(),
            "drift_keys": drift_keys_json(),
            "uptime_s": self.started.elapsed().as_secs(),
            "version": env!("CARGO_PKG_VERSION"),
        })
    }
}

/// Every leaf, in one place, so `schema()` and the dispatch cannot disagree.
///
/// Hand-maintained for the reason omoya's and the greeter's are: kanshou does
/// not dispatch `schema()` over the wire, so an MCP face mirrors this list.
/// The pair of tests below is what keeps the mirror honest — one direction
/// each, because a single-direction check passes happily while the surface
/// grows a leaf nobody can discover.
pub const LEAVES: &[&str] = &[
    "attempts",
    "coverage",
    "drift_keys",
    "echo",
    "failures",
    "greeter_pid",
    "greeter_spawns",
    "greeter_user",
    "last_user",
    "may_drive",
    "mode",
    "prompt",
    "seat",
    "session_open",
    "session_owner",
    "session_path",
    "step",
    "successes",
    "uptime_s",
    "version",
    "vt",
];

/// The 31-action coverage catalog, as data.
///
/// `mukae_spec::coverage::COVERAGE` maps each catalog action to the phase
/// that makes it live, and `Phase::milestone()` names the M-number. Both
/// already exist and had no consumer outside the crate; this publishes them
/// rather than restating them, so the catalog and the answer cannot drift.
fn coverage_json() -> serde_json::Value {
    serde_json::Value::Array(
        mukae_spec::coverage::COVERAGE
            .iter()
            .map(|(action, phase)| {
                serde_json::json!({
                    "action": action,
                    "live": phase.is_live(),
                    "milestone": phase.milestone(),
                })
            })
            .collect(),
    )
}

/// The reconciler key catalog, with what a loop may DO to each.
///
/// ★ `SessionOpen` is `CloseOnly` — a reconciler may close a session and may
/// never open one. That asymmetry is the interesting fact here and the reason
/// this is worth publishing: it tells an agent what is even askable before it
/// proposes anything.
///
/// The live `Gap` is deliberately NOT published. `Gap::is_converged()`
/// requires `examined > 0` so a blind reconciler cannot report convergence,
/// and computing a Gap needs a live `SeatEnv` the daemon only holds mid-login
/// — a snapshot taken outside that window would be a convergence claim made
/// from no observation, which is the exact hole that type closes.
fn drift_keys_json() -> serde_json::Value {
    serde_json::Value::Array(
        mukae_spec::surface::Key::ALL
            .iter()
            .map(|k| {
                serde_json::json!({
                    "key": k.path(),
                    "drivable": format!("{:?}", k.drivable()),
                })
            })
            .collect(),
    )
}

impl Introspect for DaemonState {
    fn query(&self, q: &Query) -> QueryResult {
        let head = q.path.first().map(String::as_str).unwrap_or_default();
        let snap = self.snapshot_json();
        if head.is_empty() {
            return Ok(snap);
        }
        snap.get(head)
            .cloned()
            .ok_or_else(|| QueryError::unknown_field(head))
    }

    fn schema(&self) -> &'static [&'static str] {
        LEAVES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both directions. A one-way check passes while the surface grows a leaf
    /// that no caller can discover, which is the failure this pair exists to
    /// catch — and it is the check the greeter's own face still lacks.
    #[test]
    fn every_advertised_leaf_answers() {
        let st = DaemonState::new();
        for leaf in LEAVES {
            let q = Query::field(vec![(*leaf).to_string()]);
            assert!(
                st.query(&q).is_ok(),
                "advertised leaf `{leaf}` does not answer"
            );
        }
    }

    #[test]
    fn every_answering_leaf_is_advertised() {
        let st = DaemonState::new();
        let serde_json::Value::Object(map) = st.snapshot_json() else {
            panic!("the snapshot must be an object");
        };
        for key in map.keys() {
            assert!(
                LEAVES.contains(&key.as_str()),
                "leaf `{key}` answers but is not advertised in LEAVES"
            );
        }
    }

    /// The username oracle stays shut. Same rule as the greeter's surface,
    /// asserted again here because this is a SECOND surface over the same
    /// flow and the rule has to hold on both or it holds on neither.
    #[test]
    fn no_failure_class_leaf() {
        let st = DaemonState::new();
        for forbidden in ["class", "pam_class", "failure_class"] {
            assert!(
                !LEAVES.contains(&forbidden),
                "`{forbidden}` must never be advertised"
            );
            let q = Query::field(vec![forbidden.to_string()]);
            assert!(st.query(&q).is_err(), "`{forbidden}` must not answer");
        }
    }

    /// A real seat is never drivable, whatever else changes.
    #[test]
    fn a_root_daemon_never_reports_drivable() {
        let st = DaemonState::new();
        let q = Query::field(vec!["may_drive".to_string()]);
        assert_eq!(st.query(&q).unwrap(), serde_json::json!(false));
    }

    /// `last_user` outliving the session is the whole reason the daemon
    /// carries this surface instead of the greeter.
    #[test]
    fn last_user_survives_the_session_ending() {
        let st = DaemonState::new();
        st.authenticated("luis");
        st.session_started("luis");
        st.session_ended();
        let owner = st
            .query(&Query::field(vec!["session_owner".to_string()]))
            .unwrap();
        let last = st
            .query(&Query::field(vec!["last_user".to_string()]))
            .unwrap();
        assert_eq!(owner, serde_json::Value::Null, "owner clears on end");
        assert_eq!(last, serde_json::json!("luis"), "last_user is sticky");
    }

    /// ★ THE DENOMINATOR IS INSIDE THE ASSERTION. A catalog that quietly
    /// lost its entries would publish `[]` and every other test here would
    /// stay green — the surface would answer confidently about nothing. The
    /// floors are well under today's counts (31 actions, 3 keys) so adding an
    /// entry never demands an edit here, while losing most of them fails.
    #[test]
    fn the_published_catalogs_are_not_empty() {
        let st = DaemonState::new();
        let cov = st
            .query(&Query::field(vec!["coverage".to_string()]))
            .unwrap();
        assert!(
            cov.as_array().is_some_and(|a| a.len() >= 20),
            "the coverage catalog collapsed: {} entries",
            cov.as_array().map_or(0, Vec::len)
        );
        let keys = st
            .query(&Query::field(vec!["drift_keys".to_string()]))
            .unwrap();
        assert!(
            keys.as_array().is_some_and(|a| !a.is_empty()),
            "the drift-key catalog collapsed"
        );
    }

    /// An unknown leaf is a typed refusal, never a null that reads as "no".
    #[test]
    fn an_unknown_leaf_refuses() {
        let st = DaemonState::new();
        assert!(
            st.query(&Query::field(vec!["nonsense".to_string()]))
                .is_err()
        );
    }
}
