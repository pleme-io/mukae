//! The login environment with **no libpam** — mukae authenticating on its own.
//!
//! ── ★ WHAT THIS CRATE IS FOR ─────────────────────────────────────────────
//! `mukae-spec` describes a login as a typed flow and seals its illegal states
//! at the type level. Until now the only thing that implemented that flow was
//! `MockSeatEnv`, which lives inside `mukae-spec` and authenticates nobody. A
//! login manager whose sole environment is a mock cannot log anyone in, and
//! that — not the design — is what has kept greetd on the seat.
//!
//! This is the first production [`mukae_spec::env::SeatEnv`], and it links no
//! libpam.
//!
//! ── ★ THE LINE THIS CRATE DRAWS ──────────────────────────────────────────
//! `libc` is linked and that is not a compromise: it is the kernel's ABI, and
//! a login manager that cannot `fork`, `setuid` or `execve` is not one. Every
//! call here is a syscall.
//!
//! libpam is NOT linked, and the argument is `mukae-native`'s, measured
//! against the fleet's own `/etc/pam.d/login`: ten module invocations over six
//! modules, of which five are file I/O, one is a hash check against
//! `/etc/shadow`, and one — `pam_systemd` — registers the session with logind
//! **over D-Bus**. A wire is a wire and we speak it; a `.so` that dlopens
//! third-party policy modules into our address space is the guest shape
//! naturalize exists to retire.
//!
//! ── ★ THE TRAIT IS PAM-SHAPED AND THAT IS FINE ───────────────────────────
//! `SeatEnv`'s methods are named `pam_*` because PAM's pull-conversation is
//! the shape the world imposes on a login: the authenticator asks, the face
//! answers, and neither knows how many rounds there will be. Implementing it
//! natively does not mean inventing a different shape — it means being the
//! thing on the far side of it. So `pam_next` produces OUR prompts, and
//! `pam_open_session` calls logind rather than a module stack.
//!
//! ── ★ WHAT IS NOT DONE, STATED HERE RATHER THAN DISCOVERED ───────────────
//! * `pam_chauthtok` — an expired password cannot be changed from this
//!   environment yet. It returns a typed refusal rather than pretending to
//!   succeed, because a login flow that silently skips a mandatory token
//!   change lets an expired account in.
//! * `enumerate_principals` — answers `Refused`, honestly. Walking every NSS
//!   source to list users is a real feature and a half-done one that quietly
//!   omits LDAP accounts is worse than an answer that says it does not
//!   enumerate. `kotae`'s four arms exist exactly so this can be said.
//! * No VT claim. The daemon that owns a console must do that; this
//!   environment authenticates and spawns.

pub mod config;
pub mod introspect;
pub mod ipc;
mod spawn;
pub mod vt;

use std::collections::HashMap;

use mukae_spec::capability::{AuthProof, Passphrase};
use mukae_spec::env::{
    AcctVerdict, Answer, ChildPid, CredFlag, EnvPair, EnvSet, MsgStyle, PamAnswer, PamClass,
    PamError, PamStep, PromptText, PublicProfile, SeatEnv, SpawnError,
};
use mukae_spec::ids::{PamHandleId, ServiceName, Uid, UserName};
use mukae_spec::session::SessionPlan;

/// Where the hashes live. A field rather than a constant so a test can point
/// at a fixture without being root, and so a container image that keeps its
/// shadow file elsewhere is a configuration rather than a fork.
const DEFAULT_SHADOW: &str = "/etc/shadow";

/// One login in progress.
struct Txn {
    user: Option<String>,
    uid: Option<Uid>,
    /// What the flow is waiting for. `None` once the conversation ended.
    awaiting: Option<MsgStyle>,
    /// Set once verification succeeded. The runtime half of the capability
    /// seal — `mint_proof` refuses without it.
    authenticated: bool,
    /// Set once verification ran and FAILED. Distinguished from "not yet
    /// attempted" so a second `pam_next` cannot restart a lost attempt.
    refused: bool,
    env: HashMap<String, String>,
    /// The logind session. Dropping it ends the session, so it is held for
    /// exactly as long as the login is meant to last.
    session: Option<mukae_native::logind::Session>,
    /// Held only between the answer and the verification, then zeroized.
    authtok: Option<Passphrase>,
}

/// Where the session is attached, and the two are NOT independent.
///
/// ── ★ logind ENFORCES THE PAIRING, AND THE ERROR IS OPAQUE ───────────────
/// Measured on plo 2026-08-28: `CreateSession` with `seat="seat0"` and
/// `vtnr=0` fails with `org.freedesktop.DBus.Error.InvalidArgs: VT number out
/// of range`. A seat that HAS VTs demands one; a seatless session forbids
/// one. mukae-native's own comment recorded half of that rule — "must be 0
/// for a session with no VT" — and the other half is what this type closes.
///
/// Two independent fields let a caller write the illegal combination and
/// learn about it from a D-Bus error mentioning neither the seat nor which
/// of the two was wrong. A sum type makes it unconstructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Console {
    /// No seat and no VT — what a login over ssh or a socket produces.
    /// `seat` is empty and `vtnr` is 0, together, always.
    Seatless,
    /// A seat with VTs. The VT number is REQUIRED and must be the one this
    /// session actually occupies; logind refuses 0 here.
    Vt {
        seat: String,
        vtnr: std::num::NonZeroU32,
    },
}

/// The production login environment.
pub struct NativeSeatEnv {
    shadow: std::path::PathBuf,
    console: Console,
    txns: HashMap<u64, Txn>,
    next: u64,
}

impl Default for NativeSeatEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeSeatEnv {
    #[must_use]
    pub fn new() -> Self {
        Self::with_shadow(std::path::PathBuf::from(DEFAULT_SHADOW))
    }

    #[must_use]
    pub fn with_shadow(shadow: std::path::PathBuf) -> Self {
        Self {
            shadow,
            // Seatless by default, and that is the honest default for a
            // process that has not claimed a console: registering against
            // seat0 without owning a VT is how two owners end up fighting for
            // the keyboard.
            console: Console::Seatless,
            txns: HashMap::new(),
            next: 1,
        }
    }

    /// Attach sessions to a console. See [`Console`] for why the seat and the
    /// VT travel together.
    #[must_use]
    pub fn on_console(mut self, console: Console) -> Self {
        self.console = console;
        self
    }

    fn txn(&mut self, h: PamHandleId) -> Result<&mut Txn, PamError> {
        self.txns.get_mut(&h.0).ok_or(PamError::NoSuchHandle)
    }
}

impl SeatEnv for NativeSeatEnv {
    fn pam_start(
        &mut self,
        _svc: &ServiceName,
        user: Option<&UserName>,
    ) -> Result<PamHandleId, PamError> {
        let id = self.next;
        self.next += 1;
        let name = user.map(|u| u.as_str().to_string());
        // If the face already knows who is logging in, the first thing asked
        // is the passphrase. Asking for a username we were handed is the
        // small rudeness every greeter commits.
        let awaiting = Some(if name.is_some() {
            MsgStyle::PromptEchoOff
        } else {
            MsgStyle::PromptEchoOn
        });
        self.txns.insert(
            id,
            Txn {
                user: name,
                uid: None,
                awaiting,
                authenticated: false,
                refused: false,
                env: HashMap::new(),
                session: None,
                authtok: None,
            },
        );
        Ok(PamHandleId(id))
    }

    fn pam_next(&mut self, h: PamHandleId) -> Result<PamStep, PamError> {
        let t = self.txn(h)?;
        if t.authenticated {
            return Ok(PamStep::Complete);
        }
        if t.refused {
            // ★ ONE ATTEMPT PER TRANSACTION. A flow that re-prompts inside the
            // same transaction after a refusal is a flow whose failure counter
            // means nothing — and the counter is what a lockout policy reads.
            return Ok(PamStep::Failed {
                class: PamClass::AuthError,
            });
        }
        match t.awaiting {
            Some(MsgStyle::PromptEchoOn) => Ok(PamStep::Prompt {
                style: MsgStyle::PromptEchoOn,
                msg: PromptText("Username".to_string()),
            }),
            Some(MsgStyle::PromptEchoOff) => Ok(PamStep::Prompt {
                style: MsgStyle::PromptEchoOff,
                msg: PromptText("Password".to_string()),
            }),
            _ => Ok(PamStep::Failed {
                class: PamClass::AuthError,
            }),
        }
    }

    fn pam_answer(&mut self, h: PamHandleId, a: PamAnswer) -> Result<(), PamError> {
        let shadow = self.shadow.clone();
        // ★ READ WHAT IS NEEDED, THEN DROP THE BORROW. The verification below
        // must hand `&*self` to `expose_authtok` — the environment proving it
        // is the environment — and it cannot do that while a `&mut` borrow of
        // the transaction is still live. Taking the two fields first is what
        // makes the privilege check expressible at all.
        let (style, user) = {
            let t = self.txn(h)?;
            (t.awaiting, t.user.clone())
        };
        let Some(style) = style else {
            return Err(PamError::OutOfOrder("nothing was being asked"));
        };

        match (style, a) {
            (MsgStyle::PromptEchoOn, PamAnswer::Visible(name)) => {
                let t = self.txn(h)?;
                t.user = Some(name);
                t.awaiting = Some(MsgStyle::PromptEchoOff);
                Ok(())
            }
            (MsgStyle::PromptEchoOff, PamAnswer::Secret(p)) => {
                let Some(user) = user else {
                    return Err(PamError::OutOfOrder("a passphrase before a username"));
                };

                // ── the verification, in pure Rust, no libpam ───────────
                // The plaintext exists for exactly this expression: it is
                // borrowed from `p`, handed to the hash comparison, and never
                // stored. `p` itself moves into the transaction only on
                // success, where `mint_proof` consumes it.
                let verdict = {
                    let plain = mukae_spec::capability::expose_authtok(&*self, &p);
                    mukae_native::verify_user(&shadow, &user, plain)
                }
                .map_err(|_| PamError::OutOfOrder("the shadow file could not be read"))?;

                let resolved = matches!(verdict, mukae_native::verify::Verdict::Accepted)
                    .then(|| uid_of(&user))
                    .flatten();

                let t = self.txn(h)?;
                t.awaiting = None;
                match resolved {
                    Some(uid) => {
                        t.uid = Some(uid);
                        t.authenticated = true;
                        t.authtok = Some(p);
                    }
                    // ★ A HASH THAT MATCHED BUT NO passwd ENTRY IS A REFUSAL.
                    // Inventing a uid here would start a session as whoever
                    // that number happens to be. It is a real state on a host
                    // whose shadow and passwd sources disagree, and the safe
                    // reading is "no".
                    None => t.refused = true,
                }
                Ok(())
            }
            _ => Err(PamError::OutOfOrder("the answer did not match the prompt")),
        }
    }

    fn pam_acct_mgmt(&mut self, h: PamHandleId) -> Result<AcctVerdict, PamError> {
        let t = self.txn(h)?;
        if t.authenticated {
            Ok(AcctVerdict::Ok)
        } else {
            Ok(AcctVerdict::PermDenied)
        }
    }

    fn pam_chauthtok(&mut self, h: PamHandleId) -> Result<(), PamError> {
        let _ = self.txn(h)?;
        // ★ REFUSED, NOT SILENTLY SUCCEEDED. `AcctVerdict::NewAuthTokRequired`
        // exists so a flow cannot skip a mandatory token change; returning
        // `Ok` here would defeat that by letting an expired account through
        // with nothing changed.
        Err(PamError::OutOfOrder(
            "changing an expired passphrase is not implemented in the native environment",
        ))
    }

    fn pam_setcred(&mut self, h: PamHandleId, _f: CredFlag) -> Result<(), PamError> {
        // Nothing to establish: there is no credential cache, no kerberos
        // ticket and no keyring in this environment. A no-op that says so.
        let _ = self.txn(h)?;
        Ok(())
    }

    fn pam_putenv(&mut self, h: PamHandleId, kv: EnvPair) -> Result<(), PamError> {
        let t = self.txn(h)?;
        t.env.insert(kv.key, kv.value);
        Ok(())
    }

    fn pam_open_session(&mut self, h: PamHandleId) -> Result<(), PamError> {
        // Read the console before the mutable borrow of the transaction.
        let (seat, vtnr) = match &self.console {
            Console::Seatless => (String::new(), 0u32),
            Console::Vt { seat, vtnr } => (seat.clone(), vtnr.get()),
        };
        let t = self.txn(h)?;
        if !t.authenticated {
            return Err(PamError::OutOfOrder(
                "a session cannot be opened for an unauthenticated transaction",
            ));
        }
        let uid = t.uid.ok_or(PamError::OutOfOrder("no uid resolved"))?;
        let req = mukae_native::logind::Request {
            uid: uid.0,
            pid: std::process::id(),
            service: "mukae".to_string(),
            kind: mukae_native::logind::Kind::Tty,
            class: mukae_native::logind::Class::User,
            desktop: String::new(),
            // ★ FROM THE TYPE, so the illegal pairing cannot be written. See
            // `Console`: seat0 with vtnr 0 is refused by logind with an error
            // that names neither field.
            seat,
            vtnr,
            tty: String::new(),
            display: String::new(),
            remote: false,
            remote_user: String::new(),
            remote_host: String::new(),
        };
        let sess = mukae_native::logind::create_session(&req).map_err(|e| {
            // ★ THE REASON IS PRINTED BECAUSE THE TYPE CANNOT CARRY IT.
            // `PamError::OutOfOrder` takes a `&'static str`, so mapping into
            // it discards logind's own message — and "logind refused the
            // session" is exactly the useless error this codebase refuses
            // everywhere else. Until the border grows an owned arm, the
            // reason goes to stderr rather than nowhere.
            eprintln!("mukae-seat: logind refused CreateSession: {e}");
            PamError::OutOfOrder("logind refused the session")
        })?;
        // logind is what creates /run/user/<uid>, and it reports back the
        // values the session must carry. Read them from the reply rather than
        // deriving them here, so the two cannot disagree.
        // Read from the reply rather than derived here, so the session's
        // idea of its own runtime dir and the environment's cannot disagree.
        // XDG_RUNTIME_DIR is the one that matters most: a session that does
        // not export it leaves every consumer falling back to /tmp.
        t.env
            .insert("XDG_RUNTIME_DIR".to_string(), sess.runtime_path.clone());
        t.env.insert("XDG_SESSION_ID".to_string(), sess.id.clone());
        t.env.insert("XDG_SEAT".to_string(), sess.seat.clone());
        t.env.insert("XDG_VTNR".to_string(), sess.vtnr.to_string());
        t.session = Some(sess);
        Ok(())
    }

    fn pam_getenvlist(&mut self, h: PamHandleId) -> Result<EnvSet, PamError> {
        let t = self.txn(h)?;
        Ok(EnvSet(t.env.clone().into_iter().collect()))
    }

    fn pam_close_session(&mut self, h: PamHandleId) -> Result<(), PamError> {
        let t = self.txn(h)?;
        // Dropping the descriptor is what ends the session, so this is the
        // close: explicit, and paired with the open by construction.
        t.session = None;
        Ok(())
    }

    fn pam_end(&mut self, h: PamHandleId) -> Result<(), PamError> {
        self.txns.remove(&h.0).ok_or(PamError::NoSuchHandle)?;
        Ok(())
    }

    fn fork_session(
        &mut self,
        plan: &SessionPlan,
        env: &EnvSet,
        to: Uid,
    ) -> Result<ChildPid, SpawnError> {
        let prepared = spawn::prepare(plan, env, to)?;
        spawn::spawn(&prepared)
    }

    fn resolve_principal(&self, n: &UserName) -> Answer<PublicProfile> {
        match uid_of(n.as_str()) {
            Some(uid) => Answer::Found(PublicProfile {
                uid,
                name: n.clone(),
                display_name: None,
            }),
            // ★ `Empty` — a finding, not an error. "There is no such user" is
            // a fact the face should render differently from "NSS timed out".
            None => Answer::Empty { of: "principal" },
        }
    }

    fn enumerate_principals(&self) -> Answer<Vec<PublicProfile>> {
        // ★ REFUSED, and honestly. Walking every NSS source is a real feature;
        // a half-done one that lists local users and silently omits LDAP
        // accounts is worse than saying it does not enumerate, because the
        // omission is invisible on the machine where it matters.
        Answer::Refused {
            because: "the native environment does not enumerate principals".to_string(),
            legal: vec!["resolve_principal by exact name".to_string()],
        }
    }

    fn uid_for_handle(&self, h: PamHandleId) -> Result<Uid, PamError> {
        self.txns
            .get(&h.0)
            .ok_or(PamError::NoSuchHandle)?
            .uid
            .ok_or(PamError::OutOfOrder("no uid resolved yet"))
    }

    fn mint_proof(&mut self, h: PamHandleId, uid: Uid) -> Result<AuthProof, PamError> {
        let authed = {
            let t = self.txns.get(&h.0).ok_or(PamError::NoSuchHandle)?;
            t.authenticated
        };
        if !authed {
            // ★ THE RUNTIME HALF OF THE CAPABILITY SEAL. The type system stops
            // a caller building a capability without a proof; this stops the
            // ENVIRONMENT handing out a proof for a login that never
            // succeeded. Both halves are needed and neither implies the other.
            return Err(PamError::OutOfOrder(
                "cannot mint a proof from an unfinished conversation",
            ));
        }
        let tok = self
            .txns
            .get_mut(&h.0)
            .ok_or(PamError::NoSuchHandle)?
            .authtok
            .take()
            .ok_or(PamError::OutOfOrder("the authtok was already consumed"))?;
        Ok(mukae_spec::capability::mint_password_proof(self, uid, tok))
    }

    fn clock(&self) -> mukae_spec::env::Instant {
        // The spec's own monotonic stamp, not `std::time::Instant`: the border
        // is a plain `u64` so a spec consumer needs no clock type of its own.
        mukae_spec::env::Instant(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64),
        )
    }
}

/// Resolve a username to a uid through NSS.
///
/// `getpwnam_r`, never a read of `/etc/passwd`: an LDAP or SSSD account must
/// resolve exactly as a local one does, and reading the file is the shortcut
/// that works on the author's laptop and fails on every directory-backed host.
fn uid_of(user: &str) -> Option<Uid> {
    let c = std::ffi::CString::new(user).ok()?;
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0i8; 4096];
    let mut out = std::ptr::null_mut::<libc::passwd>();
    let rc = unsafe {
        libc::getpwnam_r(
            c.as_ptr(),
            &raw mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut out,
        )
    };
    if rc != 0 || out.is_null() {
        return None;
    }
    Some(Uid(entry.pw_uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> NativeSeatEnv {
        NativeSeatEnv::with_shadow(std::path::PathBuf::from("/nonexistent/shadow"))
    }

    #[test]
    fn a_transaction_with_a_known_user_asks_for_the_passphrase_first() {
        let mut e = env();
        let h = e
            .pam_start(
                &ServiceName::parse("login").unwrap(),
                Some(&UserName::parse("luis").unwrap()),
            )
            .unwrap();
        match e.pam_next(h).unwrap() {
            PamStep::Prompt { style, .. } => assert_eq!(
                style,
                MsgStyle::PromptEchoOff,
                "a username we were handed must not be asked for again"
            ),
            other => panic!("expected a masked prompt, got {other:?}"),
        }
    }

    #[test]
    fn a_transaction_with_no_user_asks_for_one_in_the_clear() {
        let mut e = env();
        let h = e
            .pam_start(&ServiceName::parse("login").unwrap(), None)
            .unwrap();
        match e.pam_next(h).unwrap() {
            PamStep::Prompt { style, .. } => assert_eq!(style, MsgStyle::PromptEchoOn),
            other => panic!("expected a visible prompt, got {other:?}"),
        }
    }

    /// ★ THE RUNTIME HALF OF THE CAPABILITY SEAL.
    #[test]
    fn a_proof_cannot_be_minted_from_an_unfinished_conversation() {
        let mut e = env();
        let h = e
            .pam_start(&ServiceName::parse("login").unwrap(), None)
            .unwrap();
        assert!(
            e.mint_proof(h, Uid(1000)).is_err(),
            "an environment must not hand out a proof for a login that never succeeded"
        );
    }

    #[test]
    fn a_session_cannot_be_opened_for_an_unauthenticated_transaction() {
        let mut e = env();
        let h = e
            .pam_start(&ServiceName::parse("login").unwrap(), None)
            .unwrap();
        assert!(e.pam_open_session(h).is_err());
    }

    /// An expired token must not be waved through: returning `Ok` here would
    /// defeat `AcctVerdict::NewAuthTokRequired`, whose whole job is to make
    /// the change unskippable.
    #[test]
    fn changing_an_expired_token_is_refused_rather_than_faked() {
        let mut e = env();
        let h = e
            .pam_start(&ServiceName::parse("login").unwrap(), None)
            .unwrap();
        assert!(e.pam_chauthtok(h).is_err());
    }

    #[test]
    fn enumeration_refuses_rather_than_returning_a_partial_list() {
        let e = env();
        assert!(
            matches!(e.enumerate_principals(), Answer::Refused { .. }),
            "a list that silently omits directory users is worse than no list"
        );
    }

    #[test]
    fn an_unknown_handle_is_refused_everywhere() {
        let mut e = env();
        let bogus = PamHandleId(999);
        assert!(e.pam_next(bogus).is_err());
        assert!(e.pam_acct_mgmt(bogus).is_err());
        assert!(e.pam_getenvlist(bogus).is_err());
        assert!(e.pam_end(bogus).is_err());
    }
}

/// Spawn a process as `to`, letting it keep ONE descriptor at a known number.
///
/// The greeter's spawn. It goes through the same drop the session uses —
/// `initgroups`/`setgid`/`setuid`, verified — rather than a second, weaker
/// implementation written for the unprivileged half. See
/// [`spawn::Prepared::inherit`] for why the descriptor is named rather than
/// CLOEXEC being relaxed.
///
/// # Errors
/// As [`mukae_spec::env::SeatEnv::fork_session`].
pub fn spawn_inheriting(
    plan: &SessionPlan,
    env: &EnvSet,
    to: Uid,
    inherit: Vec<(i32, i32)>,
) -> Result<ChildPid, SpawnError> {
    let prepared = spawn::prepare_inheriting(plan, env, to, inherit)?;
    spawn::spawn(&prepared)
}
