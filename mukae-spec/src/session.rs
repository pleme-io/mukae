//! Starting a session — and the two things that cannot happen while doing it.
//!
//! **Illegal state [8]: a session command re-split by a shell.** greetd's
//! recorded bug R1. A session is `Argv(Vec<OsString>)` here and there is no
//! `Display`, no `From<String>`, no `join` and no `to_shell` — so there is no
//! expression that turns a plan back into a string a shell could re-parse.
//! The exec path is `execve`, which takes the vector.
//!
//! **Illegal states [1] and [2]: starting an unauthenticated session, and
//! reusing one authentication twice.** [`start_session`] names
//! `SeatCapability<Authenticated>` as a parameter and takes it BY VALUE. A
//! caller with no capability cannot name the argument (E0061); a caller with
//! one gets exactly one session out of it (E0382).
//!
//! Taking the capability by value is deliberately stronger than escuta's `&`
//! on the analogous primitive: escuta's lock permits many writes under one
//! proof, and here one authentication must yield exactly one session.

use crate::capability::{Authenticated, SeatCapability};
use crate::env::{ChildPid, EnvSet, SeatEnv, SpawnError};
use std::ffi::OsString;

/// A session's argv. **The only shape a session command takes.**
///
/// Note what is absent, because the absence IS the mechanism: no `Display`,
/// no `From<String>`, no `join`, no `as_shell_string`. There is no method
/// that produces something a shell would re-split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argv(Vec<OsString>);

impl Argv {
    /// # Errors
    /// [`SessionError::EmptyArgv`] — `execve` needs a program to run, and an
    /// empty argv is the shape that turns into "run the user's shell" in
    /// managers that accept it.
    pub fn new(parts: Vec<OsString>) -> Result<Self, SessionError> {
        if parts.is_empty() {
            return Err(SessionError::EmptyArgv);
        }
        Ok(Self(parts))
    }

    #[must_use]
    pub fn program(&self) -> &OsString {
        &self.0[0]
    }

    #[must_use]
    pub fn as_slice(&self) -> &[OsString] {
        &self.0
    }
}

/// What to run, and as whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlan {
    pub argv: Argv,
    /// Extra environment mukae contributes on top of PAM's.
    pub env: EnvSet,
}

/// A running session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHandle {
    pub pid: ChildPid,
    pub uid: crate::ids::Uid,
    pub seat: crate::ids::SeatId,
    /// The environment the session was actually started with — PAM's, plus
    /// mukae's. Kept so `mukae explain` can answer "where did this value come
    /// from?" without re-deriving it.
    pub env: EnvSet,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("argv is empty; execve needs a program")]
    EmptyArgv,
    #[error("pam: {0}")]
    Pam(#[from] crate::env::PamError),
    #[error("spawn: {0}")]
    Spawn(#[from] SpawnError),
}

/// Start a session. **The signature is the lock.**
///
/// The ordering below is not arbitrary and is the half of a login where the
/// real bugs live (`MUKAE.md` §9, "genuinely hard"). Each step is here because
/// doing it in a different order breaks something silently:
///
/// 1. `pam_setcred(Establish)` — BEFORE the privilege drop, because
///    establishing credentials is what acquires the Kerberos ticket, and after
///    the drop there is no privilege left to acquire it with.
/// 2. `pam_putenv` — before `open_session`, because session modules read the
///    environment they are given.
/// 3. `pam_open_session` — this is what creates `/run/user/<uid>`.
/// 4. `pam_getenvlist` — AFTER open_session, because that is when the session
///    modules have contributed their variables.
/// 5. fork.
///
/// Getting 1 wrong breaks the keyring and kerberos, and it breaks them
/// *silently*: the login succeeds and the user finds out later that their
/// tickets are missing.
///
/// # Errors
/// [`SessionError`] if any PAM step or the spawn fails. The capability is
/// consumed either way — a failed start does not hand back a reusable
/// authentication.
pub fn start_session<E: SeatEnv>(
    env: &mut E,
    cap: SeatCapability<Authenticated>,
    plan: SessionPlan,
) -> Result<SessionHandle, SessionError> {
    let h = cap.pam_handle();

    // 1 — credentials BEFORE the drop.
    env.pam_setcred(h, crate::env::CredFlag::Establish)?;

    // 2 — contribute the environment the session modules will read.
    for (key, value) in &plan.env.0 {
        env.pam_putenv(
            h,
            crate::env::EnvPair {
                key: key.clone(),
                value: value.clone(),
            },
        )?;
    }

    // 3 — this is what creates /run/user/<uid>.
    env.pam_open_session(h)?;

    // 4 — read the environment AFTER the session modules ran.
    let session_env = env.pam_getenvlist(h)?;

    // 5 — fork.
    let pid = env.fork_session(&plan, &session_env, cap.uid())?;

    Ok(SessionHandle {
        pid,
        uid: cap.uid(),
        seat: cap.seat().clone(),
        env: session_env,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_argv_dies_at_the_boundary() {
        assert_eq!(Argv::new(vec![]).unwrap_err(), SessionError::EmptyArgv);
    }

    /// ★ ILLEGAL STATE [8]. There is no expression producing a shell string
    /// from a plan, so a session command cannot be re-split. This test can
    /// only assert the positive half — that argv survives intact with spaces
    /// and quotes preserved as ONE element; the absence of `Display` is
    /// proven by tests/ui/argv_to_shell_string.rs.
    #[test]
    fn argv_elements_survive_whole() {
        let a = Argv::new(vec![
            OsString::from("/run/current-system/sw/bin/omoya"),
            OsString::from("--mode session"),
            OsString::from("a b; rm -rf /"),
        ])
        .unwrap();
        assert_eq!(a.as_slice().len(), 3);
        assert_eq!(a.as_slice()[2], OsString::from("a b; rm -rf /"));
        assert_eq!(
            a.program(),
            &OsString::from("/run/current-system/sw/bin/omoya")
        );
    }
}
