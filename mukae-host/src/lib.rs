//! # `mukae-host` — the real PAM linkage
//!
//! The only crate in the tree that names `libc`, and the only one that may:
//! `mukae-spec` closes illegal state [14] by *not* depending on it, and that
//! proof is only meaningful if the syscalls have somewhere else to live.
//!
//! ## ★ TIER — read this before citing this crate
//!
//! **COMPILED AND LINKED against linux-pam 1.7.1 on x86_64-linux. NEVER RUN.**
//!
//! Not one line of this has authenticated anybody. `theory/MUKAE.md` M3's
//! done-predicate is a `loginctl show-session` transcript from a real VM
//! reporting `Type=tty Class=user Seat=seat0 VTNr=N`, plus `/run/user/<uid>`
//! existing during a session and being *gone* after logout. None of that has
//! happened. What HAS happened is that these declarations match
//! `security/pam_appl.h`, the crate links against the real library, and the
//! memory contracts are written down where a reviewer can check them.
//!
//! Compiling is not running, and for an authentication path the gap between
//! those two is exactly where the bugs live.
//!
//! ## What is implemented and what deliberately is not
//!
//! | | |
//! |---|---|
//! | `setcred` / `putenv` / `open_session` / `getenvlist` / `close_session` / `end` / `acct_mgmt` / `chauthtok` | implemented — straight calls with typed error mapping |
//! | the CONVERSATION (`pam_next` / `pam_answer`) | **returns a typed error**, and the reason is below |
//!
//! ### The conversation is a push/pull impedance mismatch, not an oversight
//!
//! `SeatEnv` models the conversation as a **pull**: `pam_next` returns one
//! step and the caller answers. That is the right shape for a face — it is
//! what lets a greeter handle 2FA, an expired password and a smartcard without
//! a redesign, and it is why `mukae-spec` has no method taking a username and
//! password together.
//!
//! libpam's real interface is a **push**: you hand `pam_start` a callback, call
//! `pam_authenticate`, and libpam calls *you* — synchronously, from inside its
//! own stack, possibly several times, on a thread it chose.
//!
//! Bridging those needs either a thread with a channel per transaction, or a
//! coroutine. Both are correct; both are more than a compile-check can verify;
//! and getting the callback's memory ownership wrong is a security bug in an
//! auth path rather than a crash. So the conversation methods return
//! [`HostError::ConversationNotBridged`] — a typed refusal naming the work —
//! instead of a plausible-looking implementation nobody has run.
//!
//! A placeholder `Ok` here would be the worst artifact in the repository: an
//! authentication that always succeeds, behind a signature that reads as done.

#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg(target_os = "linux")]

pub mod authenticate;
pub mod bridge;
pub mod bridging_conv;
pub mod conv;
pub mod ffi;

use mukae_spec::env::{
    AcctVerdict, CredFlag, EnvPair, EnvSet, Instant, PamAnswer, PamClass, PamError, PamStep,
};
use mukae_spec::ids::{PamHandleId, ServiceName, Uid, UserName};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("a NUL byte in {0} — it cannot cross into C")]
    InteriorNul(&'static str),
    #[error(
        "the PAM conversation is not bridged. libpam PUSHES through a callback \
         while SeatEnv PULLS one step at a time; bridging needs a thread with a \
         channel per transaction, and that is unwritten rather than stubbed \
         because a plausible-looking auth path nobody has run is worse than an \
         absent one"
    )]
    ConversationNotBridged,
    #[error("no such handle")]
    NoSuchHandle,
    #[error("pam: {0}")]
    Pam(String),
}

/// Map libpam's return code onto the border's closed class.
///
/// Every arm is here because the distinction matters somewhere: `MAXTRIES`
/// separate from `AUTH_ERR` because retrying on the former locks an account,
/// and `NEW_AUTHTOK_REQD` is NOT a failure — it is a successful authentication
/// that must be followed by a token change.
#[must_use]
pub fn class_of(code: c_int) -> PamClass {
    match code {
        ffi::PAM_USER_UNKNOWN => PamClass::UserUnknown,
        ffi::PAM_MAXTRIES => PamClass::MaxTries,
        ffi::PAM_CRED_INSUFFICIENT => PamClass::CredInsufficient,
        ffi::PAM_AUTHINFO_UNAVAIL => PamClass::AuthInfoUnavail,
        ffi::PAM_ABORT | ffi::PAM_SYSTEM_ERR | ffi::PAM_BUF_ERR => PamClass::Abort,
        _ => PamClass::AuthError,
    }
}

/// Map an account-management code onto the border's verdict.
#[must_use]
pub fn verdict_of(code: c_int) -> AcctVerdict {
    match code {
        ffi::PAM_SUCCESS => AcctVerdict::Ok,
        ffi::PAM_NEW_AUTHTOK_REQD => AcctVerdict::NewAuthTokRequired,
        ffi::PAM_ACCT_EXPIRED => AcctVerdict::AcctExpired,
        _ => AcctVerdict::PermDenied,
    }
}

#[must_use]
pub const fn cred_flag(f: CredFlag) -> c_int {
    match f {
        CredFlag::Establish => ffi::PAM_ESTABLISH_CRED,
        CredFlag::Delete => ffi::PAM_DELETE_CRED,
        CredFlag::Reinitialize => ffi::PAM_REINITIALIZE_CRED,
        CredFlag::Refresh => ffi::PAM_REFRESH_CRED,
    }
}

/// One live PAM transaction.
struct Txn {
    pamh: *mut ffi::pam_handle_t,
    uid: Option<Uid>,
}

/// A `SeatEnv` backed by the real libpam.
///
/// **Never run.** See this module's tier note.
#[derive(Default)]
pub struct HostSeatEnv {
    txns: BTreeMap<u64, Txn>,
    next: u64,
}

impl HostSeatEnv {
    #[must_use]
    pub fn new() -> Self {
        Self {
            txns: BTreeMap::new(),
            next: 1,
        }
    }

    fn handle(&self, h: PamHandleId) -> Result<*mut ffi::pam_handle_t, PamError> {
        self.txns
            .get(&h.0)
            .map(|t| t.pamh)
            .ok_or(PamError::NoSuchHandle)
    }

    /// Start a transaction.
    ///
    /// # Errors
    /// [`HostError`] if a name carries an interior NUL or libpam refuses.
    ///
    /// # Panics
    /// Never.
    pub fn start(
        &mut self,
        svc: &ServiceName,
        user: Option<&UserName>,
    ) -> Result<PamHandleId, HostError> {
        let c_svc =
            CString::new(svc.as_str()).map_err(|_| HostError::InteriorNul("service name"))?;
        let c_user = match user {
            Some(u) => Some(CString::new(u.as_str()).map_err(|_| HostError::InteriorNul("user"))?),
            None => None,
        };

        // The conversation is not bridged, so the struct carries a callback
        // that refuses rather than a null pointer: libpam is entitled to call
        // it, and a null there is a segfault instead of a typed failure.
        let conv = ffi::pam_conv {
            conv: Some(conv::refusing_conv),
            appdata_ptr: ptr::null_mut(),
        };

        let mut pamh: *mut ffi::pam_handle_t = ptr::null_mut();
        // SAFETY: c_svc and c_user outlive the call; `conv` is a valid
        // initialised struct; `pamh` is a writable out-pointer. libpam copies
        // what it needs during pam_start.
        let rc = unsafe {
            ffi::pam_start(
                c_svc.as_ptr(),
                c_user.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &raw const conv,
                &raw mut pamh,
            )
        };
        if rc != ffi::PAM_SUCCESS || pamh.is_null() {
            return Err(HostError::Pam(format!("pam_start returned {rc}")));
        }

        let id = self.next;
        self.next += 1;
        self.txns.insert(id, Txn { pamh, uid: None });
        Ok(PamHandleId(id))
    }
}

impl HostSeatEnv {
    /// Set an environment variable inside the transaction.
    ///
    /// # Errors
    /// [`PamError`] if the handle is unknown or libpam refuses.
    pub fn putenv(&mut self, h: PamHandleId, kv: &EnvPair) -> Result<(), PamError> {
        let pamh = self.handle(h)?;
        let pair = format!("{}={}", kv.key, kv.value);
        let c = CString::new(pair).map_err(|_| PamError::OutOfOrder("interior NUL in env pair"))?;
        // SAFETY: `pamh` came from a successful pam_start and has not been
        // ended; `c` outlives the call and libpam copies the string.
        let rc = unsafe { ffi::pam_putenv(pamh, c.as_ptr()) };
        if rc == ffi::PAM_SUCCESS {
            Ok(())
        } else {
            Err(PamError::Refused(class_of(rc)))
        }
    }

    /// Read the environment the PAM stack computed.
    ///
    /// ★ The returned array is OWNED BY THE CALLER: libpam mallocs both the
    /// array and every string, and the application must free each entry and
    /// then the array. Leaking it is the common bug; freeing it with the wrong
    /// allocator is the dangerous one.
    ///
    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    pub fn getenvlist(&mut self, h: PamHandleId) -> Result<EnvSet, PamError> {
        let pamh = self.handle(h)?;
        // SAFETY: `pamh` is live. The returned pointer is a NULL-terminated
        // malloc'd array of malloc'd C strings, owned by us from here on.
        let list = unsafe { ffi::pam_getenvlist(pamh) };
        if list.is_null() {
            return Ok(EnvSet::default());
        }

        let mut out = BTreeMap::new();
        let mut i = 0isize;
        loop {
            // SAFETY: the array is NULL-terminated, so this walk stops.
            let entry = unsafe { *list.offset(i) };
            if entry.is_null() {
                break;
            }
            // SAFETY: `entry` is a valid NUL-terminated C string from libpam.
            let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
            if let Ok(s) = std::str::from_utf8(bytes)
                && let Some((k, v)) = s.split_once('=')
            {
                out.insert(k.to_owned(), v.to_owned());
            }
            // SAFETY: libpam malloc'd this entry and handed us ownership.
            unsafe { libc::free(entry.cast::<libc::c_void>()) };
            i += 1;
        }
        // SAFETY: same — the array itself is ours to free.
        unsafe { libc::free(list.cast::<libc::c_void>()) };
        Ok(EnvSet(out))
    }

    /// # Errors
    /// [`PamError`] if the handle is unknown or libpam refuses.
    pub fn setcred(&mut self, h: PamHandleId, f: CredFlag) -> Result<(), PamError> {
        let pamh = self.handle(h)?;
        // SAFETY: `pamh` is live.
        let rc = unsafe { ffi::pam_setcred(pamh, cred_flag(f)) };
        if rc == ffi::PAM_SUCCESS {
            Ok(())
        } else {
            Err(PamError::Refused(class_of(rc)))
        }
    }

    /// # Errors
    /// [`PamError`] if the handle is unknown.
    pub fn acct_mgmt(&mut self, h: PamHandleId) -> Result<AcctVerdict, PamError> {
        let pamh = self.handle(h)?;
        // SAFETY: `pamh` is live.
        let rc = unsafe { ffi::pam_acct_mgmt(pamh, 0) };
        Ok(verdict_of(rc))
    }

    /// # Errors
    /// [`PamError`] if the handle is unknown or the change is refused.
    pub fn chauthtok(&mut self, h: PamHandleId) -> Result<(), PamError> {
        let pamh = self.handle(h)?;
        // SAFETY: `pamh` is live.
        let rc = unsafe { ffi::pam_chauthtok(pamh, 0) };
        if rc == ffi::PAM_SUCCESS {
            Ok(())
        } else {
            Err(PamError::Refused(class_of(rc)))
        }
    }

    /// # Errors
    /// [`PamError`] if the handle is unknown or the session cannot open.
    pub fn open_session(&mut self, h: PamHandleId) -> Result<(), PamError> {
        let pamh = self.handle(h)?;
        // SAFETY: `pamh` is live.
        let rc = unsafe { ffi::pam_open_session(pamh, 0) };
        if rc == ffi::PAM_SUCCESS {
            Ok(())
        } else {
            Err(PamError::Refused(class_of(rc)))
        }
    }

    /// # Errors
    /// [`PamError`] if the handle is unknown or the session cannot close.
    pub fn close_session(&mut self, h: PamHandleId) -> Result<(), PamError> {
        let pamh = self.handle(h)?;
        // SAFETY: `pamh` is live.
        let rc = unsafe { ffi::pam_close_session(pamh, 0) };
        if rc == ffi::PAM_SUCCESS {
            Ok(())
        } else {
            Err(PamError::Refused(class_of(rc)))
        }
    }

    /// End the transaction and drop the handle.
    ///
    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    pub fn end(&mut self, h: PamHandleId) -> Result<(), PamError> {
        let t = self.txns.remove(&h.0).ok_or(PamError::NoSuchHandle)?;
        // SAFETY: the handle came from pam_start and is removed from the map
        // first, so nothing can use it after this point.
        unsafe { ffi::pam_end(t.pamh, ffi::PAM_SUCCESS) };
        Ok(())
    }

    /// The conversation. **Not bridged** — see this module's header.
    ///
    /// # Errors
    /// Always [`HostError::ConversationNotBridged`].
    pub fn next_step(&mut self, _h: PamHandleId) -> Result<PamStep, HostError> {
        Err(HostError::ConversationNotBridged)
    }

    /// # Errors
    /// Always [`HostError::ConversationNotBridged`].
    pub fn answer(&mut self, _h: PamHandleId, _a: PamAnswer) -> Result<(), HostError> {
        Err(HostError::ConversationNotBridged)
    }

    /// The uid a completed transaction resolved to.
    ///
    /// # Errors
    /// [`PamError::NoSuchHandle`] for an unknown handle.
    pub fn uid_for(&self, h: PamHandleId) -> Result<Option<Uid>, PamError> {
        self.txns
            .get(&h.0)
            .map(|t| t.uid)
            .ok_or(PamError::NoSuchHandle)
    }

    #[must_use]
    pub fn clock(&self) -> Instant {
        // SAFETY: CLOCK_MONOTONIC into a zeroed timespec; the call only writes.
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
        #[allow(clippy::cast_sign_loss)]
        Instant(ts.tv_sec as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ THE CODE MAP IS THE PART A COMPILE-CHECK CAN ACTUALLY VERIFY, and
    /// every distinction below matters somewhere in the login flow.
    #[test]
    fn pam_codes_map_onto_the_borders_closed_classes() {
        // MAXTRIES is NOT AuthError: retrying on it locks an account.
        assert_eq!(class_of(ffi::PAM_MAXTRIES), PamClass::MaxTries);
        assert_eq!(class_of(ffi::PAM_AUTH_ERR), PamClass::AuthError);
        assert_eq!(class_of(ffi::PAM_USER_UNKNOWN), PamClass::UserUnknown);
        assert_eq!(class_of(ffi::PAM_ABORT), PamClass::Abort);
    }

    /// ★ AN EXPIRED PASSWORD IS A SUCCESSFUL AUTHENTICATION. Mapping
    /// NEW_AUTHTOK_REQD to a denial locks a user out on the exact day they
    /// most need to log in.
    #[test]
    fn an_expired_token_is_a_verdict_not_a_denial() {
        assert_eq!(
            verdict_of(ffi::PAM_NEW_AUTHTOK_REQD),
            AcctVerdict::NewAuthTokRequired
        );
        assert_eq!(verdict_of(ffi::PAM_SUCCESS), AcctVerdict::Ok);
        assert_eq!(verdict_of(ffi::PAM_ACCT_EXPIRED), AcctVerdict::AcctExpired);
    }

    #[test]
    fn cred_flags_match_pam_appl_h() {
        assert_eq!(cred_flag(CredFlag::Establish), 0x0002);
        assert_eq!(cred_flag(CredFlag::Delete), 0x0004);
        assert_eq!(cred_flag(CredFlag::Reinitialize), 0x0008);
        assert_eq!(cred_flag(CredFlag::Refresh), 0x0010);
    }

    /// ★ THE CONVERSATION REFUSES RATHER THAN PRETENDING. A placeholder `Ok`
    /// here would be an authentication that always succeeds behind a signature
    /// that reads as finished — the worst artifact this repository could hold.
    #[test]
    fn the_unbridged_conversation_refuses_loudly() {
        let mut env = HostSeatEnv::new();
        let err = env.next_step(PamHandleId(1)).unwrap_err();
        assert!(matches!(err, HostError::ConversationNotBridged));
        assert!(
            err.to_string().contains("PUSHES") && err.to_string().contains("PULL"),
            "the error must explain WHY, not just that: {err}"
        );
    }

    #[test]
    fn an_unknown_handle_is_refused_everywhere() {
        let mut env = HostSeatEnv::new();
        let h = PamHandleId(999);
        assert!(env.setcred(h, CredFlag::Establish).is_err());
        assert!(env.open_session(h).is_err());
        assert!(env.close_session(h).is_err());
        assert!(env.end(h).is_err());
    }

    /// The clock is monotonic and real — one of the few things on this crate
    /// that can be exercised without a PAM stack.
    #[test]
    fn the_clock_advances_or_holds_but_never_goes_back() {
        let env = HostSeatEnv::new();
        let a = env.clock();
        let b = env.clock();
        assert!(b >= a);
    }
}
