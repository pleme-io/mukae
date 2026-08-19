//! The end-to-end authentication: a real `pam_authenticate`, driven by a face.
//!
//! This is the piece every other file in `mukae-host` was built for. `bridge`
//! adapts push to pull, `bridging_conv` answers on libpam's stack, and this
//! runs the transaction that uses both.
//!
//! ── ★ WHY THE ConvSide LIVES ON THE WORKER'S STACK ────────────────────────
//! `pam_start` takes an `appdata_ptr` that libpam hands back to the callback on
//! every prompt. The obvious move is `Box::into_raw`, and it is wrong here:
//! nothing would own the box, and freeing it after `pam_authenticate` returns
//! races a module that prompts twice.
//!
//! Instead the `ConvSide` is a local on the worker thread and the pointer is a
//! borrow of it. The worker does not return until `pam_authenticate` does, so
//! the referent outlives every call libpam can make — which is the property the
//! callback's safety comment requires, expressed as a lifetime rather than as a
//! promise.
//!
//! ── WHAT THIS DOES NOT DO ─────────────────────────────────────────────────
//! It authenticates. It does not open a session, set credentials, or exec
//! anything — `acct_mgmt`, `setcred` and `open_session` are separate calls
//! `HostSeatEnv` already has, and running them from here would bury a
//! session-creating side effect inside a function named `authenticate`.

use std::ffi::CString;
use std::os::raw::c_void;
use std::ptr;

use mukae_spec::env::{PamClass, PamStep};
use mukae_spec::ids::{ServiceName, UserName};

use crate::bridge::{Bridge, ConvSide};
use crate::bridging_conv::bridging_conv;
use crate::ffi;

/// Start a real PAM authentication and return the face's half of the bridge.
///
/// The conversation runs on a detached worker. Callers step it with
/// [`Bridge::next`] and answer with [`Bridge::answer`] until a terminal step
/// arrives.
///
/// # Errors
/// Returns the reason as a `String` when the transaction cannot be started at
/// all — a bad service name, or `pam_start` refusing. Failures *during*
/// authentication arrive as a `PamStep::Failed` on the bridge instead, because
/// the face has to render them and a Result would make them a different shape
/// from every other step.
pub fn authenticate(svc: &ServiceName, user: Option<&UserName>) -> Result<Bridge, String> {
    // Built before the thread so a bad name fails here, synchronously, rather
    // than as a mysterious Failed step a moment later.
    let c_svc = CString::new(svc.as_str()).map_err(|_| "service name contains a NUL".to_string())?;
    let c_user = match user {
        Some(u) => {
            Some(CString::new(u.as_str()).map_err(|_| "username contains a NUL".to_string())?)
        }
        None => None,
    };

    let (face, conv) = Bridge::new();

    std::thread::spawn(move || {
        // ★ The ConvSide is OWNED here, on this stack, for the whole
        // transaction. See the module header: a Box::into_raw would have no
        // owner and freeing it after pam_authenticate races a module that
        // prompts more than once.
        let conv: ConvSide = conv;
        let appdata: *mut c_void = std::ptr::from_ref(&conv).cast_mut().cast();

        let pam_conv = ffi::pam_conv {
            conv: Some(bridging_conv),
            appdata_ptr: appdata,
        };

        let mut pamh: *mut ffi::pam_handle_t = ptr::null_mut();
        // SAFETY: c_svc/c_user outlive the call; pam_conv is initialised and
        // its appdata points at a live local; pamh is a writable out-pointer.
        let rc = unsafe {
            ffi::pam_start(
                c_svc.as_ptr(),
                c_user.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                &raw const pam_conv,
                &raw mut pamh,
            )
        };
        if rc != ffi::PAM_SUCCESS || pamh.is_null() {
            conv.finish(PamStep::Failed {
                class: PamClass::Abort,
            });
            return;
        }

        // SAFETY: pamh is the handle pam_start just produced.
        let rc = unsafe { ffi::pam_authenticate(pamh, 0) };

        // ★ End the transaction BEFORE reporting. pam_end releases libpam's
        // state, and reporting first would let a face that reacts instantly to
        // `Complete` race a handle that is still open.
        // SAFETY: pamh is live and has not been ended.
        unsafe { ffi::pam_end(pamh, rc) };

        conv.finish(if rc == ffi::PAM_SUCCESS {
            PamStep::Complete
        } else {
            // ★ The class is derived but NOT distinguished for the caller
            // beyond what PAM said. `class_of` maps the code; the face is
            // responsible for not turning UserUnknown into a different message
            // from AuthError, which would be a username oracle.
            PamStep::Failed {
                class: crate::class_of(rc),
            }
        });
    });

    Ok(face)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_name_with_a_nul_fails_synchronously() {
        // Synchronously, not as a Failed step: a caller that mistyped a service
        // name should learn at the call, not after a thread has spun up and a
        // face has drawn a prompt for a transaction that never existed.
        let bad = ServiceName::new("lo\0gin".to_string());
        assert!(authenticate(&bad, None).is_err());
    }

    #[test]
    fn an_unknown_service_reports_through_the_bridge_not_a_panic() {
        // PAM services are files in /etc/pam.d. A service nobody configured is
        // a normal runtime outcome — a misconfigured seat — and must arrive as
        // a step the face can render rather than as a crash on the worker.
        let svc = ServiceName::new("mukae-no-such-service-exists".to_string());
        let mut face = authenticate(&svc, None).expect("start is fine; the service is not");
        assert!(
            matches!(face.next(), PamStep::Failed { .. }),
            "an unknown PAM service must fail the transaction, not hang it"
        );
    }
}
