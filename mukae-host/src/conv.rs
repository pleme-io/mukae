//! The conversation callback — and why it currently refuses.
//!
//! ## Why a refusing callback rather than a null pointer
//!
//! `pam_start` takes a `pam_conv` struct, and libpam is entitled to call
//! whatever is in it. A null `conv` is not "no conversation" — it is a
//! segfault the first time a module asks anything. So the struct carries
//! [`refusing_conv`], which returns `PAM_CONV_ERR` and allocates nothing.
//!
//! A refusal is a typed failure the caller can read. A crash is not.
//!
//! ## The memory contract, written down because it is where the bugs are
//!
//! When a real conversation lands, it MUST obey all four of these. They are
//! recorded now, while there is nothing to get wrong, rather than discovered
//! later against a running auth stack:
//!
//! 1. **`resp` is allocated with `malloc`, never with Rust.** libpam frees it
//!    with `free`. Handing it a `Box::into_raw` pointer is a cross-allocator
//!    free — undefined behaviour of the kind that works on the machine you
//!    tested it on.
//! 2. **Exactly `num_msg` responses**, in the order asked. libpam indexes them
//!    positionally; a short array is an out-of-bounds read inside libpam.
//! 3. **On any failure, free everything already allocated and return
//!    `PAM_CONV_ERR`** with `*resp` left null. A partially-filled array handed
//!    back with an error code is a leak at best.
//! 4. **The messages arrive as an array of POINTERS** (`*mut *const
//!    pam_message`) on Linux-PAM. Solaris PAM uses a pointer to an array, and
//!    code written against one segfaults on the other. This crate is
//!    Linux-only for exactly this reason, and `lib.rs` is `cfg`-gated so a
//!    darwin build fails with a message instead of a link error.
//!
//! ## What bridging actually requires
//!
//! libpam PUSHES: it calls this function synchronously from inside
//! `pam_authenticate`, on its own stack. `SeatEnv` PULLS: `pam_next` returns
//! one step and the caller answers at its leisure.
//!
//! The bridge is a thread per transaction plus two channels — `pam_authenticate`
//! runs on the worker, and the callback blocks on a channel while the face
//! composes an answer. That is a well-understood shape and it is also the
//! shape where a mistake is a hung login rather than a compile error, so it
//! lands with M3's VM where `loginctl` can prove a session actually opened.

use crate::ffi;
use std::os::raw::{c_int, c_void};

/// A conversation that answers nothing and allocates nothing.
///
/// # Safety
/// Called by libpam with its own pointers. This implementation dereferences
/// none of them and writes only the out-parameter, so it is sound for any
/// arguments libpam can pass — including the `num_msg == 0` case some modules
/// use as a probe.
pub unsafe extern "C" fn refusing_conv(
    _num_msg: c_int,
    _msg: *mut *const ffi::pam_message,
    resp: *mut *mut ffi::pam_response,
    _appdata_ptr: *mut c_void,
) -> c_int {
    // Contract rule 3: leave *resp null on failure. libpam checks it, and a
    // stale non-null value here would be freed as if we had allocated it.
    if !resp.is_null() {
        // SAFETY: libpam passes a writable out-pointer; we write a null and
        // read nothing.
        unsafe { *resp = std::ptr::null_mut() };
    }
    ffi::PAM_CONV_ERR
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ THE CALLBACK IS SOUND FOR EVERY SHAPE libpam CAN HAND IT, including
    /// the null and zero-message cases some modules use as probes. This is one
    /// of the few things about the FFI boundary that can be exercised without
    /// a PAM stack, so it is exercised.
    #[test]
    fn the_refusing_conversation_is_sound_for_every_input_shape() {
        let mut out: *mut ffi::pam_response = std::ptr::null_mut();

        // SAFETY: matches libpam's calling convention; the impl reads nothing.
        let rc =
            unsafe { refusing_conv(0, std::ptr::null_mut(), &raw mut out, std::ptr::null_mut()) };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(
            out.is_null(),
            "contract rule 3: *resp stays null on failure"
        );

        // A caller that passes a null out-pointer must not crash us either.
        // SAFETY: same convention; the null is explicitly handled.
        let rc = unsafe {
            refusing_conv(
                3,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
    }

    /// A non-null `*resp` left over from a previous call is overwritten with
    /// null rather than passed back — otherwise libpam would free a pointer we
    /// never allocated.
    #[test]
    fn a_stale_response_pointer_is_cleared_not_forwarded() {
        let mut out = 0xdead_beef_usize as *mut ffi::pam_response;
        // SAFETY: standard convention.
        let rc =
            unsafe { refusing_conv(1, std::ptr::null_mut(), &raw mut out, std::ptr::null_mut()) };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(out.is_null(), "a stale pointer must not survive");
    }
}
