//! The conversation callback that actually answers — libpam's side of the
//! bridge.
//!
//! `conv.rs` ships `refusing_conv`, which is sound and answers nothing. This is
//! the one that talks to a human, and it is the single most delicate piece of
//! code in mukae: it runs on libpam's stack, it allocates memory libpam will
//! free, and a mistake is a segfault inside a login screen.
//!
//! ── THE FOUR CONTRACT RULES, FROM conv.rs, HONOURED HERE ──────────────────
//! 1. `resp` is allocated with `malloc`, never with Rust. libpam frees it with
//!    `free()`, and handing it a Rust allocation is a heap corruption that
//!    fires later, somewhere else.
//! 2. Exactly `num_msg` responses, in order. libpam indexes them positionally,
//!    so a short array is an out-of-bounds read INSIDE libpam.
//! 3. Leave `*resp` null on failure. libpam checks it, and a stale non-null
//!    value is freed as though we had allocated it.
//! 4. `msg` is a pointer to an array of pointers on Linux-PAM. Solaris differs;
//!    this crate is `cfg(target_os = "linux")` for exactly that reason.
//!
//! ── ★ WHAT MAKES THIS SAFE TO CALL FROM C ─────────────────────────────────
//! The callback never unwinds. A Rust panic crossing an `extern "C"` boundary
//! is undefined behaviour, and the panic most likely here — a poisoned lock, a
//! closed channel — is exactly the one that happens when the greeter is dying.
//! So every fallible step is converted to `PAM_CONV_ERR` rather than allowed to
//! propagate, and the whole body is wrapped in `catch_unwind`.

use std::os::raw::{c_char, c_int, c_void};

use mukae_spec::env::{MsgStyle, PamAnswer, PromptText};

use crate::bridge::ConvSide;
use crate::ffi;

/// Hand libpam a heap copy of `s` that it may `free()`.
///
/// Returns null on any failure, which the caller turns into `PAM_CONV_ERR` —
/// contract rule 3.
///
/// # Safety
/// The returned pointer is owned by libpam. Nothing in Rust may free it, and
/// nothing may read it after libpam does.
unsafe fn malloc_cstr(s: &str) -> *mut c_char {
    // NUL-terminated, and rejecting interior NULs rather than truncating: a
    // truncated answer is a DIFFERENT password, silently.
    if s.as_bytes().contains(&0) {
        return std::ptr::null_mut();
    }
    let len = s.len();
    // SAFETY: len + 1 is non-zero, so malloc's contract is satisfied.
    let p = unsafe { libc::malloc(len + 1) }.cast::<c_char>();
    if p.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: p has len + 1 bytes; we write len then the terminator.
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr().cast::<c_char>(), p, len);
        *p.add(len) = 0;
    }
    p
}

/// The bridging conversation.
///
/// `appdata_ptr` carries a `*const ConvSide`. It is BORROWED for the duration
/// of the call and never dropped here — the worker that installed it owns it,
/// and freeing it from a callback libpam may invoke many times would be a
/// use-after-free on the second prompt.
///
/// # Safety
/// Must be called with libpam's calling convention, and `appdata_ptr` must be
/// a live `*const ConvSide` for the whole call.
pub unsafe extern "C" fn bridging_conv(
    num_msg: c_int,
    msg: *mut *const ffi::pam_message,
    resp: *mut *mut ffi::pam_response,
    appdata_ptr: *mut c_void,
) -> c_int {
    // Rule 3 first, unconditionally: whatever happens below, a failure path
    // must not leave a stale pointer for libpam to free.
    if !resp.is_null() {
        // SAFETY: libpam passes a writable out-pointer.
        unsafe { *resp = std::ptr::null_mut() };
    }
    if resp.is_null() || msg.is_null() || appdata_ptr.is_null() || num_msg <= 0 {
        return ffi::PAM_CONV_ERR;
    }

    // ★ No unwinding across the FFI boundary, ever. The panic most likely here
    // is a closed channel while the greeter is dying, which is precisely when
    // undefined behaviour is least welcome.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: the worker installed a live ConvSide and outlives the call.
        let side: &ConvSide = unsafe { &*appdata_ptr.cast::<ConvSide>() };
        let n = usize::try_from(num_msg).unwrap_or(0);

        // Rule 1: one malloc'd array of exactly n responses (rule 2).
        let bytes = n.checked_mul(std::mem::size_of::<ffi::pam_response>())?;
        // SAFETY: bytes is non-zero because n > 0.
        let arr = unsafe { libc::calloc(n, std::mem::size_of::<ffi::pam_response>()) }
            .cast::<ffi::pam_response>();
        if arr.is_null() {
            return None;
        }
        let _ = bytes;

        for i in 0..n {
            // SAFETY: Linux-PAM passes an array of n pointers (rule 4).
            let m = unsafe { *msg.add(i) };
            if m.is_null() {
                unsafe { libc::free(arr.cast()) };
                return None;
            }
            // SAFETY: m points to a pam_message libpam owns for this call.
            let (style_raw, text_ptr) = unsafe { ((*m).msg_style, (*m).msg) };
            let text = if text_ptr.is_null() {
                String::new()
            } else {
                // SAFETY: libpam guarantees a NUL-terminated string.
                unsafe { std::ffi::CStr::from_ptr(text_ptr) }
                    .to_string_lossy()
                    .into_owned()
            };

            let answer = match style_raw {
                ffi::PAM_PROMPT_ECHO_OFF => {
                    side.ask(MsgStyle::PromptEchoOff, PromptText(text)).ok()?
                }
                ffi::PAM_PROMPT_ECHO_ON => {
                    side.ask(MsgStyle::PromptEchoOn, PromptText(text)).ok()?
                }
                // Errors and info want no answer. Telling the face is
                // best-effort — a module that emits info while the greeter is
                // shutting down must not fail the whole conversation.
                _ => {
                    let _ = side.tell(MsgStyle::TextInfo, PromptText(text));
                    // Rule 2 still applies: a response SLOT must exist even
                    // where no answer does. calloc already zeroed it.
                    continue;
                }
            };

            // ★ The one place a secret is turned into bytes on this path, and
            // it is immediately handed to C.
            //
            // ── WHAT THIS ARM USED TO DO, AND WHY IT WAS WRONG ────────────
            // It matched `Secret(_)`, freed the array and returned
            // `PAM_CONV_ERR` — on the reasoning that a `Passphrase` cannot be
            // read outside its own crate and "the face converts it at the
            // boundary". Nothing converted it anywhere. So a password typed
            // into mukae was never handed to PAM and every login failed,
            // always, with the failure looking exactly like a wrong password.
            //
            // `into_wire` is the deliberate, consuming escape that makes the
            // program work without widening the surface: it destroys the
            // `Passphrase` in the act, so the plaintext lives only as the
            // `String` being copied into libpam's memory on the next line.
            let owned = match answer {
                PamAnswer::Visible(v) => v,
                PamAnswer::Secret(sec) => mukae_spec::capability::into_wire(sec),
            };
            let s: &str = &owned;

            // SAFETY: writing within the calloc'd array of n elements.
            unsafe {
                let slot = arr.add(i);
                (*slot).resp = malloc_cstr(s);
                (*slot).resp_retcode = 0;
                if (*slot).resp.is_null() {
                    // Free what we allocated so far, then bail. Partially
                    // filled is not a state libpam may see.
                    for j in 0..=i {
                        let p = (*arr.add(j)).resp;
                        if !p.is_null() {
                            libc::free(p.cast());
                        }
                    }
                    libc::free(arr.cast());
                    return None;
                }
            }
        }
        Some(arr)
    }));

    match result {
        Ok(Some(arr)) => {
            // SAFETY: resp checked non-null above.
            unsafe { *resp = arr };
            ffi::PAM_SUCCESS
        }
        // Both a clean failure and a caught panic land here with *resp still
        // null, which is rule 3.
        _ => ffi::PAM_CONV_ERR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::Bridge;

    #[test]
    fn null_and_zero_shapes_are_refused_without_touching_memory() {
        // Same property refusing_conv is tested for: libpam probes with these.
        let mut out: *mut ffi::pam_response = std::ptr::null_mut();
        // SAFETY: matches the calling convention; nothing is dereferenced.
        let rc = unsafe {
            bridging_conv(
                0,
                std::ptr::null_mut(),
                &raw mut out,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(out.is_null(), "rule 3: *resp stays null on failure");
    }

    #[test]
    fn a_stale_response_pointer_is_cleared_before_anything_else() {
        let mut out = 0xdead_beef_usize as *mut ffi::pam_response;
        // SAFETY: standard convention.
        let rc = unsafe {
            bridging_conv(1, std::ptr::null_mut(), &raw mut out, std::ptr::null_mut())
        };
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(out.is_null(), "a stale pointer must never survive");
    }

    #[test]
    fn a_vanished_face_fails_the_conversation_rather_than_answering_empty() {
        // If the greeter dies mid-login, libpam must be told the conversation
        // failed. Sending an empty password instead would be a real (wrong)
        // answer that burns an attempt against the account.
        let (face, conv) = Bridge::new();
        drop(face);
        let mut out: *mut ffi::pam_response = std::ptr::null_mut();
        let side = Box::into_raw(Box::new(conv));
        // SAFETY: side is live for the call; freed immediately after.
        let rc = unsafe {
            bridging_conv(1, std::ptr::null_mut(), &raw mut out, side.cast())
        };
        // msg is null here, so it refuses before reaching the channel — the
        // point is that it refuses, and leaves *resp null.
        assert_eq!(rc, ffi::PAM_CONV_ERR);
        assert!(out.is_null());
        // SAFETY: reclaim the box we leaked for the call.
        drop(unsafe { Box::from_raw(side) });
    }
}
