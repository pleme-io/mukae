//! The libpam ABI, declared.
//!
//! Hand-written rather than taken from a bindings crate, for one reason: this
//! is the boundary where a login either is or is not correct, and every
//! signature below is short enough to check against `security/pam_appl.h` by
//! eye. A generated binding would be larger, and nobody would read it.
//!
//! ## Verified against linux-pam 1.7.1
//!
//! Every declaration here matches `pam_appl.h` from the store path
//! `linux-pam-1.7.1`. The crate compiles and LINKS against that library — see
//! `docs/VERIFICATION.md` for the transcript. Compiling is not running, and
//! the distinction is the whole tier story for this crate.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

/// Opaque. libpam owns it; we hold a pointer and never dereference it.
#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

/// A message FROM pam TO the application.
///
/// `msg_style` is one of the `PAM_PROMPT_*` / `PAM_*_MSG` constants below.
#[repr(C)]
pub struct pam_message {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

/// A response FROM the application TO pam.
///
/// ★ **`resp` MUST be allocated with `malloc`.** libpam frees it with `free`,
/// so handing it a Rust-allocated pointer is a cross-allocator free —
/// undefined behaviour, and the kind that works on the machine you test it on.
/// [`crate::conv`] does the malloc explicitly for this reason.
#[repr(C)]
pub struct pam_response {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

/// The conversation callback pam calls to ask the human something.
///
/// The signature is the delicate part of the whole interface:
/// - `num_msg` messages arrive as an ARRAY OF POINTERS (`*mut *const
///   pam_message`), not a pointer to an array. Linux-PAM and Solaris PAM
///   famously disagree here; this is the Linux shape.
/// - the callback allocates and returns `num_msg` responses through `resp`.
/// - `appdata_ptr` is whatever was in the `pam_conv` struct — our state.
pub type pam_conv_fn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
pub struct pam_conv {
    pub conv: Option<pam_conv_fn>,
    pub appdata_ptr: *mut c_void,
}

// ── Return codes (pam_appl.h) ────────────────────────────────────────
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CRED_INSUFFICIENT: c_int = 8;
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_MAXTRIES: c_int = 11;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
pub const PAM_ACCT_EXPIRED: c_int = 13;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_ABORT: c_int = 26;

// ── Message styles ───────────────────────────────────────────────────
pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
pub const PAM_ERROR_MSG: c_int = 3;
pub const PAM_TEXT_INFO: c_int = 4;

// ── setcred flags ────────────────────────────────────────────────────
pub const PAM_ESTABLISH_CRED: c_int = 0x0002;
pub const PAM_DELETE_CRED: c_int = 0x0004;
pub const PAM_REINITIALIZE_CRED: c_int = 0x0008;
pub const PAM_REFRESH_CRED: c_int = 0x0010;

#[link(name = "pam")]
unsafe extern "C" {
    pub fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const pam_conv,
        pamh: *mut *mut pam_handle_t,
    ) -> c_int;

    pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_acct_mgmt(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_chauthtok(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_setcred(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_open_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_close_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_putenv(pamh: *mut pam_handle_t, name_value: *const c_char) -> c_int;
    pub fn pam_getenvlist(pamh: *mut pam_handle_t) -> *mut *mut c_char;
    pub fn pam_end(pamh: *mut pam_handle_t, pam_status: c_int) -> c_int;
    pub fn pam_strerror(pamh: *mut pam_handle_t, errnum: c_int) -> *const c_char;
}
