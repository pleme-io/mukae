//! mukae's own credential verification — no libpam, no `.so`, no C ABI.
//!
//! ── ★ WHY THIS EXISTS WHEN `mukae-host` ALREADY WORKS ─────────────────────
//! `mukae-host` links libpam and it works: libpam calls mukae's conversation,
//! takes a passphrase, returns a verdict. It is also a **guest**, and the
//! naturalize doctrine's waiver does not cover it. That waiver is for
//! standards we must SPEAK on a wire — magma speaking the Terraform provider
//! protocol. libpam is not a wire; it is a C library with an ABI, dlopened
//! from a `.so`, and calling into one is the guest shape naturalize exists to
//! retire.
//!
//! ── WHAT libpam WAS ACTUALLY DOING, MEASURED ──────────────────────────────
//! `/etc/pam.d/login` on the fleet's Linux node is ten module invocations over
//! six modules. Five are file I/O — read `/etc/pam/environment`, write
//! `/proc/self/loginuid`, append a lastlog record, `setrlimit` from a conf,
//! deny. One is a hash check against `/etc/shadow`. The last, `pam_systemd`,
//! registers the session with logind **over D-Bus** — which IS a wire, and
//! speaking it is the sanctioned posture.
//!
//! So there was never a technical reason for the `.so`. There was a shortest
//! path to a working login, which is a different thing.
//!
//! ── SCOPE, HONESTLY ───────────────────────────────────────────────────────
//! This crate is the CREDENTIAL half: read the shadow file, verify the hash,
//! produce the same conversation every other transport produces. It is not the
//! session half — no logind registration, no VT, no rlimits, no privilege
//! drop. Those are named and unbuilt.
//!
//! `pending-mukae-native: session (logind over zbus, loginuid, limits, VT)`
//!
//! ── ★ THE PRIVILEGE PROBLEM, STATED RATHER THAN SKIRTED ───────────────────
//! `/etc/shadow` is `root:shadow 0640`. A greeter running as an unprivileged
//! `greeter` user cannot read it, which is exactly why PAM ships the setuid
//! `unix_chkpwd` helper. mukae has the same problem and the same two answers:
//! run as root on the VT and drop privileges after — what greetd does — or
//! ship a small privileged verifier. Neither is chosen here, because choosing
//! it is the session half's decision and pretending otherwise would put a
//! security-shaped assumption in a crate that only checks hashes.

pub mod logind;
pub mod shadow;
pub mod verify;

use std::path::Path;

use shadow::{ShadowEntry, Validity};
use verify::{Verdict, verify, verify_absent_user};

/// Seconds in a day, for turning a UNIX timestamp into shadow(5)'s day count.
const DAY: i64 = 86_400;

/// Today, as shadow(5) counts days: whole days since the epoch, UTC.
///
/// ★ `div_euclid`, not `/`. Rust's `/` truncates toward zero, so a timestamp
/// before 1970 would round the wrong way — which matters not at all in
/// practice and costs nothing to get right, and getting it wrong here would
/// be an off-by-one in an account-expiry check.
#[must_use]
pub fn today_days(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(DAY)
}

/// Whether `user` may log in on day `today`, independently of the password.
///
/// ★ A SEPARATE READ OF THE SHADOW FILE FROM `verify_user`, deliberately.
/// PAM's `acct_mgmt` is its own step for a reason: the two answers are about
/// different things, and an account can expire between authentication and
/// session start. Re-reading is one `open` on a file already in page cache.
///
/// An absent user is [`Validity::AccountExpired`] — the safe reading, and
/// unreachable in practice because authentication refused first.
///
/// # Errors
/// The reason the shadow file could not be read, which is a different thing
/// from a refusal and must not be reported as one.
pub fn account_validity(shadow_path: &Path, user: &str, today: i64) -> Result<Validity, String> {
    let text = std::fs::read_to_string(shadow_path)
        .map_err(|e| format!("reading {}: {e}", shadow_path.display()))?;
    Ok(text
        .lines()
        .filter_map(ShadowEntry::parse_line)
        .find(|e| e.name == user)
        .map_or(Validity::AccountExpired, |e| e.validity(today)))
}

/// Whether `/etc/nologin` blocks this login, and the message it carries.
///
/// ★ ROOT IS EXEMPT, which is `pam_nologin`'s own rule and is the whole point
/// of the file: it exists so an administrator can lock everyone else out
/// while keeping a way back in. mukaed replaced the PAM stack and inherited
/// none of this — the file could sit there through a maintenance window with
/// every user still logging in.
///
/// Returns `None` when the file is absent, which is the normal state.
#[must_use]
pub fn nologin_block(path: &Path, is_root: bool) -> Option<String> {
    if is_root {
        return None;
    }
    // A file that exists but cannot be read still blocks: its presence is the
    // signal and its contents are only the message.
    match std::fs::metadata(path) {
        Ok(_) => Some(std::fs::read_to_string(path).unwrap_or_default()),
        Err(_) => None,
    }
}

/// Verify a passphrase for `user` against a shadow file.
///
/// ★ An absent user is NOT an early return. It runs `verify_absent_user`,
/// which spends a verification's worth of time against a ballast hash — see
/// `verify`'s rule 4. Returning early here would make "no such user"
/// measurably faster than "wrong password" and turn the login screen into a
/// username enumeration service, however careful the messages are.
///
/// # Errors
/// The reason the shadow file could not be read — which is nearly always
/// permissions, and is a DIFFERENT thing from a failed login. Collapsing them
/// would report "login incorrect" to someone whose credentials were fine on a
/// machine that was misconfigured.
pub fn verify_user(shadow_path: &Path, user: &str, passphrase: &str) -> Result<Verdict, String> {
    let text = std::fs::read_to_string(shadow_path)
        .map_err(|e| format!("reading {}: {e}", shadow_path.display()))?;

    let found = text
        .lines()
        .filter_map(ShadowEntry::parse_line)
        .find(|e| e.name == user);

    Ok(match found {
        Some(e) => verify(&e, passphrase),
        None => verify_absent_user(passphrase),
    })
}
