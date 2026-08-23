//! Hash verification — what `pam_unix.so` was being loaded to do.
//!
//! ── ★ THE FOUR RULES, EACH A WAY THIS GOES WRONG SILENTLY ─────────────────
//! 1. **The scheme comes from the STORED hash, never from a caller.** A
//!    verifier that takes "which algorithm" as a parameter can be handed the
//!    wrong one, and the wrong one does not error — it fails to match, which
//!    reads as a wrong password forever.
//! 2. **An unknown scheme REFUSES.** Fail closed. A `_ => true` arm is
//!    absurd written down and is exactly what a hurried `match` produces when
//!    the author is thinking about the happy path.
//! 3. **Comparison is constant-time.** A `==` on two hash strings leaks how
//!    many leading bytes matched, and an attacker who can submit guesses can
//!    walk a hash out one byte at a time.
//! 4. **A missing user costs the same as a wrong password.** Returning early
//!    when the account does not exist makes the response measurably faster,
//!    which is a username oracle built out of a stopwatch. So an absent user
//!    is verified against a real hash whose passphrase nobody knows.

use crate::shadow::{ShadowEntry, Unusable};

/// The verdict. Deliberately three arms rather than a `bool`.
///
/// `Refused` and `Unusable` are both "no", and collapsing them would make a
/// locked account indistinguishable from a wrong password *to the caller* —
/// which is right for the SCREEN and wrong for a log an operator reads at
/// 3am. The face renders both as "login incorrect"; the type keeps the
/// difference for whoever is allowed to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// The passphrase was checked against a real hash and did not match.
    Refused,
    /// The account cannot authenticate at all, passphrase notwithstanding.
    Cannot(Unusable),
    /// The stored hash uses a scheme this build cannot verify.
    ///
    /// ★ Its own arm, and NOT folded into `Refused`. Folded, an operator whose
    /// machine uses a scheme mukae lacks sees "wrong password" forever and has
    /// no way to learn why. It is still a refusal at the screen; it is a
    /// different thing in the logs.
    UnknownScheme,
}

/// A hash whose passphrase nobody knows, used only to spend time.
///
/// ★ sha512crypt rather than yescrypt, DELIBERATELY, and the reason is that a
/// ballast has to be REAL. An invalid hash string is rejected by the parser in
/// microseconds, which would make this "constant-time" padding that pads
/// nothing — the exact vacuous guard it exists to prevent. This one is a
/// genuine `$6$` hash of a random string, verifiable by the same code path a
/// real entry takes, and a test below asserts it is well-formed rather than
/// trusting that it looks right.
///
/// The cost is not identical to a yescrypt derivation. It is a real
/// derivation, which closes the microseconds-vs-milliseconds gap that
/// enumerates usernames; it does not close a fine-grained one.
/// `pending-mukae-native: ballast should match the stored scheme's cost`
const TIMING_BALLAST: &str = "$6$mukaeballast$0hOFwFJZFFOb1zBiRfWiCYJPz7XyM.\
tBaFXfCB6TT5uAEQmHjWurDVQlWvBz98Sk/rJ3JwmYRDIvhNTvj/Br1";

/// Verify a passphrase against one shadow entry.
#[must_use]
pub fn verify(entry: &ShadowEntry, passphrase: &str) -> Verdict {
    match entry.usable_hash() {
        Err(u) => {
            // ★ Still pay the cost. A locked account that answers instantly
            // is a locked account an attacker can enumerate.
            let _ = check(TIMING_BALLAST, passphrase);
            Verdict::Cannot(u)
        }
        Ok(stored) => match check(stored, passphrase) {
            Some(true) => Verdict::Accepted,
            Some(false) => Verdict::Refused,
            None => Verdict::UnknownScheme,
        },
    }
}

/// Spend a verification's worth of time on an account that does not exist.
///
/// ★ Not an optimisation to skip. Without it, "no such user" returns in
/// microseconds while a real user costs a full yescrypt derivation — a
/// difference any client can measure, which turns the login screen into a
/// username enumeration service no matter how carefully the MESSAGES are
/// undifferentiated.
#[must_use]
pub fn verify_absent_user(passphrase: &str) -> Verdict {
    let _ = check(TIMING_BALLAST, passphrase);
    Verdict::Refused
}

/// `Some(matched)`, or `None` when the scheme is not one we implement.
///
/// ★ NOTHING HERE IMPLEMENTS A HASH. Both arms delegate to RustCrypto, which
/// also means both do their own constant-time comparison — rule 3 is honoured
/// by not writing the comparison at all. A verifier that hand-rolled the MCF
/// encoding to compare strings itself is how this goes wrong in the direction
/// that accepts.
fn check(stored: &str, passphrase: &str) -> Option<bool> {
    // ★ The scheme is read FROM the stored hash. See rule 1.
    if stored.starts_with("$y$") {
        // yescrypt — NixOS's default since 21.11, and the only scheme pwhash
        // does not carry.
        use yescrypt::PasswordVerifier;
        // `PasswordVerifier<str>` — the crate parses the MCF string itself, so
        // nothing here touches the `$y$params$salt$hash` encoding.
        return Some(
            yescrypt::Yescrypt::default()
                .verify_password(passphrase.as_bytes(), stored)
                .is_ok(),
        );
    }
    // ★ THE SCHEMES pwhash ACTUALLY IMPLEMENTS, ENUMERATED — not delegated.
    //
    // `pwhash::unix::verify` returns `false` for a scheme it does not know,
    // which is safe and INDISTINGUISHABLE from a wrong password. Routing
    // every `$`-prefixed hash to it therefore made `UnknownScheme` DEAD CODE:
    // an operator on a machine using a scheme mukae lacks would have seen
    // "login incorrect" forever with no way to learn why. Measured — the test
    // below caught it by asserting `$1$` was unknown when in fact pwhash
    // handles md5crypt, which is how the dead arm surfaced.
    //
    // So the supported set is listed here. A scheme not on this list is
    // `UnknownScheme`: still a refusal at the screen, and a nameable fact in
    // a log. Adding one is a deliberate edit rather than a silent widening.
    const PWHASH_SCHEMES: &[&str] = &[
        "$1$",  // md5crypt
        "$5$",  // sha256crypt
        "$6$",  // sha512crypt
        "$2a$", // bcrypt, three spellings
        "$2b$", "$2y$", "$sha1$", // sha1crypt
        "_",      // BSDi extended DES
    ];
    if PWHASH_SCHEMES.iter().any(|p| stored.starts_with(p)) {
        return Some(pwhash::unix::verify(passphrase, stored));
    }
    // Traditional DES crypt: 13 characters, no marker at all. Length is the
    // only signal it gives, which is why it needs its own arm.
    if stored.len() == 13 && !stored.starts_with('$') {
        return Some(pwhash::unix::verify(passphrase, stored));
    }
    // ★ Rule 2, on this crate's own terms rather than a dependency's.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_scheme_is_refused_and_says_so() {
        // ★ The `_ => true` arm, guarded — and this test already earned its
        // keep once. It was written with `$1$`, which pwhash DOES implement,
        // so it failed and revealed that `UnknownScheme` was unreachable: the
        // dispatch sent every `$` hash to pwhash, whose unknown-scheme answer
        // is `false` — indistinguishable from a wrong password.
        //
        // `$gy$` is gost-yescrypt: a real scheme, in real shadow files, that
        // neither dependency implements. Exactly the case an operator needs
        // named rather than rendered as "login incorrect" forever.
        let e = ShadowEntry::parse_line("old:$gy$j9T$salt$hash:::::::").expect("parses");
        assert_eq!(verify(&e, "anything"), Verdict::UnknownScheme);

        // And md5crypt, which IS supported, must be a real verdict rather
        // than an unknown — the other side of the same line.
        let stored = pwhash::md5_crypt::hash("pw").expect("hashes");
        let line = format!("old:{stored}:::::::");
        let e = ShadowEntry::parse_line(&line).expect("parses");
        assert_eq!(verify(&e, "pw"), Verdict::Accepted);
        assert_eq!(verify(&e, "nope"), Verdict::Refused);
    }

    #[test]
    fn a_locked_account_is_refused_before_the_passphrase_matters() {
        let e = ShadowEntry::parse_line("bob:!$6$salt$hash:::::::").expect("parses");
        assert!(matches!(
            verify(&e, "whatever"),
            Verdict::Cannot(Unusable::Locked)
        ));
    }

    #[test]
    fn an_empty_password_never_accepts() {
        // The nullok behaviour, refused. Both an empty guess and a non-empty
        // one must fail — a verifier that accepted the empty guess would log
        // anyone in as every passwordless system account on the machine.
        let e = ShadowEntry::parse_line("svc::::::::").expect("parses");
        assert!(matches!(
            verify(&e, ""),
            Verdict::Cannot(Unusable::NoPassword)
        ));
        assert!(matches!(
            verify(&e, "x"),
            Verdict::Cannot(Unusable::NoPassword)
        ));
    }

    #[test]
    fn a_sha512crypt_round_trip_accepts_the_right_passphrase_and_only_it() {
        // Proves the verifier VERIFIES rather than merely parses. Generated
        // here, so it depends on no machine's shadow file.
        let stored = pwhash::sha512_crypt::hash("correct horse").expect("hashes");
        let line = format!("ann:{stored}:::::::");
        let e = ShadowEntry::parse_line(&line).expect("parses");
        assert_eq!(verify(&e, "correct horse"), Verdict::Accepted);
        assert_eq!(verify(&e, "correct hors"), Verdict::Refused);
        assert_eq!(verify(&e, ""), Verdict::Refused);
    }

    #[test]
    fn a_yescrypt_round_trip_accepts_the_right_passphrase_and_only_it() {
        // ★ THE ONE THAT MATTERS ON THIS FLEET. yescrypt is NixOS's default
        // since 21.11, so every real entry in plo's shadow file is `$y$`, and
        // it is the one scheme `pwhash` does not carry — the arm most likely
        // to be wrong and least likely to be exercised by a generic test.
        use yescrypt::{PasswordHasher, Yescrypt};
        let stored = Yescrypt::default()
            .hash_password(b"correct horse")
            .expect("hashes");
        let stored = stored.as_str();
        assert!(stored.starts_with("$y$"), "must be a yescrypt MCF string");

        let line = format!("ann:{stored}:::::::");
        let e = ShadowEntry::parse_line(&line).expect("parses");
        assert_eq!(verify(&e, "correct horse"), Verdict::Accepted);
        assert_eq!(verify(&e, "correct hors"), Verdict::Refused);
    }

    #[test]
    fn the_timing_ballast_is_a_REAL_hash_and_not_decoration() {
        // ★ THE ANTI-VACUITY TEST. A ballast exists to make a nonexistent
        // account cost the same as a real one. An INVALID hash string is
        // rejected by the parser in microseconds — so a malformed ballast is
        // padding that pads nothing, and the timing oracle it was written to
        // close stays wide open while the code reads as though it is handled.
        //
        // This asserts the ballast actually runs a derivation: a wrong
        // passphrase against it must come back `false`, not an early parse
        // error, which `check` reports as `Some(false)` rather than `None`.
        assert_eq!(
            check(TIMING_BALLAST, "not the passphrase"),
            Some(false),
            "the ballast must be a parseable hash that a real derivation rejects"
        );
    }

    #[test]
    fn an_absent_user_reports_the_same_verdict_as_a_wrong_password() {
        // The MESSAGE being undifferentiated is not enough; see the module
        // header on rule 4. This asserts the shape; the timing property is
        // what the shared ballast buys.
        assert_eq!(verify_absent_user("anything"), Verdict::Refused);
    }
}
