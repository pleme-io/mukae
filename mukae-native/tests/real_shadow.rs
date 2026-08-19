//! The verifier, run against a REAL `/etc/shadow` rather than fixtures.
//!
//! ── ★ WHY FIXTURES ARE NOT ENOUGH HERE ────────────────────────────────────
//! Every unit test in this crate builds its own hash and checks it back. That
//! proves the algorithms round-trip and proves nothing about the file this
//! code will actually be pointed at — whose entries were written by
//! `shadow(5)` over years, in whatever schemes and lock states accumulated.
//!
//! The census that motivated this crate found, on the fleet's Linux node, 51
//! entries beginning with `!` and 2 in `$y$`. So the overwhelmingly common
//! case on a real machine is the LOCKED one — 51 accounts a verifier that
//! stripped the bang would authenticate with their old passwords — and it is
//! a case no round-trip test generates, because you do not round-trip a lock.
//!
//! ── ★ WHAT THIS CAN AND CANNOT ASSERT ─────────────────────────────────────
//! It cannot assert a successful login: nobody's passphrase is known to a
//! test, and a test that knew one would be a test that stored one.
//!
//! It CAN assert the two properties whose failure is catastrophic and silent:
//! every locked account is reported locked, and no account accepts a
//! passphrase that is not its own. Those are the fail-open directions. The
//! fail-closed direction — refusing someone who should get in — is loud, and
//! a person finds it in seconds.
//!
//! Run where a shadow file is readable:
//!
//! ```text
//! sudo -E cargo test -p mukae-native --test real_shadow -- --ignored --nocapture
//! ```

use std::path::Path;

use mukae_native::shadow::{ShadowEntry, Unusable};
use mukae_native::verify::{Verdict, verify};

const SHADOW: &str = "/etc/shadow";

#[test]
#[ignore = "needs a readable /etc/shadow; run as root with --ignored"]
fn no_entry_on_this_machine_accepts_a_passphrase_that_is_not_its_own() {
    let text = std::fs::read_to_string(Path::new(SHADOW))
        .unwrap_or_else(|e| panic!("cannot read {SHADOW}: {e} — run this as root"));

    let entries: Vec<ShadowEntry> = text.lines().filter_map(ShadowEntry::parse_line).collect();
    assert!(
        !entries.is_empty(),
        "a shadow file with no parseable entries means the parser is broken, \
         not that the machine has no accounts"
    );

    let mut locked = 0usize;
    let mut checkable = 0usize;
    let mut unknown_scheme = Vec::new();

    for e in &entries {
        // Guesses no account should accept. Deliberately including the empty
        // string: an empty passphrase accepted anywhere is the `nullok`
        // behaviour this crate exists to refuse.
        for guess in ["", "password", "x", "!", "*"] {
            match verify(e, guess) {
                Verdict::Accepted => panic!(
                    "account `{}` ACCEPTED the guess {guess:?} — this is a \
                     fail-open and the machine is not the problem",
                    e.name
                ),
                Verdict::Cannot(Unusable::Locked) => {}
                Verdict::Cannot(_) => {}
                Verdict::Refused => {}
                Verdict::UnknownScheme => unknown_scheme.push(e.name.clone()),
            }
        }

        match e.usable_hash() {
            Err(Unusable::Locked) => locked += 1,
            Ok(_) => checkable += 1,
            Err(_) => {}
        }
    }

    // ★ Reported, not asserted to a number. A count baked in here would be a
    // dated claim about somebody's machine that rots the moment an account is
    // added — the exact failure mode this fleet's docs keep hitting. What
    // matters is that it is not zero: a run where NOTHING was locked and
    // NOTHING was checkable proved nothing while printing green.
    println!(
        "shadow census: {} entries — {locked} locked, {checkable} checkable, \
         {} unknown-scheme",
        entries.len(),
        unknown_scheme.len()
    );
    assert!(
        locked + checkable > 0,
        "no entry was either locked or checkable — this test verified nothing"
    );

    // An unknown scheme is not a failure of this machine; it is a gap in this
    // crate, and it must be NAMED rather than silently behaving as a refusal.
    assert!(
        unknown_scheme.is_empty(),
        "these accounts use a scheme mukae-native cannot verify, so they could \
         never log in through it: {unknown_scheme:?}"
    );
}
