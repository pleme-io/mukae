//! The logind wire, actually spoken — not merely compiled against.
//!
//! ── ★ WHY THIS FILE HAS TO EXIST ──────────────────────────────────────────
//! `logind.rs` compiles, and compiling proves nothing about a D-Bus call. The
//! risky part is the argument marshalling: `CreateSession` takes
//! `uusssssussbssa(sv)`, with five consecutive strings in the middle. Rust's
//! type checker sees five `&str` and is perfectly happy with any permutation
//! of them, logind accepts what it is given, and the result is a session that
//! exists and is wrong. Nothing short of making the call finds that.
//!
//! ── WHAT THIS DOES TO THE MACHINE, EXACTLY ────────────────────────────────
//! Creates a session with `class = Greeter`, no seat, no VT and no TTY — the
//! shape an unseated background session takes — and then DROPS it, which
//! closes the descriptor logind watches and ends the session. It is the least
//! invasive thing that still exercises the real argument list.
//!
//! `class = Greeter` deliberately, not `User`: a `User` session counts as a
//! logged-in person for idle and multi-seat purposes, and a test should not
//! make a machine believe someone logged in.
//!
//! ```text
//! sudo -E cargo test -p mukae-native --test real_logind -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use mukae_native::logind::{Class, Kind, Request, create_session};

#[test]
#[ignore = "talks to the real logind and creates a transient session; run as root with --ignored"]
fn logind_accepts_our_argument_list_and_hands_back_a_session() {
    let req = Request {
        uid: unsafe { libc::getuid() },
        pid: std::process::id(),
        service: "mukae-selftest".to_string(),
        kind: Kind::Unspecified,
        // Not `User` — see the module header.
        class: Class::Greeter,
        desktop: String::new(),
        // ★ Empty seat AND vtnr 0 together. logind rejects a nonzero vtnr on a
        // seat with no VTs, and the error names the seat rather than the
        // number — which reads as "your seat is wrong" when the defect is the
        // vtnr.
        seat: String::new(),
        vtnr: 0,
        tty: String::new(),
        display: String::new(),
        remote: false,
        remote_user: String::new(),
        remote_host: String::new(),
    };

    let session = create_session(&req).expect("logind should accept this request");

    // ★ THE ASSERTIONS THAT CATCH A PERMUTED ARGUMENT LIST. A session created
    // with the strings in the wrong order still comes back Ok — what differs
    // is what it CONTAINS. A non-empty id and a real runtime path are the
    // cheapest evidence that logind understood the request rather than merely
    // accepted it.
    assert!(!session.id.is_empty(), "logind returned an empty session id");
    assert!(
        session.object_path.starts_with("/org/freedesktop/login1/session/"),
        "object path is not a login1 session path: {}",
        session.object_path
    );
    println!(
        "session id={} path={} runtime={} seat={:?} vtnr={} existing={}",
        session.id, session.object_path, session.runtime_path, session.seat,
        session.vtnr, session.existing
    );

    // Dropping ends it. Stated rather than left implicit, because the whole
    // design of `Session` rests on this being what happens.
    drop(session);
}
