//! `mukae` — the greeter binary. The thing greetd execs instead of tuigreet.
//!
//! ── WHAT THIS IS AND IS NOT, TODAY ────────────────────────────────────────
//! This runs the pleme-io face, collects a username and a masked answer, and
//! reports what it collected to whatever is driving the login. It is a REAL
//! binary a display manager can exec, which is the thing every piece of mukae
//! built so far was missing — three library crates that compiled and could not
//! be run.
//!
//! It does NOT yet own the session. `mukae-host` has the PAM pieces (start,
//! setcred, acct_mgmt, open_session) and `mukae-host::bridge` has the
//! push↔pull adapter, but wiring authentication end to end needs a machine
//! with a PAM stack to prove it against, and a greeter that CLAIMS to
//! authenticate without having done so once is the worst thing in this
//! directory. So the auth path is behind `--authenticate`, off by default, and
//! the default run is a face you can look at and drive.
//!
//! `pending-mukae-session:` exec the session on success. That rung needs
//! `open_session` + a VT + utmp, and it lands where `loginctl` can prove a
//! session actually opened rather than where it merely compiled.
//!
//! ── ★ WHY THE BINARY EXISTS BEFORE THE AUTHENTICATION DOES ────────────────
//! Because the face is the half that cannot be tested any other way. The PAM
//! bridge has unit tests and the introspection surface has unit tests; a
//! terminal UI has neither until something draws it on a terminal. Shipping
//! the runnable face first means the next person to touch the auth path is
//! debugging ONE unknown instead of two.

use std::process::ExitCode;

use egaku_term::theme::Palette;
use mukae_face::Face;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "mukae (迎え) — the pleme-io login face\n\
             \n\
               mukae [--authenticate] [--user NAME]\n\
             \n\
             --authenticate   drive a real PAM conversation. Requires a PAM\n\
                              stack; NOT yet wired — see pending-mukae-session.\n\
             --user NAME      prefill the username field.\n\
             \n\
             With no flags this draws the face and exits on Esc, which is what\n\
             makes the UI testable on a machine that has no PAM at all."
        );
        return ExitCode::SUCCESS;
    }

    // ★ Refused rather than half-done. A greeter that accepted the flag and
    // then silently drew a face without authenticating would be the single
    // most dangerous shape this binary could take: it looks like a login
    // screen, it takes a password, and it lets nobody in — or worse, some
    // caller assumes a successful exit means a successful login.
    if args.iter().any(|a| a == "--authenticate") {
        eprintln!(
            "mukae: --authenticate is not wired yet.\n\
             \n\
             mukae-host has the PAM calls and mukae-host::bridge has the\n\
             push-pull adapter, but no login has been driven end to end on a\n\
             real PAM stack. A greeter that claims to authenticate without\n\
             having done so once is worse than one that admits it does not.\n\
             \n\
             Tracked as `pending-mukae-session`."
        );
        return ExitCode::FAILURE;
    }

    let prefill = args
        .iter()
        .position(|a| a == "--user")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Nord, from the same place every other pleme-io surface gets it. The
    // palette is not spelled out here — a hex value in a greeter is how a seat
    // ends up with two Nords that drift apart.
    let mut face = Face::new(Palette::default());
    if let Some(u) = prefill {
        for c in u.chars() {
            face.user.insert_char(c);
        }
    }

    match egaku_term::run(&mut face) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The terminal is restored by `Terminal`'s Drop, including on
            // panic, so this only has to report.
            eprintln!("mukae: {e}");
            ExitCode::FAILURE
        }
    }
}
