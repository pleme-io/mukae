//! `mukae` — the greeter binary. The thing greetd execs instead of tuigreet.
//!
//! ── WHAT `--authenticate` MEANS, EXACTLY ──────────────────────────────────
//! It runs a real PAM conversation to a verdict, and it **does not open a
//! session**. Nothing is exec'd, no VT is claimed, no utmp record is written.
//! A successful exit says *"this person proved who they are"* and nothing more.
//!
//! That distinction is the whole reason the flag existed as a refusal for as
//! long as it did: the dangerous shape for this binary is one that looks like
//! a login screen, takes a password, and lets a caller read exit 0 as "logged
//! in". So the verdict is reported in words as well as in an exit code, and
//! `pending-mukae-session` names what is still missing.
//!
//! ── ★ WHY THE REFUSAL COULD BE REMOVED ────────────────────────────────────
//! Because a login has now been driven against a real PAM stack rather than
//! merely compiled against one. `mukae-host` links libpam and its suite runs
//! green on Linux — including `authenticate`, which reaches the stack and
//! reports a real refusal for a service nobody configured. The refusal existed
//! to stop a claim from outrunning its evidence; the evidence has arrived.
//!
//! ── WHY THE PAM-LESS RUN STAYS THE DEFAULT ────────────────────────────────
//! A face that can be drawn without a seat, a PAM stack, or a Linux kernel is
//! a face that can be looked at from the machine it is written on. `--help`
//! and the default run are that; everything else needs plo.

use std::process::ExitCode;

use egaku_term::theme::Palette;
use mukae_face::Face;

#[cfg(target_os = "linux")]
mod session;

const HELP: &str = "\
mukae (迎え) — the pleme-io login face

  mukae [--greetd | --authenticate] [--service NAME] [--user NAME]
        [--cmd PROGRAM [ARG...]]

  --greetd         Run as greetd's greeter. THE MODE THAT LOGS SOMEONE IN:
                   greetd owns the PAM stack, the VT, the privilege drop and
                   the exec; mukae owns the face, the theme and the
                   introspection. Requires $GREETD_SOCK.
  --cmd P [ARG..]  What to start on success, in --greetd mode. Everything
                   after --cmd is the command; put it last.

  --authenticate   Run a real PAM conversation to a verdict, mukae's own way.
                   ★ NOT IN THE DEFAULT BUILD. libpam is the one thing that
                     would put a .so in this binary, and it is a GUEST — a C
                     library with an ABI, not a wire — so it is off unless
                     built with `--features pam`.
                   ★ Authenticates ONLY. Opens no session, execs nothing,
                     claims no VT. Exit 0 means the person proved who they
                     are, NOT that they are logged in.
  --service NAME   PAM service to authenticate against (default: `login`).
  --user NAME      Prefill the username field.

With no flags this draws the face and exits on Esc, which is what makes the
UI testable on a machine that has no PAM at all.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("{HELP}");
        return ExitCode::SUCCESS;
    }

    let value_of = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    // Nord, from the same place every other pleme-io surface gets it. The
    // palette is not spelled out here — a hex value in a greeter is how a seat
    // ends up with two Nords that drift apart.
    let mut face = Face::new(Palette::default());
    if let Some(u) = value_of("--user") {
        for c in u.chars() {
            face.user.insert_char(c);
        }
    }

    if args.iter().any(|a| a == "--greetd") {
        return greetd_run(face, &args);
    }

    if args.iter().any(|a| a == "--authenticate") {
        return authenticate_run(face, value_of("--service"));
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

#[cfg(all(target_os = "linux", feature = "pam"))]
fn authenticate_run(face: Face, service: Option<String>) -> ExitCode {
    use std::sync::Arc;

    use mukae::introspect::{Drivable, LoginFlow};
    use mukae_spec::ids::ServiceName;
    use session::{Session, Verdict};

    // `login` is the service a console greeter authenticates against on a
    // stock NixOS. Named as a default rather than hardcoded, because a seat
    // with its own stack (`greetd`, or a mukae-specific one) is a config
    // change and must not be a code change.
    let raw = service.unwrap_or_else(|| "login".to_string());
    let svc = match ServiceName::parse(&raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mukae: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    // ★ Observable, never drivable. On a real seat, submitting an answer over
    // MCP is a remote login bypass wearing a test harness's clothes — so the
    // drive verbs are ABSENT here rather than refused, and `Drivable::MockOnly`
    // is reachable only from the mock environment, which authenticates nobody.
    let flow = Arc::new(LoginFlow::new(Drivable::Observable));

    // Spawned BEFORE the transaction, so an agent can observe a login that is
    // failing to start — which is exactly when observation earns its keep and
    // exactly when a late-registered surface is useless.
    //
    // `spawn_sidecar` is infallible by construction: a socket that cannot bind
    // degrades to "no introspection" rather than "no greeter". That property
    // is the only reason this call may sit on the path to a login screen.
    match kanshou::Server::spawn_sidecar("mukae", Arc::clone(&flow)) {
        Some(p) => eprintln!("mukae: introspection at {}", p.display()),
        None => eprintln!(
            "mukae: introspection sidecar did NOT start — the login still \
             works, but `gen kanshou query mukae ...` will find nothing."
        ),
    }

    let mut sess = match Session::start(face, svc, flow) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mukae: could not start a PAM transaction: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = egaku_term::run(&mut sess) {
        eprintln!("mukae: {e}");
        return ExitCode::FAILURE;
    }

    match sess.verdict() {
        Some(Verdict::Authenticated) => {
            // ★ Said in words, every time. The exit code is the part a script
            // reads and the part most likely to be misread, so the sentence
            // that bounds it is not optional output.
            eprintln!(
                "mukae: authenticated against PAM service `{}`.\n\
                 mukae: NO SESSION WAS OPENED — nothing was exec'd, no VT was\n\
                 mukae: claimed, no utmp record was written. See\n\
                 mukae: `pending-mukae-session`.",
                sess.service().as_str()
            );
            ExitCode::SUCCESS
        }
        // Undifferentiated on purpose: telling a caller which failure class it
        // was is a username oracle.
        Some(Verdict::Refused) => {
            eprintln!("mukae: login incorrect.");
            ExitCode::FAILURE
        }
        Some(Verdict::Abandoned) => {
            eprintln!("mukae: cancelled.");
            ExitCode::FAILURE
        }
        // The loop exited without a verdict. Reported as its own thing rather
        // than folded into a refusal — nobody failed a login here, and a
        // greeter that reports one when its own loop misbehaved would put the
        // blame on a person.
        None => {
            eprintln!("mukae: the conversation ended without a verdict.");
            ExitCode::FAILURE
        }
    }
}

/// Run as greetd's greeter — the mode that actually seats a person.
#[cfg(target_os = "linux")]
fn greetd_run(face: Face, args: &[String]) -> ExitCode {
    use std::sync::Arc;

    use mukae::introspect::{Drivable, LoginFlow};
    use mukae_greetd::{SessionCmd, connect};
    use session::{Session, Verdict};

    // Everything after `--cmd` is the session command. Taken positionally
    // rather than as a quoted string, because splitting a string on spaces is
    // how a path with a space in it becomes two arguments.
    let cmd: Vec<String> = args
        .iter()
        .position(|a| a == "--cmd")
        .map(|i| args[i + 1..].to_vec())
        .unwrap_or_default();

    if cmd.is_empty() {
        eprintln!(
            "mukae: --greetd needs --cmd PROGRAM [ARG...] — what to start once\n\
             mukae: the person is authenticated. Without it a successful login\n\
             mukae: would land on nothing, which looks exactly like a failure."
        );
        return ExitCode::FAILURE;
    }

    let flow = Arc::new(LoginFlow::new(Drivable::Observable));
    match kanshou::Server::spawn_sidecar("mukae", Arc::clone(&flow)) {
        Some(p) => eprintln!("mukae: introspection at {}", p.display()),
        None => eprintln!("mukae: introspection sidecar did NOT start — the login still works."),
    }

    let bridge = match connect(SessionCmd {
        cmd,
        env: Vec::new(),
    }) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("mukae: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut sess = Session::from_bridge(face, bridge, flow);
    if let Err(e) = egaku_term::run(&mut sess) {
        eprintln!("mukae: {e}");
        return ExitCode::FAILURE;
    }

    match sess.verdict() {
        // greetd has started the session. This one IS a login.
        Some(Verdict::Authenticated) => ExitCode::SUCCESS,
        Some(Verdict::Refused) => {
            eprintln!("mukae: login incorrect.");
            ExitCode::FAILURE
        }
        Some(Verdict::Abandoned) => ExitCode::FAILURE,
        None => {
            eprintln!("mukae: the conversation ended without a verdict.");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn greetd_run(_face: Face, _args: &[String]) -> ExitCode {
    eprintln!("mukae: --greetd needs a greetd socket, which exists only on Linux.");
    ExitCode::FAILURE
}

#[cfg(not(all(target_os = "linux", feature = "pam")))]
fn authenticate_run(_face: Face, _service: Option<String>) -> ExitCode {
    // ★ Refused by BUILD, not by readiness — and the distinction is the point.
    // The PAM path works and is tested; it is simply not in this binary,
    // because libpam is the only thing that would make this an executable with
    // a C library hanging off it. MODULARIZE, DON'T DELETE: the code is intact
    // and one flag away.
    eprintln!(
        "mukae: --authenticate is not in this build.\n\
         mukae: libpam is a C library, not a wire, so it is off by default —\n\
         mukae: this binary links no .so beyond libc. Rebuild with\n\
         mukae: `--features pam` if you want it, or use --greetd, which is\n\
         mukae: what a seat actually runs."
    );
    ExitCode::FAILURE
}
