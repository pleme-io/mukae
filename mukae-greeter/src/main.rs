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

  mukae [--authenticate] [--service NAME] [--user NAME]

  --authenticate   Run a real PAM conversation to a verdict.
                   ★ Authenticates ONLY. Opens no session, execs nothing,
                     claims no VT. Exit 0 means the person proved who they
                     are, NOT that they are logged in.
                   Linux only — libpam is not linked elsewhere.
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

#[cfg(target_os = "linux")]
fn authenticate_run(face: Face, service: Option<String>) -> ExitCode {
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

    let mut sess = match Session::start(face, svc) {
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

#[cfg(not(target_os = "linux"))]
fn authenticate_run(_face: Face, _service: Option<String>) -> ExitCode {
    // Refused by PLATFORM, not by readiness. libpam is a Linux interface and
    // mukae-host is not built here at all, so there is no code path to run —
    // this arm exists so the message names the reason instead of the linker
    // naming `-lpam`.
    eprintln!(
        "mukae: --authenticate needs libpam, which is linked only on Linux.\n\
         mukae: the face itself runs here — drop the flag to draw it."
    );
    ExitCode::FAILURE
}
