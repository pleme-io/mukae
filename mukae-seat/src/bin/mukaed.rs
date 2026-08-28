//! `mukaed` — the privileged half of a login, with no libpam and no greetd.
//!
//! ── ★ WHAT THIS IS ───────────────────────────────────────────────────────
//! greetd owns four things on this seat: the PAM stack, the VT, the privilege
//! drop, and the exec. `mukae-seat` replaced the first and the third. This is
//! the process that holds root and drives them, which is the last reason
//! greetd is still installed.
//!
//! ── ★ WHAT IT DOES *NOT* DO YET, SAID HERE RATHER THAN DISCOVERED ────────
//! * **No VT claim.** `--vt` is accepted and refused, loudly. A daemon that
//!   silently ignored it would look like it took the console and leave the
//!   getty fighting it for the keyboard.
//! * **No greeter supervision.** The conversation is answered on stdin, so
//!   this is a login rather than a login *screen*. Wiring `mukae-greeter` to
//!   it over a socketpair is the next rung and needs a typed protocol —
//!   MUKAE.md is explicit that greetd's wire is a deletable adapter, not the
//!   internal seam.
//!
//! So this is the M3 subject: it proves the privileged path end to end, and
//! its done-predicate is a `loginctl show-session` transcript, not a build.
//!
//! ── ★ THE PASSPHRASE ARRIVES ON STDIN, NEVER IN argv ─────────────────────
//! `/proc/<pid>/cmdline` is world-readable. A passphrase passed as an
//! argument is visible to every process on the machine for the lifetime of
//! this one, and it lands in shell history besides. There is no `--password`
//! flag and there will not be one.

use std::io::BufRead as _;

use mukae_seat::NativeSeatEnv;
use mukae_spec::capability::SeatCapability;
use mukae_spec::env::{MsgStyle, PamAnswer, PamStep, SeatEnv as _};
use mukae_spec::ids::{SeatId, ServiceName, UserName};
use mukae_spec::session::{Argv, SessionPlan};

const HELP: &str = "\
mukaed — the pleme-io login daemon

  mukaed login --user NAME --cmd PROGRAM [ARG...]

  --user NAME     who to authenticate.
  --vt N          NOT IMPLEMENTED — refused rather than ignored.
  --cmd P [A..]   the session to exec on success. Everything after --cmd is
                  the command, so put it last.

The passphrase is read from stdin. It is never an argument: /proc/<pid>/cmdline
is world-readable.

Exit 0 means a session was opened AND the child exec'd. Anything else means no
session exists — there is no partial success.
";

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{HELP}");
        return std::process::ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("mukaed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<std::process::ExitCode, String> {
    if args[0] != "login" {
        return Err(format!("unknown subcommand `{}`", args[0]));
    }

    let mut user: Option<String> = None;
    let mut cmd: Vec<std::ffi::OsString> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => {
                i += 1;
                user = Some(args.get(i).ok_or("--user needs a name")?.clone());
            }
            "--vt" => {
                // ★ REFUSED, NOT IGNORED. Accepting a flag whose behaviour is
                // absent is how an operator concludes the daemon took the
                // console when it did not, and then spends an hour on the
                // getty that is still holding it.
                return Err(
                    "--vt is not implemented: mukaed does not claim a console yet. \
                     Run it on a VT that is already yours."
                        .into(),
                );
            }
            "--cmd" => {
                cmd = args[i + 1..].iter().map(Into::into).collect();
                break;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }

    let user = user.ok_or("--user is required")?;
    let user = UserName::parse(&user).map_err(|e| format!("bad username: {e}"))?;
    if cmd.is_empty() {
        return Err("--cmd is required and must name a program".into());
    }
    let argv = Argv::new(cmd).map_err(|e| format!("bad session command: {e}"))?;

    // ── ★ ROOT IS CHECKED UP FRONT, WITH THE REASON ────────────────────
    // Every failure downstream of here would be a confusing symptom of the
    // same cause: initgroups returns EPERM, logind refuses the session, and
    // neither error says "you are not root".
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "must run as root — it opens a logind session and drops privilege to the user".into(),
        );
    }

    let mut env = NativeSeatEnv::new();
    let svc = ServiceName::parse("mukae").map_err(|e| format!("{e}"))?;
    let h = env
        .pam_start(&svc, Some(&user))
        .map_err(|e| format!("starting the transaction: {e}"))?;

    // ── the conversation ────────────────────────────────────────────────
    // Driven exactly as a face would drive it: pull a step, answer it, pull
    // again. The daemon does not know how many rounds there will be, which is
    // the property that lets the same loop serve a second factor later.
    let stdin = std::io::stdin();
    loop {
        match env.pam_next(h).map_err(|e| format!("{e}"))? {
            PamStep::Prompt { style, msg } => {
                let mut line = String::new();
                if style == MsgStyle::PromptEchoOff {
                    eprintln!("{}: (reading from stdin)", msg.0);
                } else {
                    eprintln!("{}:", msg.0);
                }
                stdin
                    .lock()
                    .read_line(&mut line)
                    .map_err(|e| format!("reading the answer: {e}"))?;
                let line = line.trim_end_matches(['\n', '\r']).to_string();
                let answer = if style == MsgStyle::PromptEchoOff {
                    PamAnswer::Secret(mukae_spec::capability::Passphrase::new(line))
                } else {
                    PamAnswer::Visible(line)
                };
                env.pam_answer(h, answer).map_err(|e| format!("{e}"))?;
            }
            PamStep::Info { msg, .. } => eprintln!("{}", msg.0),
            PamStep::Complete => break,
            PamStep::Failed { class } => {
                // ★ ONE MESSAGE FOR EVERY DENIAL. `class` is recorded and not
                // rendered: telling the person at the keyboard whether the
                // USER was wrong or the PASSPHRASE was is the oracle that
                // turns a guess into an enumeration.
                eprintln!("mukaed: login incorrect");
                let _ = env.pam_end(h);
                return Ok(std::process::ExitCode::FAILURE);
            }
        }
    }

    // ── account management, AFTER authentication ────────────────────────
    match env.pam_acct_mgmt(h).map_err(|e| format!("{e}"))? {
        mukae_spec::env::AcctVerdict::Ok => {}
        other => {
            eprintln!("mukaed: the account is not permitted to log in: {other:?}");
            let _ = env.pam_end(h);
            return Ok(std::process::ExitCode::FAILURE);
        }
    }

    let uid = env.uid_for_handle(h).map_err(|e| format!("{e}"))?;
    let proof = env
        .mint_proof(h, uid)
        .map_err(|e| format!("minting the proof: {e}"))?;
    let seat = SeatId::parse("seat0").map_err(|e| format!("{e}"))?;

    // The capability, and the whole point of the type: `start_session` takes
    // it BY VALUE, so this authentication buys exactly one session and the
    // compiler is what says so.
    let cap = SeatCapability::mint(proof, seat, h);

    // ── ★ A SESSION WITH NO `PATH` IS A BROKEN SESSION ─────────────────
    // Measured on plo 2026-08-28, in the first login this daemon ever
    // completed: the session opened, logind reported `State=active`, the
    // privilege drop was correct — and the shell answered `loginctl: command
    // not found` for every binary it tried. Everything downstream of a login
    // assumes a PATH, and libpam's stack quietly supplies one via `pam_env`;
    // an environment that replaces PAM inherits that obligation along with
    // the rest of it.
    //
    // These are the values NixOS puts on a login shell's PATH, and they are a
    // FLOOR rather than the final word: the user's shell profile extends it,
    // as it does under any login manager. HOME, USER, LOGNAME and SHELL for
    // the same reason — a session missing them is one where `~` does not
    // expand and `su` reports the wrong user.
    let mut base = mukae_spec::env::EnvSet::default();
    for (k, v) in [
        ("PATH", "/run/current-system/sw/bin:/usr/bin:/bin"),
        ("USER", user.as_str()),
        ("LOGNAME", user.as_str()),
    ] {
        base.0.insert(k.to_string(), v.to_string());
    }
    let plan = SessionPlan { argv, env: base };
    let session = mukae_spec::session::start_session(&mut env, cap, plan)
        .map_err(|e| format!("starting the session: {e}"))?;

    eprintln!(
        "mukaed: session opened — pid {} uid {}",
        session.pid.0, session.uid.0
    );
    for (k, v) in &session.env.0 {
        if k.starts_with("XDG_") {
            eprintln!("mukaed:   {k}={v}");
        }
    }

    // ── wait, then close — and the close is paired by construction ──────
    // This process outlives the child on purpose. `pam_close_session` (here,
    // dropping the logind descriptor) must happen after the session ends, and
    // a daemon that exited first would leave logind holding a session for a
    // process that is gone.
    let mut status = 0;
    unsafe { libc::waitpid(session.pid.0, &raw mut status, 0) };

    env.pam_close_session(h).map_err(|e| format!("{e}"))?;
    env.pam_end(h).map_err(|e| format!("{e}"))?;
    eprintln!("mukaed: session closed");
    Ok(std::process::ExitCode::SUCCESS)
}
