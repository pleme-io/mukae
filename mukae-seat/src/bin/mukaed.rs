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

/// Supervise an unprivileged greeter and authenticate what it collects.
///
/// ── ★ THE PRIVILEGE SPLIT, MADE STRUCTURAL ───────────────────────────────
/// The greeter draws — fonts, a terminal, input parsing — and that surface
/// must not run as root. So it is a separate process, dropped to its own
/// unprivileged user, and the ONLY thing it can reach is one end of a
/// socketpair created here before the fork. It never sees /etc/shadow, never
/// talks to logind, and cannot start a session.
/// The passwd name for a uid, for the one PATH entry that needs it.
///
/// `mukae_seat::spawn` resolves the full record again at the moment of exec
/// -- deliberately, since that is where HOME/USER/LOGNAME/SHELL are
/// guaranteed. This is the narrower question mukaed itself has to answer
/// while assembling policy, and it is a lookup rather than a second source
/// of truth: nothing here is exported.
fn passwd_name_of_uid(uid: u32) -> Option<String> {
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0i8; 4096];
    let mut out = std::ptr::null_mut::<libc::passwd>();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut out,
        )
    };
    if rc != 0 || out.is_null() || entry.pw_name.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// The environment mukaed CONTRIBUTES to a session.
///
/// ── ★ WHAT IS AND IS NOT DECIDED HERE ───────────────────────────────────
/// Policy only. HOME, USER, LOGNAME and SHELL are NOT here: they are facts
/// about the account, and `mukae_seat::spawn` derives them from the passwd
/// record at the point of exec, where they cannot be forgotten. Setting them
/// here as well would put one fact in two places, which is the shape that
/// produced today's other two defects.
///
/// This function exists because both login paths were assembling PATH by hand
/// and had already drifted -- one of them silently shipping a session with
/// nine environment variables and no HOME.
fn session_env_for(uid: u32, cfg: &mukae_seat::config::MukaeConfig) -> mukae_spec::env::EnvSet {
    let mut env = mukae_spec::env::EnvSet::default();
    // ── ★ /run/wrappers/bin FIRST, OR THE SESSION HAS NO sudo ──────────
    // Every setuid binary on a NixOS host lives in /run/wrappers/bin --
    // sudo, passwd, mount, ping. The store copy at
    // /run/current-system/sw/bin/sudo is NOT setuid and refuses to run:
    //
    //     sudo must be owned by uid 0 and have the setuid bit set
    //
    // Omitting the wrappers directory therefore does not merely hide sudo,
    // it produces an error that reads like a broken installation. Measured
    // on plo 2026-08-28, from the operator's own seat, trying to reboot.
    //
    // A login shell does not rescue this: frostmourne's rc PREPENDS its
    // entries to whatever it inherits, so a directory missing here is
    // missing for everything the session ever starts.
    //
    // The per-user profile is here for the same reason -- a session whose
    // PATH lacks it cannot see anything home-manager installed, which is
    // most of what an operator actually types.
    //
    // ★ THIS IS NIXOS-SHAPED, AND THAT IS A KNOWN WART. mukaed should take
    // its session PATH from configuration rather than know a distribution's
    // layout; the hardcode predates this fix and is left as one line to
    // ★ RESOLVED 2026-08-28. The wart above is gone: the value now comes from
    // `MukaeConfig::session_path`, so a distribution's layout is a declaration
    // an operator can read and a Nix module can render, not a literal three
    // call-frames deep. The prescribed tier is byte-identical to what this
    // block used to build -- see `config::tests`, which pin the wrappers-first
    // ordering that made the difference between a working sudo and an error
    // blaming the installation.
    env.0.insert(
        "PATH".into(),
        cfg.session_path_for(passwd_name_of_uid(uid).as_deref()),
    );
    // Not a class the session can choose: mukaed only ever starts one after
    // authenticating a person. XDG_SESSION_TYPE is deliberately NOT set --
    // mukaed cannot know whether the command it is about to exec is graphical,
    // and guessing "tty" for a Wayland seat would be a confident wrong answer
    // that display-backend autodetection would then act on.
    env.0.insert("XDG_SESSION_CLASS".into(), "user".into());
    env
}

/// The logind attachment implied by a VT selection.
///
/// ── ★ ONE DERIVATION, BECAUSE TWO DISAGREED ─────────────────────────────
/// The console and the logind attachment are ONE fact: a session on a VT
/// registers against seat0 with that VT, and a session without one is
/// seatless. `run` derived it correctly and `greeter_login` did not derive it
/// at all -- it took `NativeSeatEnv::new()`, whose default is `Seatless`.
///
/// Measured on plo 2026-08-28: that made every greeter login on tty1 produce
/// a SEATLESS session -- `XDG_SEAT=""`, `XDG_VTNR=0` -- on the one path that
/// actually runs the machine's seat. logind grants device access per seat, so
/// the compositor started by that session is the thing it breaks, several
/// steps away from here and with nothing pointing back.
///
/// The invariant had already been written down, in a comment on the path that
/// got it right, saying that deriving both from `vt` "is what stops them
/// disagreeing". It stopped nothing, because the other path did not call it.
/// A rule stated in a comment binds one call site; a function binds every
/// caller, including the next one somebody adds.
fn console_for(vt: Option<std::num::NonZeroU32>) -> mukae_seat::Console {
    match vt {
        Some(vtnr) => mukae_seat::Console::Vt {
            seat: "seat0".to_string(),
            vtnr,
        },
        None => mukae_seat::Console::Seatless,
    }
}

fn greeter_login(
    program: &str,
    greeter_user: &str,
    session_cmd: Vec<std::ffi::OsString>,
    vt: Option<std::num::NonZeroU32>,
    cfg: &mukae_seat::config::MukaeConfig,
    state: &std::sync::Arc<mukae_seat::introspect::DaemonState>,
) -> Result<std::process::ExitCode, String> {
    use std::os::unix::io::AsRawFd as _;

    if session_cmd.is_empty() {
        return Err("--cmd is required: there is nothing to start on success".into());
    }
    let argv = Argv::new(session_cmd).map_err(|e| format!("bad session command: {e}"))?;

    let guid = uid_of_name(greeter_user)
        .ok_or_else(|| format!("no passwd entry for the greeter user `{greeter_user}`"))?;
    if guid == 0 {
        // ★ THE GREETER MUST NOT BE ROOT, and this is the one place that can
        // still be true by accident — an operator naming the wrong user in a
        // unit file. The greeter parses fonts, terminal escapes and keyboard
        // input; it is the largest attack surface in a login and the reason
        // the daemon is split in two at all.
        return Err(
            "the greeter user must not be root — that is the whole point of the split".into(),
        );
    }

    // Created BEFORE the fork so the child can inherit its end. Never a
    // filesystem path: a socketpair is reachable by exactly these two
    // processes and by nothing else on the machine.
    let (mine, theirs) =
        std::os::unix::net::UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;

    // fd 3 in the child, by convention and stated in the environment so the
    // greeter does not have to guess.
    const GREETER_FD: i32 = 3;
    let mut genv = mukae_spec::env::EnvSet::default();
    genv.0
        .insert("MUKAE_SOCK_FD".into(), GREETER_FD.to_string());
    genv.0.insert(
        "PATH".into(),
        "/run/current-system/sw/bin:/usr/bin:/bin".into(),
    );
    // ★ crossterm reads TERM to decide what it may emit. Unset, it takes the
    // most conservative path it has and a face that looks fine under a
    // terminal emulator renders as very little on a bare VT. `linux` is what
    // a Linux console IS, and it is what agetty would have exported.
    genv.0.insert("TERM".into(), "linux".into());

    let gplan = SessionPlan {
        // ★ `--mukaed` IS LOAD-BEARING, not decoration. Without it the
        // greeter takes its STANDALONE path: it opens the tty, draws a face,
        // and never reads the socket we just handed it -- a login screen that
        // cannot log anyone in, with no error on either side. Measured on plo
        // 2026-08-28.
        argv: Argv::new(vec![program.into(), "--mukaed".into()])
            .map_err(|e| format!("bad greeter: {e}"))?,
        // ★ EMPTY, AND THE ENV GOES IN THE OTHER ARGUMENT. `SessionPlan::env`
        // is what a session CONTRIBUTES to PAM before the session modules
        // run; the environment a child is actually exec'd with is the second
        // argument to the spawn, which for a session is what `getenvlist`
        // returned afterwards. They are different things and only one of them
        // reaches `execve`.
        //
        // Getting this backwards cost a debugging round: the greeter spawned,
        // dropped privilege correctly, inherited its socket — and died on
        // `KeyError: MUKAE_SOCK_FD`, because the variable had been put in the
        // half that never reaches the child.
        env: mukae_spec::env::EnvSet::default(),
    };

    // The greeter goes through the SAME verified drop as a session. One
    // implementation of "become this user" rather than a second, weaker one
    // written for the unprivileged half.
    // ── ★ THE GREETER NEEDS A TERMINAL, NOT JUST A SOCKET ──────────────
    // It draws with egaku-term, which reads stdin and writes stdout. Spawned
    // without them it inherits whatever the daemon had — under systemd that
    // is the journal, so the face renders escape sequences into a log file
    // and the screen stays blank while everything reports healthy.
    let tty = vt.map(|n| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/tty{}", n.get()))
    });
    let tty = match tty {
        Some(Ok(f)) => Some(f),
        Some(Err(e)) => return Err(format!("opening the greeter's console: {e}")),
        None => None,
    };

    let mut inherit = vec![(theirs.as_raw_fd(), GREETER_FD)];
    if let Some(t) = &tty {
        // stdin, stdout, stderr — all three, because a face that can draw but
        // cannot report its own failure is the worst of the three states.
        for target in 0..=2 {
            inherit.push((t.as_raw_fd(), target));
        }
    }

    let gpid = mukae_seat::spawn_inheriting(&gplan, &genv, mukae_spec::ids::Uid(guid), inherit)
        .map_err(|e| format!("spawning the greeter: {e}"))?;
    drop(theirs);

    eprintln!("mukaed: greeter running as {greeter_user} (pid {})", gpid.0);
    state.greeter_spawned(gpid.0, greeter_user);

    // ── the conversation, over our own wire ─────────────────────────────
    let mut env = NativeSeatEnv::new().on_console(console_for(vt));
    let svc = ServiceName::parse("mukae").map_err(|e| format!("{e}"))?;
    let h = env
        .pam_start(&svc, None)
        .map_err(|e| format!("starting the transaction: {e}"))?;

    let mut sock = mine;
    // ★ The daemon's own copy of the conversation. The greeter feeds an
    // identical flow from its own pump and loses it on SIGTERM — which is the
    // instant a login SUCCEEDS. This one outlives every greeter it spawns, so
    // the counters and the last step are still answerable from inside the
    // session an operator is actually looking at.
    let outcome = mukae_seat::ipc::serve_observed(&mut sock, &mut env, h, Some(state.flow()))?;

    if outcome.is_none() {
        eprintln!("mukaed: login incorrect");
        let _ = env.pam_end(h);
        // Reap the greeter so it cannot outlive the attempt.
        let mut st = 0;
        unsafe { libc::waitpid(gpid.0, &raw mut st, 0) };
        return Ok(std::process::ExitCode::FAILURE);
    }

    match env.pam_acct_mgmt(h).map_err(|e| format!("{e}"))? {
        mukae_spec::env::AcctVerdict::Ok => {}
        other => {
            eprintln!("mukaed: the account is not permitted to log in: {other:?}");
            let _ = env.pam_end(h);
            return Ok(std::process::ExitCode::FAILURE);
        }
    }

    // ★ THE GREETER GOES BEFORE THE SESSION COMES UP. Two processes drawing
    // to one console is the artefact an operator sees as a flickering or
    // half-painted screen, and the greeter has no reason to exist past the
    // moment its answer was accepted.
    // ── ★ THE FACE IS KILLED, SO THE SCREEN IS OURS TO REPAIR ──────────
    // SIGTERM terminates the process outright, so the greeter never runs
    // its `Terminal` Drop -- no LeaveAlternateScreen, no Show cursor, no
    // reset. Whatever frame it drew last stays on the console until
    // something else paints over it.
    //
    // Measured on plo 2026-08-28, on the operator's own login: after Enter
    // the greeter wrote 1401 bytes and NONE of them were \e[?1049l or
    // \e[?25h, leaving the console reading `Password` / the username /
    // a row of asterisks. So a SUCCESSFUL login leaves your own name and
    // your masked passphrase frozen on screen for as long as the
    // compositor takes to draw -- which reads as a hang at the exact
    // moment a person is waiting to learn whether they got in.
    //
    // Repaired HERE rather than by asking the face to exit politely,
    // because this cannot fail: mukaed owns the console claim, the greeter
    // is already reaped, and a face that CRASHED leaves exactly the same
    // mess as one that was signalled. The owner of the console repairs it.
    unsafe { libc::kill(gpid.0, libc::SIGTERM) };
    let mut st = 0;
    unsafe { libc::waitpid(gpid.0, &raw mut st, 0) };
    const RESTORE: &[u8] = b"\x1b[?1049l\x1b[?25h\x1b[0m\x1b[2J\x1b[H";
    // The face draws on `tty` when a VT was claimed and on the descriptors
    // we were started with when it was not; it leaves the same wreckage
    // either way. isatty keeps escape bytes out of the journal, which is
    // where a systemd unit's stdout actually goes.
    if let Some(console) = &tty {
        use std::io::Write as _;
        let mut console = console;
        let _ = console.write_all(RESTORE);
        let _ = console.flush();
    } else if unsafe { libc::isatty(1) } == 1 {
        // SAFETY: fd 1 is ours and stays ours -- write(2) rather than a
        // File, which would close the descriptor when it dropped.
        unsafe { libc::write(1, RESTORE.as_ptr().cast(), RESTORE.len()) };
    }

    let uid = env.uid_for_handle(h).map_err(|e| format!("{e}"))?;
    // Recorded HERE, between a proven authentication and a started session, so
    // `last_user` is true even when the session start below FAILS — which is
    // the case an operator most needs to see, and the one where nothing else
    // on the machine will ever say who it was.
    if let Some(name) = passwd_name_of_uid(uid.0) {
        state.authenticated(&name);
    }
    let proof = env.mint_proof(h, uid).map_err(|e| format!("{e}"))?;
    let seat = SeatId::parse("seat0").map_err(|e| format!("{e}"))?;
    let cap = SeatCapability::mint(proof, seat, h);

    let plan = SessionPlan {
        argv,
        env: session_env_for(uid.0, cfg),
    };
    let session = mukae_spec::session::start_session(&mut env, cap, plan)
        .map_err(|e| format!("starting the session: {e}"))?;

    eprintln!(
        "mukaed: session opened — pid {} uid {}",
        session.pid.0, session.uid.0
    );
    if let Some(name) = passwd_name_of_uid(session.uid.0) {
        state.session_started(&name);
    }
    // ── ★ SAY WHAT THE SESSION WAS ACTUALLY HANDED ─────────────────────
    // A session started with no HOME is invisible from the outside: the
    // login succeeds, the compositor comes up, and every layer reports
    // healthy while the person gets a machine that is not theirs. That
    // shipped, and it took reading /proc/<pid>/environ of a live process to
    // find -- by which point the operator had already been told twice that
    // their theme and their shell were wrong.
    //
    // Keys only, and the value of HOME. No secret reaches this map (PATH,
    // HOME, USER, LOGNAME, SHELL, XDG_*), but logging keys is enough to see
    // an absence, and an absence is the whole failure mode here.
    {
        let mut keys: Vec<&str> = session.env.0.keys().map(String::as_str).collect();
        keys.sort_unstable();
        eprintln!(
            "mukaed: session environment ({} vars): {}",
            keys.len(),
            keys.join(" ")
        );
        if !session.env.0.contains_key("HOME") {
            eprintln!(
                "mukaed: WARNING — this session has no HOME. Every ~/.config \
                     lookup it makes will miss, so a compositor or terminal will \
                     silently run its built-in defaults instead of the \
                     operator\u{2019}s configuration."
            );
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(session.pid.0, &raw mut status, 0) };
    env.pam_close_session(h).map_err(|e| format!("{e}"))?;
    env.pam_end(h).map_err(|e| format!("{e}"))?;
    eprintln!("mukaed: session closed");
    Ok(std::process::ExitCode::SUCCESS)
}

/// Resolve a username to a uid through NSS.
fn uid_of_name(user: &str) -> Option<u32> {
    let c = std::ffi::CString::new(user).ok()?;
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0i8; 4096];
    let mut out = std::ptr::null_mut::<libc::passwd>();
    let rc = unsafe {
        libc::getpwnam_r(
            c.as_ptr(),
            &raw mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut out,
        )
    };
    if rc != 0 || out.is_null() {
        return None;
    }
    Some(entry.pw_uid)
}

fn run(args: &[String]) -> Result<std::process::ExitCode, String> {
    if args[0] != "login" {
        return Err(format!("unknown subcommand `{}`", args[0]));
    }

    // ── ★ CONFIG FIRST, ARGV SECOND ────────────────────────────────────
    // shikumi's sealed progressive fold, with argv as the last rung: the
    // typed config supplies the defaults and a flag overrides one. Before
    // this, argv WAS the config -- there was no other rung -- which meant
    // mukae's behaviour could not be validated, defaulted or round-tripped,
    // and the session PATH lived as a literal inside `session_env_for`.
    //
    // `load()` cannot fail; a broken file yields the prescribed tier and says
    // so. See config.rs: refusing to start over a yaml typo would leave a
    // machine with no way in that does not involve a second computer.
    let (cfg, cfg_source) = mukae_seat::config::load_with_source();

    let mut user: Option<String> = None;
    let mut cmd: Vec<std::ffi::OsString> = Vec::new();
    // ★ A configured `vt: 0` is REJECTED here rather than silently becoming
    // "seatless". Config carries what the operator wrote; this is the point
    // where it means something, so it is the point that can say what to do
    // instead. Same message as the flag, because it is the same mistake.
    let mut vt: Option<std::num::NonZeroU32> = match cfg.vt {
        Some(0) => {
            return Err("config `vt: 0` is not a VT — omit it for a seatless session".into());
        }
        Some(n) => std::num::NonZeroU32::new(n),
        None => None,
    };
    let mut greeter: Option<String> = cfg.greeter.clone();
    let mut greeter_user: Option<String> = cfg.greeter_user.clone();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => {
                i += 1;
                user = Some(args.get(i).ok_or("--user needs a name")?.clone());
            }
            "--vt" => {
                i += 1;
                let n: u32 = args
                    .get(i)
                    .ok_or("--vt needs a number")?
                    .parse()
                    .map_err(|_| "--vt takes a VT number")?;
                vt = std::num::NonZeroU32::new(n);
                if vt.is_none() {
                    // ★ 0 IS NOT "no VT" HERE. logind refuses vtnr=0 on a
                    // seat that has VTs, and accepting it would produce that
                    // refusal three steps later naming neither field. Omit
                    // --vt for a seatless session; that is what it means.
                    return Err("--vt 0 is not a VT — omit --vt for a seatless session".into());
                }
            }
            "--greeter" => {
                i += 1;
                greeter = Some(args.get(i).ok_or("--greeter needs a program")?.clone());
            }
            "--greeter-user" => {
                i += 1;
                greeter_user = Some(args.get(i).ok_or("--greeter-user needs a name")?.clone());
            }
            "--cmd" => {
                cmd = args[i + 1..].iter().map(Into::into).collect();
                break;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }

    // ── ★ THE CONSOLE, CLAIMED BEFORE ANYTHING IS DRAWN ────────────────
    // Held in a binding that lives to the end of `run`, so the restore
    // happens on EVERY exit from here — including the error paths below,
    // which is exactly when a half-claimed console is most likely and most
    // damaging. See `vt::Console`: the give-back is Drop, not a call site.
    let _console = match vt {
        Some(n) => Some(
            // ★ TEXT. The greeter is a TUI and the kernel console must keep
            // drawing for it. A compositor that wants the pixels sets
            // graphics mode itself when it takes the DRM device — doing it
            // here blanks the screen for the face that runs FIRST.
            mukae_seat::vt::Console::claim(n.get(), mukae_seat::vt::Mode::Text)
                .map_err(|e| format!("{e}"))?,
        ),
        None => None,
    };

    // ── introspection ───────────────────────────────────────────────────
    //
    // ★ SPAWNED BEFORE THE CONVERSATION, so a login that fails to even start
    // is still observable. `spawn_sidecar` is infallible by construction: a
    // `None` degrades to "no introspection", never to "no login". A login
    // manager that refuses to seat a person because a diagnostic socket would
    // not bind is a far worse failure than being unobservable.
    //
    // Root has no XDG_RUNTIME_DIR, so kanshou resolves `/tmp/kanshou-0` — the
    // same directory sentinela already uses, and root-only, which is the
    // correct posture for a surface that publishes session identity.
    let state = std::sync::Arc::new(mukae_seat::introspect::DaemonState::new());
    match kanshou::Server::spawn_sidecar(mukae_seat::introspect::APP, state.clone()) {
        Some(path) => eprintln!("mukaed: introspection at {}", path.display()),
        None => eprintln!("mukaed: introspection sidecar did NOT start — the login still works."),
    }
    state.console_claimed("seat0", vt.map(std::num::NonZeroU32::get));
    state.session_path_resolved(&cfg.session_path_for(None), cfg_source);

    // ── the greeter path: supervise a face instead of reading stdin ─────
    if let Some(program) = greeter {
        let who = greeter_user.ok_or("--greeter requires --greeter-user")?;
        return greeter_login(&program, &who, cmd, vt, &cfg, &state);
    }

    let user = user.ok_or("--user is required (or use --greeter)")?;
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

    // The console and the logind attachment are ONE fact: a session on a VT
    // registers against seat0 with that VT, and a session without one is
    // seatless. Deriving both from `vt` is what stops them disagreeing — see
    // `mukae_seat::Console` for the refusal logind gives when they do.
    let mut env = NativeSeatEnv::new().on_console(console_for(vt));
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
                // ★ ONE MESSAGE AT THE FACE, THE CLASS IN THE JOURNAL.
                // Telling the person at the keyboard whether the USER was
                // wrong or the PASSPHRASE was is the oracle that turns a
                // guess into an enumeration, so the face gets one
                // undifferentiated denial. The operator needs the
                // distinction to debug a seat, and this is the DAEMON's
                // stderr -- the journal, which they read and the person at
                // the keyboard cannot see. `PamClass` is a closed enum of
                // failure kinds carrying no name and no secret.
                //
                // This said "recorded" while the binding was dropped on the
                // floor -- the same comment-outruns-code defect that cost
                // this seat its login screen. Now it records.
                eprintln!("mukaed: login incorrect (class: {class:?})");
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
    let plan = SessionPlan {
        argv,
        env: session_env_for(uid.0, &cfg),
    };
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

#[cfg(test)]
mod tests {
    use super::{console_for, session_env_for};
    use mukae_seat::Console;
    use mukae_seat::config::MukaeConfig;

    // ── ★ THE ASYMMETRY THIS FUNCTION EXISTS TO REMOVE ──────────────────
    // Before it, `run` derived the attachment from `vt` and `greeter_login`
    // took the `Seatless` default, so the path that runs the machine's actual
    // seat produced XDG_SEAT="" on a real VT. Both call this now; these pin
    // what it must return so a third caller cannot quietly reintroduce the
    // split.
    // ── ★ THE SETUID GUARD ──────────────────────────────────────────
    // A session PATH without /run/wrappers/bin has no sudo, no passwd, no
    // mount -- and the failure does not read as "not found", it reads as
    // "sudo must be owned by uid 0 and have the setuid bit set", which
    // looks like a broken installation rather than a missing directory.
    // The operator hit exactly that from their own seat, trying to reboot.
    #[test]
    fn the_session_path_leads_with_the_setuid_wrappers() {
        let env = session_env_for(unsafe { libc::getuid() }, &MukaeConfig::prescribed());
        let path = env.0.get("PATH").expect("a session must have a PATH");
        assert!(
            path.starts_with("/run/wrappers/bin"),
            "the wrappers directory must come FIRST -- a later entry is \
             shadowed by the non-setuid store copy. got {path:?}"
        );
    }

    #[test]
    fn the_session_path_keeps_the_system_profile() {
        // Leading with the wrappers must not cost the system profile: that
        // is where everything else the session runs comes from.
        let env = session_env_for(unsafe { libc::getuid() }, &MukaeConfig::prescribed());
        let path = env.0.get("PATH").expect("a session must have a PATH");
        assert!(path.contains("/run/current-system/sw/bin"), "got {path:?}");
    }

    #[test]
    fn a_vt_attaches_to_seat0_with_that_vt() {
        let c = console_for(std::num::NonZeroU32::new(1));
        match c {
            Console::Vt { seat, vtnr } => {
                assert_eq!(seat, "seat0");
                assert_eq!(vtnr.get(), 1, "the VT must be the one claimed, never 0");
            }
            Console::Seatless => panic!("a VT login must not be seatless"),
        }
    }

    #[test]
    fn no_vt_is_seatless() {
        // Not "seat0 with vtnr 0": logind refuses that pairing outright, which
        // is the refusal `mukae_seat::Console` was introduced to make
        // unrepresentable rather than diagnose three steps later.
        assert!(matches!(console_for(None), Console::Seatless));
    }
}
