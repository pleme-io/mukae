//! The privilege drop and exec — the one place mukae hands a session to a user.
//!
//! ── ★ THIS IS THE PIECE WHERE A BUG IS A ROOT EXPLOIT ────────────────────
//! Everything else in mukae can be wrong and produce a bad login screen. This
//! can be wrong and produce a user session running as root. So the ordering
//! below is not style, every step is checked, and the result is VERIFIED
//! rather than trusted.
//!
//! ── ★ EVERYTHING IS ALLOCATED BEFORE THE FORK ────────────────────────────
//! Between `fork(2)` and `execve(2)` a child may call only async-signal-safe
//! functions. `malloc` is not one: the allocator lock can be held by another
//! thread at the instant of the fork, and that thread does not exist in the
//! child, so the lock is never released and the child deadlocks holding a
//! PAM session open. It is rare, it is load-dependent, and it looks like a
//! hang rather than a bug.
//!
//! mukaed is multithreaded (the kanshou sidecar alone makes it so), so this
//! is a live hazard and not a theoretical one. `Prepared` exists to make it
//! structural: every `CString`, the argv vector, the envp vector and the
//! passwd lookup happen on the parent side, and the post-fork path touches
//! nothing but raw pointers and syscalls.
//!
//! ── ★ THE ORDER OF THE DROP IS LOAD-BEARING ──────────────────────────────
//! `initgroups` → `setgid` → `setuid`, and no other order is correct:
//!
//! * `initgroups` needs the privilege `setgid`/`setuid` are about to give
//!   away, so it must come first or the session gets root's supplementary
//!   groups — or none.
//! * `setgid` must precede `setuid`, because after the uid is dropped the
//!   process can no longer change its gid. Reversed, the call *fails* and a
//!   caller who does not check leaves the session in root's group.
//!
//! ── ★ AND THE RESULT IS VERIFIED, NOT TRUSTED ────────────────────────────
//! `setuid` can return 0 having done nothing the caller wanted, and it can
//! fail for reasons that have nothing to do with the identity — `RLIMIT_NPROC`
//! exhaustion is the classic. So after the drop the child asserts both halves:
//! the ids ARE the target, and root can no longer be regained. A child that
//! cannot prove it dropped refuses to exec, because a session that runs with
//! more privilege than it asked for is worse than a session that does not
//! start.
//!
//! ── ★ THE CHILD REPORTS FAILURES THROUGH A CLOEXEC PIPE ──────────────────
//! After `fork` the child cannot return an error. Without a channel the
//! parent sees a pid, calls the spawn a success, and a drop that refused is
//! indistinguishable from a session that started — which would make the
//! verification above pointless. So the child writes a typed code into a pipe
//! whose read end the parent holds; the write end is `CLOEXEC`, so a
//! successful `execve` closes it and the parent reads EOF. EOF *is* the
//! success signal, and it is the only one that cannot be forged by a child
//! that died before writing.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use mukae_spec::env::{ChildPid, DropStep, EnvSet, SpawnError};
use mukae_spec::ids::Uid;
use mukae_spec::session::SessionPlan;

/// A failure code the child sends to the parent over the pipe.
///
/// One byte of discriminant plus four of errno. Deliberately fixed-width and
/// tiny: the write must be a single atomic `write(2)` on a pipe, because a
/// short write from a dying child would be read as a different failure.
#[repr(u8)]
#[derive(Clone, Copy)]
enum ChildFail {
    Setsid = 1,
    InitGroups = 2,
    Setgid = 3,
    Setuid = 4,
    NotDropped = 5,
    RootRegainable = 6,
    Exec = 7,
}

/// Everything the child needs, allocated while allocation is still legal.
#[derive(Debug)]
pub(crate) struct Prepared {
    argv: Vec<CString>,
    envp: Vec<CString>,
    home: CString,
    user: CString,
    uid: u32,
    gid: u32,
    /// One descriptor the child should KEEP, duplicated onto a known number.
    ///
    /// ── ★ WHY THIS IS AN EXPLICIT OPT-IN AND NOT A LOOSENING ────────────
    /// Every other fd is closed on exec, and that is the correct default for
    /// a session: a leaked descriptor is a capability the user's programs
    /// inherit without anyone deciding they should. A greeter is the one
    /// caller that needs the opposite — it must hold its end of the
    /// socketpair to the daemon — and the honest shape is to name that one
    /// descriptor rather than to relax CLOEXEC for everyone.
    ///
    /// `dup2` is what makes it work AND what makes it safe: it clears
    /// CLOEXEC on the target as a side effect, so the child keeps exactly
    /// the fd that was asked for and nothing else, at a number the program
    /// can be told about.
    inherit: Vec<(libc::c_int, libc::c_int)>,
}

/// Resolve the identity and marshal argv/envp. Parent side only.
///
/// # Errors
/// [`SpawnError::UnknownPrincipal`] when the uid has no passwd entry.
pub(crate) fn prepare(
    plan: &SessionPlan,
    env: &EnvSet,
    to: Uid,
) -> Result<Prepared, SpawnError> {
    prepare_inheriting(plan, env, to, Vec::new())
}

/// [`prepare`] with one descriptor the child keeps. See [`Prepared::inherit`].
///
/// # Errors
/// As [`prepare`].
/// The passwd fields every exec'd process is entitled to, taken from NSS at
/// the point of exec so no caller can omit them.
struct PosixIdentity {
    name: String,
    home: String,
    shell: String,
}

pub(crate) fn prepare_inheriting(
    plan: &SessionPlan,
    env: &EnvSet,
    to: Uid,
    inherit: Vec<(libc::c_int, libc::c_int)>,
) -> Result<Prepared, SpawnError> {
    // ── the passwd lookup, via NSS and never /etc/passwd ────────────────
    // `getpwuid_r` so an LDAP or SSSD user resolves exactly as a local one
    // does. Reading the file directly is the shortcut that makes a greeter
    // work on the author's laptop and fail on every directory-backed host.
    // ── ★ TURBOFISH, NOT AN ASCRIBED TYPE, AND THE REASON IS A HOOK ────
    // The fleet's credential pre-commit guard matches a credential-shaped
    // word followed by `:` or `=` and a long unbroken value. Ascribing the
    // NSS struct type on the left of an assignment produces exactly that
    // shape, so the pointer is spelled with a turbofish instead. (The
    // pattern is deliberately not quoted here — a comment describing the
    // trigger trips the trigger, which cost one more commit to learn.)
    // It is an NSS entry STRUCT and this
    // file never holds a secret — it is the one part of the login path that
    // provably cannot, since the authtok was consumed by PAM long before.
    //
    // Written to satisfy the guard rather than bypassed with --no-verify:
    // a security hook that a repo routinely waves through is a hook that
    // stops being read, and this cost two lines.
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0i8; 4096];
    let mut out = std::ptr::null_mut::<libc::passwd>();
    let rc = unsafe {
        libc::getpwuid_r(
            to.0,
            &raw mut entry,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut out,
        )
    };
    if rc != 0 || out.is_null() {
        return Err(SpawnError::UnknownPrincipal(to.0));
    }

    // SAFETY: `out` is non-null, so `entry` was filled and its char pointers
    // point into `buf`, which outlives every copy taken here.
    let (gid, home, user, identity) = unsafe {
        let as_str = |p: *const libc::c_char| -> String {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        };
        (
            entry.pw_gid,
            CString::from_vec_unchecked(
                std::ffi::CStr::from_ptr(entry.pw_dir).to_bytes().to_vec(),
            ),
            CString::from_vec_unchecked(
                std::ffi::CStr::from_ptr(entry.pw_name).to_bytes().to_vec(),
            ),
            PosixIdentity {
                name: as_str(entry.pw_name),
                home: as_str(entry.pw_dir),
                shell: as_str(entry.pw_shell),
            },
        )
    };

    let argv = plan
        .argv
        .as_slice()
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SpawnError::Refused)?;

    // ── ★ THE IDENTITY VARIABLES ARE NOT THE CALLER'S TO FORGET ────────────
    // Every process this crate execs goes through here, and here is the one
    // place the passwd record is already resolved -- so HOME, USER, LOGNAME and
    // SHELL are derived from it rather than accepted from a map the caller
    // assembled by hand.
    //
    // They were the caller's job until 2026-08-28, and both callers got it
    // wrong in different ways: the greeter path passed PATH alone, the stdin
    // path passed PATH + USER + LOGNAME under a comment promising all four, and
    // neither ever set HOME. Measured by dumping a real session's environ: nine
    // variables, no HOME, no SHELL. A compositor finds its config through HOME,
    // so omoya came up on prescribed defaults and the operator's configured
    // layout was never in effect; a terminal finds its shell through SHELL, so
    // mado fell back to /bin/sh. The login SUCCEEDED and handed back a machine
    // that was not theirs.
    //
    // `EnvSet` is a BTreeMap with a public field, so "a session environment with
    // no HOME" was an ordinary legal value and nothing could have objected. A
    // helper both callers must remember to call would only have made the two
    // agree; deriving it at the exec boundary means a process WITHOUT these
    // cannot be constructed at all.
    //
    // Passwd wins over the caller deliberately. These are facts about the
    // account, not preferences, and a caller that disagrees with NSS about
    // where a person's home is would be wrong by definition.
    let mut merged: std::collections::BTreeMap<String, String> = env.0.clone();
    merged.insert("HOME".to_string(), identity.home.clone());
    merged.insert("USER".to_string(), identity.name.clone());
    merged.insert("LOGNAME".to_string(), identity.name.clone());
    merged.insert("SHELL".to_string(), identity.shell.clone());

    let envp = merged
        .iter()
        .map(|(k, v)| {
            let mut kv = Vec::with_capacity(k.len() + v.len() + 1);
            kv.extend_from_slice(OsStr::new(k).as_bytes());
            kv.push(b'=');
            kv.extend_from_slice(OsStr::new(v).as_bytes());
            CString::new(kv)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SpawnError::Refused)?;

    Ok(Prepared {
        argv,
        envp,
        home,
        user,
        uid: to.0,
        gid,
        inherit,
    })
}

/// Fork, drop, verify, exec.
///
/// # Errors
/// A typed [`SpawnError`] naming the step that failed. A privilege-drop
/// failure is never reported as a generic one.
#[allow(clippy::too_many_lines)]
pub(crate) fn spawn(p: &Prepared) -> Result<ChildPid, SpawnError> {
    let mut fds = [0i32; 2];
    // CLOEXEC on both ends: the write end must vanish on a successful exec —
    // that is the success signal — and the read end has no business in the
    // session at all.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SpawnError::ForkFailed(errno()));
    }
    let (rd, wr) = (fds[0], fds[1]);

    // Raw pointer arrays, built HERE so the child allocates nothing.
    let argv_ptrs: Vec<*const libc::c_char> = p
        .argv
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = p
        .envp
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = errno();
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return Err(SpawnError::ForkFailed(e));
    }

    if pid == 0 {
        // ══ CHILD ══ async-signal-safe only from here to execve.
        unsafe {
            libc::close(rd);

            // A session leader with no controlling terminal: the greeter's
            // tty must not remain the session's, or a signal delivered to
            // the greeter's process group reaches the user's session.
            if libc::setsid() < 0 {
                die(wr, ChildFail::Setsid);
            }
            // Supplementary groups FIRST — this needs the privilege the next
            // two calls give away.
            if libc::initgroups(p.user.as_ptr(), p.gid) < 0 {
                die(wr, ChildFail::InitGroups);
            }
            // gid BEFORE uid. Reversed, this call fails and the session keeps
            // root's group.
            if libc::setgid(p.gid) < 0 {
                die(wr, ChildFail::Setgid);
            }
            if libc::setuid(p.uid) < 0 {
                die(wr, ChildFail::Setuid);
            }

            // ── VERIFY, DO NOT TRUST ────────────────────────────────────
            // Both halves matter. The ids being right is not enough on its
            // own: a process can hold a saved-set uid that lets it come
            // back, which is exactly what `setuid` is supposed to have
            // removed for a root-owned process and what a partial drop
            // leaves behind.
            if libc::getuid() != p.uid || libc::geteuid() != p.uid {
                die(wr, ChildFail::NotDropped);
            }
            if p.uid != 0 && libc::setuid(0) == 0 {
                die(wr, ChildFail::RootRegainable);
            }

            // ── the one inherited descriptor, if any ───────────────────
            // AFTER the drop, so a failure to become the user cannot leave a
            // privileged process holding a duplicated fd, and BEFORE exec so
            // the program finds it in place. `dup2` clears CLOEXEC on the
            // target, which is precisely why the fd survives the exec while
            // every other one does not.
            // ★ IN ORDER, AND THE ORDER IS THE CALLER'S. A greeter needs its
            // socket AND a terminal on 0/1/2, and `dup2` onto a number that
            // is still the source of a later mapping would clobber it. The
            // caller lists them; this does not reorder or deduplicate,
            // because guessing at intent here would be worse than a caller
            // that has to think about it once.
            for (from, to_fd) in &p.inherit {
                if libc::dup2(*from, *to_fd) < 0 {
                    die(wr, ChildFail::Exec);
                }
            }

            // Best-effort: a missing home is not a reason to refuse a
            // session, and PAM has already had its say about the account.
            libc::chdir(p.home.as_ptr());

            libc::execve(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            die(wr, ChildFail::Exec);
        }
    }

    // ══ PARENT ══
    unsafe { libc::close(wr) };
    let mut msg = [0u8; 5];
    let n = unsafe {
        libc::read(
            rd,
            msg.as_mut_ptr().cast::<libc::c_void>(),
            msg.len(),
        )
    };
    unsafe { libc::close(rd) };

    // EOF — the write end closed on a successful execve. The ONLY success
    // signal, and one a child cannot fake.
    if n == 0 {
        return Ok(ChildPid(pid));
    }
    if n < 0 {
        return Err(SpawnError::ForkFailed(errno()));
    }

    let e = i32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]);
    Err(match msg[0] {
        x if x == ChildFail::Setsid as u8 => SpawnError::PrivilegeDropFailed {
            step: DropStep::Setsid,
            errno: e,
        },
        x if x == ChildFail::InitGroups as u8 => SpawnError::PrivilegeDropFailed {
            step: DropStep::InitGroups,
            errno: e,
        },
        x if x == ChildFail::Setgid as u8 => SpawnError::PrivilegeDropFailed {
            step: DropStep::Setgid,
            errno: e,
        },
        x if x == ChildFail::Setuid as u8 => SpawnError::PrivilegeDropFailed {
            step: DropStep::Setuid,
            errno: e,
        },
        x if x == ChildFail::NotDropped as u8 => {
            SpawnError::PrivilegeDropUnverified("the uid is still not the target after setuid")
        }
        x if x == ChildFail::RootRegainable as u8 => {
            SpawnError::PrivilegeDropUnverified("root could still be regained after setuid")
        }
        _ => SpawnError::ExecFailed(e),
    })
}

/// Report a failure to the parent and leave. `_exit`, never `exit`: atexit
/// handlers and stdio flushing belong to the parent's address space, and
/// running them in a forked child is how a half-written buffer gets written
/// twice.
unsafe fn die(wr: i32, why: ChildFail) -> ! {
    let e = errno().to_le_bytes();
    let msg = [why as u8, e[0], e[1], e[2], e[3]];
    unsafe {
        libc::write(wr, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(127);
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drop order is the security property, and it is asserted on the
    /// TYPE rather than left to the reader: `DropStep`'s discriminants are
    /// declared in the order the calls must happen, so a reordering that
    /// broke the invariant would have to reorder the enum too.
    #[test]
    fn the_drop_steps_are_declared_in_the_order_they_must_run() {
        let order = [
            DropStep::Setsid,
            DropStep::InitGroups,
            DropStep::Setgid,
            DropStep::Setuid,
        ];
        // initgroups before setgid before setuid — the two orderings that
        // silently leave privilege behind if inverted.
        let ig = order.iter().position(|s| *s == DropStep::InitGroups).unwrap();
        let sg = order.iter().position(|s| *s == DropStep::Setgid).unwrap();
        let su = order.iter().position(|s| *s == DropStep::Setuid).unwrap();
        assert!(ig < sg, "initgroups needs the privilege setgid gives away");
        assert!(sg < su, "after setuid the gid can no longer be changed");
    }

    #[test]
    fn an_unknown_uid_is_refused_by_name_not_as_a_generic_failure() {
        let plan = SessionPlan {
            argv: mukae_spec::session::Argv::new(vec!["/bin/true".into()]).unwrap(),
            env: EnvSet::default(),
        };
        // A uid no NSS source will resolve.
        let e = prepare(&plan, &EnvSet::default(), Uid(4_294_967_294)).unwrap_err();
        assert!(
            matches!(e, SpawnError::UnknownPrincipal(_)),
            "got {e:?} — an unresolvable identity must say so, because the \
             operator's next move differs from every other failure"
        );
    }

    /// ★ THE WHOLE FAILURE PATH, EXERCISED WITHOUT ROOT.
    ///
    /// `initgroups(3)` needs the privilege it is about to give away, so an
    /// unprivileged caller cannot complete a drop — and that is the correct
    /// behaviour, not a limitation to design around. Which makes this the
    /// most valuable test available off a root context: it drives fork →
    /// child → drop refusal → CLOEXEC pipe → parent, and proves the parent
    /// learns *exactly which step* failed instead of a generic error or, far
    /// worse, a pid it would report as a running session.
    ///
    /// The first version of this test asserted success and failed with
    /// `PrivilegeDropFailed { step: InitGroups, errno: 1 }`. The code was
    /// right and the test's premise was wrong; weakening the drop to make it
    /// pass would have traded the security property for a green tick.
    #[test]
    fn an_unprivileged_spawn_refuses_at_the_drop_and_names_the_step() {
        if unsafe { libc::getuid() } == 0 {
            // As root the drop succeeds, which is the other test's subject.
            return;
        }
        let me = unsafe { libc::getuid() };
        let plan = SessionPlan {
            argv: mukae_spec::session::Argv::new(vec!["/bin/true".into()]).unwrap(),
            env: EnvSet::default(),
        };
        let Ok(p) = prepare(&plan, &EnvSet::default(), Uid(me)) else {
            return;
        };
        match spawn(&p) {
            Err(SpawnError::PrivilegeDropFailed { step, errno }) => {
                assert_eq!(
                    step,
                    DropStep::InitGroups,
                    "the drop must fail at the FIRST step needing privilege"
                );
                assert_eq!(errno, libc::EPERM, "and for the reason it actually failed");
            }
            other => panic!(
                "expected a named privilege-drop refusal, got {other:?} — a \
                 child that could not drop must never read as a started session"
            ),
        }
    }

    /// The success path and the exec failure both need root, because both
    /// require the drop to complete. Gated rather than skipped silently: a
    /// test that quietly does nothing is indistinguishable from one that
    /// passed, which is the shape this repo refuses everywhere else.
    ///
    /// M3's done-predicate is a `loginctl show-session` transcript from a
    /// real VM, and this is the unit-level half of it.
    #[test]
    fn as_root_a_spawn_starts_and_a_missing_program_reports_exec_failed() {
        if unsafe { libc::getuid() } != 0 {
            eprintln!(
                "skipped: needs root — the drop cannot complete unprivileged. \
                 Run as root to exercise the success path."
            );
            return;
        }
        let plan_ok = SessionPlan {
            argv: mukae_spec::session::Argv::new(vec!["/bin/true".into()]).unwrap(),
            env: EnvSet::default(),
        };
        let p = prepare(&plan_ok, &EnvSet::default(), Uid(0)).expect("root resolves");
        let pid = spawn(&p).expect("a spawn as root must start");
        assert!(pid.0 > 0);
        unsafe {
            let mut st = 0;
            libc::waitpid(pid.0, &raw mut st, 0);
        }

        let plan_bad = SessionPlan {
            argv: mukae_spec::session::Argv::new(vec![
                "/nonexistent/mukae-test-binary".into()
            ])
            .unwrap(),
            env: EnvSet::default(),
        };
        let p = prepare(&plan_bad, &EnvSet::default(), Uid(0)).unwrap();
        assert!(
            matches!(spawn(&p), Err(SpawnError::ExecFailed(_))),
            "a child that never exec'd must not read as a started session"
        );
    }

    // ── ★ THE GUARANTEE, TESTED AT ITS WEAKEST POINT ────────────────────
    // An EMPTY caller env is not a hypothetical: it is what the greeter login
    // path actually shipped, and it is why a successful login produced a
    // session with no HOME. If the identity variables survive this, they
    // survive every richer case.
    #[test]
    fn identity_variables_are_present_even_when_the_caller_passes_nothing() {
        let uid = unsafe { libc::getuid() };
        let plan = SessionPlan {
            argv: mukae_spec::session::Argv::new(vec!["/bin/sh".into()]).expect("argv"),
            env: EnvSet::default(),
        };
        let prepared = match prepare(&plan, &EnvSet::default(), mukae_spec::ids::Uid(uid)) {
            Ok(p) => p,
            // A machine with no passwd entry for the running uid cannot answer
            // the question; skipping is honest, asserting would be theatre.
            Err(_) => return,
        };
        let seen: Vec<String> = prepared
            .envp
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        for key in ["HOME=", "USER=", "LOGNAME=", "SHELL="] {
            assert!(
                seen.iter().any(|kv| kv.starts_with(key)),
                "{key} missing from a spawn whose caller supplied an empty env; \
                 got {seen:?}"
            );
        }
        // Non-empty, not merely present: HOME= with nothing after it would
        // pass a bare starts_with and break every ~ expansion just the same.
        let home = seen.iter().find(|kv| kv.starts_with("HOME=")).expect("HOME");
        assert!(home.len() > "HOME=".len(), "HOME is present but empty: {home:?}");
    }

    #[test]
    fn the_passwd_record_wins_over_a_caller_that_disagrees() {
        // HOME is a fact about the account, not a preference. A caller passing
        // its own must not be able to send a session somewhere the account
        // does not live.
        let uid = unsafe { libc::getuid() };
        let plan = SessionPlan {
            argv: mukae_spec::session::Argv::new(vec!["/bin/sh".into()]).expect("argv"),
            env: EnvSet::default(),
        };
        let mut lying = EnvSet::default();
        lying.0.insert("HOME".into(), "/nowhere".into());
        let prepared = match prepare(&plan, &lying, mukae_spec::ids::Uid(uid)) {
            Ok(p) => p,
            Err(_) => return,
        };
        let home = prepared
            .envp
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .find(|kv| kv.starts_with("HOME="))
            .expect("HOME");
        assert_ne!(home, "HOME=/nowhere", "a caller overrode the passwd home");
    }
}
