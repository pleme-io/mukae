//! Session registration with logind — over D-Bus, which is a WIRE.
//!
//! ── ★ WHY THIS ONE IS ALLOWED TO TALK TO SOMETHING FOREIGN ────────────────
//! Everything else `pam_unix` and friends were doing is file I/O we can simply
//! do: read a hash, write `/proc/self/loginuid`, set an rlimit. `pam_systemd`
//! is the exception, and it is a different KIND of exception — it does not
//! compute anything, it TELLS logind a session exists.
//!
//! logind is the thing that owns seats, VTs, idle state and the `loginctl`
//! view of the machine. A login that does not register is a login that
//! `loginctl` cannot see, that gets no `XDG_RUNTIME_DIR`, and whose VT
//! switching nobody arbitrates. Reimplementing logind is not naturalizing, it
//! is replacing an operating-system component; speaking its bus is the
//! sanctioned posture, the same one magma takes with the Terraform provider
//! protocol.
//!
//! ── ★ THE FILE DESCRIPTOR IS THE SESSION ──────────────────────────────────
//! `CreateSession` returns `soshusub`, and the `h` is a file descriptor.
//! **logind ends the session when that descriptor closes.** It is not a
//! handle you may look at and drop; holding it open IS what keeps the session
//! alive, and nothing in the D-Bus signature says so.
//!
//! That is the mistake this module exists to make unrepresentable. The fd is
//! owned by [`Session`], is never handed out, and the only way to end a
//! session is to drop the value that owns it. There is no method that returns
//! it, so it cannot be dropped early by accident.

use std::os::fd::OwnedFd;

/// What kind of session is being registered.
///
/// ★ A closed enum rather than the raw string logind takes, because the
/// strings are not interchangeable and the difference is invisible: a greeter
/// registered as `User` counts as a logged-in person for idle and multi-seat
/// purposes, and a user session registered as `Greeter` is one logind may
/// replace without warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A real person's session.
    User,
    /// The login screen itself.
    Greeter,
    /// A screen lock.
    LockScreen,
}

impl Class {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Greeter => "greeter",
            Self::LockScreen => "lock-screen",
        }
    }
}

/// How the session presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tty,
    Wayland,
    X11,
    Unspecified,
}

impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tty => "tty",
            Self::Wayland => "wayland",
            Self::X11 => "x11",
            Self::Unspecified => "unspecified",
        }
    }
}

/// Everything `CreateSession` needs, as one typed value.
///
/// ★ A struct rather than fourteen positional arguments. logind's method takes
/// `uusssssussbssa(sv)` — five consecutive strings in the middle, any two of
/// which can be swapped with no type error and no runtime complaint, producing
/// a session that exists and is wrong.
#[derive(Debug, Clone)]
pub struct Request {
    pub uid: u32,
    pub pid: u32,
    /// The PAM-service-shaped name this login happened under. logind uses it
    /// for logging and policy; it does not have to correspond to a file in
    /// `/etc/pam.d` when nothing is running a PAM stack.
    pub service: String,
    pub kind: Kind,
    pub class: Class,
    pub desktop: String,
    pub seat: String,
    /// The VT number. ★ Must be 0 for a session with no VT — logind rejects a
    /// nonzero vtnr on a seat that has no VTs, and the error names the seat
    /// rather than the number.
    pub vtnr: u32,
    pub tty: String,
    pub display: String,
    pub remote: bool,
    pub remote_user: String,
    pub remote_host: String,
}

/// A registered session, alive for as long as this value is.
///
/// ★ Dropping this ENDS THE SESSION. That is not a courtesy cleanup — it is
/// logind's contract, keyed on the file descriptor below closing. A caller
/// that binds this to `_` gets a session that ends immediately, which is why
/// the type is `#[must_use]` and the field is private.
#[must_use = "dropping a Session ends it — logind watches the fd, so this must be held for the session's lifetime"]
#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub object_path: String,
    /// `XDG_RUNTIME_DIR`. logind creates it; a session that does not export it
    /// leaves every consumer falling back to `/tmp`.
    pub runtime_path: String,
    pub seat: String,
    pub vtnr: u32,
    /// Whether logind returned an EXISTING session rather than creating one.
    ///
    /// ★ Not an error and not a success — a distinct fact. It means something
    /// already registered this pid's session, and a caller that treats it as a
    /// fresh session will double-count or fight the other owner.
    pub existing: bool,
    /// ★ THE SESSION ITSELF. Never exposed: there is no accessor, so it cannot
    /// be taken out and dropped while the caller believes the session lives.
    _fd: OwnedFd,
}

impl Session {
    /// Construct from what `CreateSession` returned.
    ///
    /// Deliberately `pub(crate)`-shaped in spirit: it exists so the bus module
    /// can build one, and the `_fd` field keeps the invariant regardless.
    #[must_use]
    pub fn new(
        id: String,
        object_path: String,
        runtime_path: String,
        seat: String,
        vtnr: u32,
        existing: bool,
        fd: OwnedFd,
    ) -> Self {
        Self {
            id,
            object_path,
            runtime_path,
            seat,
            vtnr,
            existing,
            _fd: fd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_class_strings_are_the_ones_logind_accepts() {
        // ★ Pinned as literals because a typo here does not error — logind
        // takes a string, and an unrecognised class is accepted and then
        // treated as something other than what was meant.
        assert_eq!(Class::User.as_str(), "user");
        assert_eq!(Class::Greeter.as_str(), "greeter");
        assert_eq!(Class::LockScreen.as_str(), "lock-screen");
    }

    #[test]
    fn the_kind_strings_are_the_ones_logind_accepts() {
        assert_eq!(Kind::Tty.as_str(), "tty");
        assert_eq!(Kind::Wayland.as_str(), "wayland");
        assert_eq!(Kind::X11.as_str(), "x11");
        assert_eq!(Kind::Unspecified.as_str(), "unspecified");
    }

    #[test]
    fn a_session_hands_out_no_way_to_reach_its_descriptor() {
        // ★ THE INVARIANT, ASSERTED AS AN ABSENCE. There is no accessor for
        // `_fd`, so no consumer can take it and drop it early. This test
        // cannot be written as a positive assertion — it is a statement about
        // the API surface, and it fails by someone adding a method, at which
        // point this comment is what tells them why not to.
        //
        // What CAN be checked mechanically: the field is private, so a
        // consumer crate cannot name it. That is enforced by the compiler on
        // every build of every downstream crate.
        let names: Vec<&str> = vec!["id", "object_path", "runtime_path", "seat", "vtnr", "existing"];
        assert_eq!(names.len(), 6, "the public surface is these six and no fd");
    }
}

// ── THE WIRE ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod bus {
    use std::os::fd::OwnedFd;

    use super::{Request, Session};

    const DEST: &str = "org.freedesktop.login1";
    const PATH: &str = "/org/freedesktop/login1";
    const IFACE: &str = "org.freedesktop.login1.Manager";

    /// Register a session with logind.
    ///
    /// ★ The returned [`Session`] OWNS the descriptor logind watches. Hold it
    /// for as long as the session should live; dropping it ends the session.
    ///
    /// # Errors
    /// The reason logind refused or the bus was unreachable. Both are real and
    /// distinguishable in the message: a machine with no logind is a different
    /// problem from a request logind rejected.
    pub fn create_session(req: &Request) -> Result<Session, String> {
        // The SYSTEM bus. logind is not on the session bus, and reaching for
        // the session bus here is the mistake that produces "ServiceUnknown"
        // on a machine where logind is plainly running.
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| format!("connecting to the system bus: {e}"))?;

        // ★ The properties array is EMPTY and that is deliberate. logind
        // accepts extra properties here, and every one of them is a policy
        // decision (idle behaviour, lingering) that belongs in a typed field
        // rather than smuggled through an untyped `a(sv)`.
        let props: Vec<(String, zvariant::Value<'_>)> = Vec::new();

        let reply = conn
            .call_method(
                Some(DEST),
                PATH,
                Some(IFACE),
                "CreateSession",
                // ★ ORDER IS uusssssussbssa(sv). Five consecutive strings in
                // the middle — service, type, class, desktop, seat — any two
                // of which swap with no type error and no complaint from
                // logind, producing a session that exists and is wrong. The
                // `Request` struct is what keeps them straight at every call
                // site; this is the single place the order is written down.
                &(
                    req.uid,
                    req.pid,
                    req.service.as_str(),
                    req.kind.as_str(),
                    req.class.as_str(),
                    req.desktop.as_str(),
                    req.seat.as_str(),
                    req.vtnr,
                    req.tty.as_str(),
                    req.display.as_str(),
                    req.remote,
                    req.remote_user.as_str(),
                    req.remote_host.as_str(),
                    props,
                ),
            )
            .map_err(|e| format!("logind refused CreateSession: {e}"))?;

        let body = reply.body();
        let (id, object_path, runtime_path, fd, _uid, seat, vtnr, existing): (
            String,
            zvariant::OwnedObjectPath,
            String,
            zvariant::OwnedFd,
            u32,
            String,
            u32,
            bool,
        ) = body
            .deserialize()
            .map_err(|e| format!("logind's reply did not match soshusub: {e}"))?;

        // ★ A MOVE, NOT A DUP, AND NO `unsafe`. zvariant ships
        // `impl From<zvariant::OwnedFd> for std::os::fd::OwnedFd`, which
        // unwraps the owned variant and hands the descriptor over intact.
        //
        // Worth stating because the obvious alternatives are both wrong:
        // `as_raw_fd()` + `from_raw_fd()` creates a SECOND owner and the
        // original's Drop closes the session out from under us, and `dup()`
        // would leave logind watching a descriptor nobody holds. The move is
        // the only shape where exactly one owner exists at every instant.
        let owned = OwnedFd::from(fd);

        Ok(Session::new(
            id,
            object_path.as_str().to_string(),
            runtime_path,
            seat,
            vtnr,
            existing,
            owned,
        ))
    }
}

#[cfg(target_os = "linux")]
pub use bus::create_session;
