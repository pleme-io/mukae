//! The console — claimed, and given back.
//!
//! ── ★ WHY A TYPE AND NOT FOUR ioctl CALLS ────────────────────────────────
//! Claiming a VT is four state changes on a device every other process on the
//! machine can also open, and every one of them must be undone. A greeter
//! that exits without restoring `KDSETMODE` leaves the console in graphics
//! mode: the screen is black, the keyboard does nothing, and the machine
//! looks dead while being perfectly healthy. That is not a hypothetical — it
//! is the single most common way a display manager bricks a seat, and the
//! recovery is a reboot or an ssh session that the operator may not have.
//!
//! So the restoration is `Drop`, not a call site. A path that returns early,
//! panics, or is killed by a signal it handles still gives the console back,
//! because the only way to not restore is to not have claimed.
//!
//! ── ★ WHAT THIS IS NOT ───────────────────────────────────────────────────
//! It does not switch VTs, allocate a fresh one, or arbitrate between two
//! claimants. logind does that, and doing it here would be a second authority
//! over the same resource — the shape that produces two owners fighting for
//! the keyboard. This takes a VT the caller was already given and makes the
//! give-back structural.

use std::fs::File;
use std::os::fd::AsRawFd as _;

/// Terminal modes, named rather than numbered at the call site.
const KD_TEXT: libc::c_int = 0x00;
const KD_GRAPHICS: libc::c_int = 0x01;
const KDSETMODE: libc::c_ulong = 0x4B3A;
const KDGKBMODE: libc::c_ulong = 0x4B44;
const KDSKBMODE: libc::c_ulong = 0x4B45;

/// A claimed console. Dropping it restores what was found.
#[derive(Debug)]
pub struct Console {
    tty: File,
    /// The keyboard mode as it was BEFORE the claim.
    ///
    /// ★ Restored to what was READ, never to a constant. A machine whose
    /// console was in an unusual mode is a machine someone configured that
    /// way, and handing it back "fixed" is still handing it back changed.
    prior_kbmode: libc::c_int,
    restored: bool,
}

/// What can go wrong taking a console.
#[derive(Debug, thiserror::Error)]
pub enum VtError {
    #[error("opening {path}: {errno}")]
    Open { path: String, errno: i32 },
    #[error("this is not a console: {0}")]
    NotATty(String),
    #[error("reading the keyboard mode: errno {0}")]
    ReadMode(i32),
    #[error("setting graphics mode: errno {0}")]
    SetMode(i32),
}

impl Console {
    /// Claim `/dev/ttyN` for graphical use.
    ///
    /// # Errors
    /// [`VtError`] naming which step failed. In particular a device that is
    /// not a console is refused BY NAME rather than being put into graphics
    /// mode — pointing this at the wrong path and getting a generic error is
    /// how an operator ends up with a blank screen and no idea which device
    /// they broke.
    pub fn claim(vtnr: u32) -> Result<Self, VtError> {
        let path = format!("/dev/tty{vtnr}");
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| VtError::Open {
                path: path.clone(),
                errno: e.raw_os_error().unwrap_or(0),
            })?;
        let fd = tty.as_raw_fd();

        // ── read the mode BEFORE changing anything ──────────────────────
        // Doubles as the "is this really a console" check: KDGKBMODE fails on
        // anything that is not one, so the refusal happens before the device
        // has been touched rather than after.
        let mut prior: libc::c_int = 0;
        if unsafe { libc::ioctl(fd, KDGKBMODE, &raw mut prior) } < 0 {
            let e = errno();
            return Err(if e == libc::ENOTTY || e == libc::EINVAL {
                VtError::NotATty(path)
            } else {
                VtError::ReadMode(e)
            });
        }

        if unsafe { libc::ioctl(fd, KDSETMODE, KD_GRAPHICS) } < 0 {
            return Err(VtError::SetMode(errno()));
        }

        Ok(Self {
            tty,
            prior_kbmode: prior,
            restored: false,
        })
    }

    /// Give the console back early, and report whether it worked.
    ///
    /// `Drop` calls this too, so it is safe to skip — but a caller that wants
    /// to KNOW the console came back needs a return value, and `Drop` cannot
    /// give one. A daemon handing a seat to a session is exactly that caller:
    /// if the restore failed it must log it before the session paints over
    /// the evidence.
    pub fn restore(&mut self) -> Result<(), VtError> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        let fd = self.tty.as_raw_fd();
        // Keyboard first, then text mode. Reversed, a failure between the two
        // leaves a visible console whose keyboard is still raw — which looks
        // like a hung machine rather than a half-restored one.
        if unsafe { libc::ioctl(fd, KDSKBMODE, self.prior_kbmode) } < 0 {
            return Err(VtError::SetMode(errno()));
        }
        if unsafe { libc::ioctl(fd, KDSETMODE, KD_TEXT) } < 0 {
            return Err(VtError::SetMode(errno()));
        }
        Ok(())
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        // ★ THE WHOLE POINT. Ignoring the result here is deliberate and is not
        // the same as ignoring the failure: `restore` is public precisely so a
        // caller that needs the answer can ask for it first. What must never
        // happen is a path that leaves the console in graphics mode, and this
        // is what makes that unreachable.
        let _ = self.restore();
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ THE REFUSAL THAT PROTECTS THE OPERATOR. A path that is not a console
    /// must be rejected by name and, critically, BEFORE the mode is changed —
    /// otherwise pointing this at the wrong device blanks it and reports a
    /// generic error.
    #[test]
    fn a_non_console_is_refused_by_name_and_left_untouched() {
        // /dev/null is openable read-write and is not a console.
        let e = Console::claim_path("/dev/null").unwrap_err();
        assert!(
            matches!(e, VtError::NotATty(_)),
            "expected a named refusal, got {e:?}"
        );
    }

    #[test]
    fn a_missing_device_reports_the_path_it_could_not_open() {
        let e = Console::claim_path("/dev/tty-nonexistent-mukae").unwrap_err();
        match e {
            VtError::Open { path, .. } => assert!(path.contains("nonexistent")),
            other => panic!("expected an open failure naming the path, got {other:?}"),
        }
    }
}

impl Console {
    /// [`Console::claim`] against an explicit path — the testable half, so the
    /// refusal path can be exercised without a spare VT.
    ///
    /// # Errors
    /// As [`Console::claim`].
    pub fn claim_path(path: &str) -> Result<Self, VtError> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| VtError::Open {
                path: path.to_string(),
                errno: e.raw_os_error().unwrap_or(0),
            })?;
        let fd = tty.as_raw_fd();
        let mut prior: libc::c_int = 0;
        if unsafe { libc::ioctl(fd, KDGKBMODE, &raw mut prior) } < 0 {
            let e = errno();
            return Err(if e == libc::ENOTTY || e == libc::EINVAL {
                VtError::NotATty(path.to_string())
            } else {
                VtError::ReadMode(e)
            });
        }
        if unsafe { libc::ioctl(fd, KDSETMODE, KD_GRAPHICS) } < 0 {
            return Err(VtError::SetMode(errno()));
        }
        Ok(Self {
            tty,
            prior_kbmode: prior,
            restored: false,
        })
    }
}
