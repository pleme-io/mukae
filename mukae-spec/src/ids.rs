//! The newtypes. Parse, don't validate.
//!
//! Every one of these is a `String`/`u32` that some login manager somewhere
//! passes around bare, and every one of them has a documented bug attached to
//! being bare. They are constructed at a parse boundary and are unforgeable
//! afterwards.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A POSIX user id.
///
/// Deliberately not `usize` and not signed: `-1` is `nobody` on some systems
/// and an error sentinel on others, and a login manager must never be in a
/// position to confuse the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Uid(pub u32);

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A seat, as logind names them.
///
/// ★ The shape here is what makes illegal state [5] unrepresentable. VTs exist
/// only on `seat0` (world-fact W8), and the only way to learn that a `SeatId`
/// IS seat0 is [`SeatId::as_seat0`], which hands back a witness. A caller
/// holding a `SeatId` for `seat-lab` can never name the argument a VT binding
/// requires.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SeatId(String);

/// Proof that a particular seat is `seat0`.
///
/// Not `Clone`, no public constructor, no fields. Its only job is to exist in
/// a signature. Shape borrowed from breathe's `LiveWitness` — a witness over a
/// private payload, because a `pub` field would let a caller fabricate one.
#[derive(Debug)]
pub struct Seat0Witness(());

impl SeatId {
    /// The parse boundary. logind's seat names are `seat0` or `seat-<slug>`.
    ///
    /// # Errors
    /// [`IdError::Malformed`] when the name is neither shape.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        let ok = s == "seat0"
            || (s.starts_with("seat-")
                && s.len() > 5
                && s[5..]
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(IdError::Malformed {
                what: "seat id",
                got: s.to_owned(),
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The SOLE producer of a [`Seat0Witness`].
    ///
    /// Returns `None` for every other seat, which is what turns "this seat has
    /// no VTs" from a runtime check into an absent argument.
    #[must_use]
    pub fn as_seat0(&self) -> Option<Seat0Witness> {
        (self.0 == "seat0").then_some(Seat0Witness(()))
    }
}

/// A principal's login name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UserName(String);

impl UserName {
    /// # Errors
    /// [`IdError::Malformed`] on an empty name, a leading `-`, or a name
    /// containing `:`, NUL or a path separator — the four shapes that break
    /// NSS, `/etc/passwd` parsing, or argument handling downstream.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        let bad = s.is_empty()
            || s.starts_with('-')
            || s.contains(':')
            || s.contains('\0')
            || s.contains('/');
        if bad {
            return Err(IdError::Malformed {
                what: "user name",
                got: s.to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A PAM service name — the file under `/etc/pam.d`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceName(String);

impl ServiceName {
    /// # Errors
    /// [`IdError::Malformed`] when the name is empty or contains a path
    /// separator — a PAM service name is a bare filename, and a `/` in it is
    /// a path traversal into an arbitrary config.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.is_empty() || s.contains('/') || s.contains('\0') {
            return Err(IdError::Malformed {
                what: "pam service name",
                got: s.to_owned(),
            });
        }
        Ok(Self(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An opaque handle to a PAM transaction held by the environment.
///
/// The spec crate never owns a `pam_handle_t`; it owns this. That is what
/// keeps `mukae-spec` free of `pam-sys` (illegal state [14]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PamHandleId(pub u64);

/// A credential id for a FIDO2 authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialId(pub Vec<u8>);

/// A smartcard slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotId(pub u8);

/// Evidence that an autologin runfile was consumed — the exactly-once token.
///
/// Not `Clone`, no public constructor, so an autologin cannot be replayed by
/// a caller holding a copy. Only the environment mints it, at the moment it
/// removes the file.
#[derive(Debug)]
pub struct RunFileConsumed(());

impl RunFileConsumed {
    /// Mint the token. `pub(crate)` on purpose: this is the environment's
    /// privilege, not a caller's.
    pub(crate) fn mint() -> Self {
        Self(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("malformed {what}: {got:?}")]
    Malformed { what: &'static str, got: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seat_names_parse_at_the_boundary() {
        assert!(SeatId::parse("seat0").is_ok());
        assert!(SeatId::parse("seat-lab").is_ok());
        assert!(SeatId::parse("seat-lab-2").is_ok());
        for bad in ["", "seat", "seat-", "Seat0", "seat0 ", "../seat0"] {
            assert!(SeatId::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    /// ★ THE WITNESS IS THE SEAL ON WORLD-FACT W8. Only seat0 yields one, so a
    /// VT binding on `seat-lab` has no way to name its argument.
    #[test]
    fn only_seat0_yields_a_witness() {
        assert!(SeatId::parse("seat0").unwrap().as_seat0().is_some());
        assert!(SeatId::parse("seat-lab").unwrap().as_seat0().is_none());
    }

    #[test]
    fn user_names_reject_the_four_shapes_that_break_downstream() {
        assert!(UserName::parse("drzzln").is_ok());
        for bad in ["", "-rf", "a:b", "a/b", "a\0b"] {
            assert!(UserName::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    /// A PAM service name is a bare filename. `../../etc/shadow` reaching
    /// `pam_start` is a config-file traversal, so it dies at the parse
    /// boundary rather than in a review.
    #[test]
    fn pam_service_names_cannot_traverse() {
        assert!(ServiceName::parse("mukae").is_ok());
        assert!(ServiceName::parse("../../etc/shadow").is_err());
        assert!(ServiceName::parse("").is_err());
    }
}
