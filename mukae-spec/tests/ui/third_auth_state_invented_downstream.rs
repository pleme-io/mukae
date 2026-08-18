//! ILLEGAL STATE [4] — a downstream crate inventing a third auth state.
//!
//! `SeatState: sealed::Sealed` and `sealed` is a private module, so a
//! downstream crate cannot satisfy the bound. Without this, nothing stops a
//! consumer adding `Probably` or `Cached` and writing a `start_session`
//! overload for it.
use mukae_spec::capability::SeatState;

struct Probably;
impl SeatState for Probably {}

fn main() {}
