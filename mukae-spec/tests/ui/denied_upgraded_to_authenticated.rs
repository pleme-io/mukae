//! ILLEGAL STATE [3] — a failed attempt upgraded to success by a later call.
//!
//! This is the classic greeter retry-loop bug: a stale `authenticated = true`
//! survives a failed attempt. It is not defended against here. There is no
//! method anywhere that takes a `SeatCapability<Denied>` and returns a
//! `SeatCapability<Authenticated>` — read `capability.rs`'s
//! `impl SeatCapability<Denied>` block and note what is absent.
use mukae_spec::capability::{Denied, SeatCapability};
use mukae_spec::ids::{PamHandleId, SeatId};

fn main() {
    let seat = SeatId::parse("seat0").unwrap();
    let denied = SeatCapability::<Denied>::denied_for(seat, PamHandleId(1));
    // None of these exist. Any of them would be the bug.
    let _ = denied.into_authenticated();
}
