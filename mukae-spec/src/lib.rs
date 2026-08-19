//! # mukae-spec — the typed login border
//!
//! mukae (迎え) is the pleme-io-native login manager. This crate is its
//! **border**: the types that make a wrong login unrepresentable, and the seam
//! that makes a whole login testable with no machine.
//!
//! It links no PAM, opens no device, draws no pixel and names no `libc`.
//!
//! ## What is actually here (M0), stated plainly
//!
//! | | |
//! |---|---|
//! | the capability chain | `AuthProof` → `SeatCapability<Authenticated>` → `start_session` |
//! | the seat typestate | `Authenticated` / `Denied`, sealed |
//! | the conversation | a PULL loop, the sole producer of a proof |
//! | the seam | [`env::SeatEnv`] — PAM, process, identity, clock |
//! | the mock | [`mock::MockSeatEnv`] — scripted, ordering-recording, fault-injecting |
//!
//! **NOT here, and deliberately not stubbed:** the seat/device/VT half of
//! `SeatEnv` (M4), the PAM linkage (M3), any face (M5/M6), the handoff (M7).
//! `theory/MUKAE.md` §7 is the phase list; a `todo!()` behind a signature that
//! reads as implemented would be worse than the absence, because only the
//! absence is a compile error at the call site.
//!
//! ## The five compile-time seals
//!
//! Each has a committed `trybuild` case under `tests/ui/`, so the claim is a
//! recorded compiler diagnostic rather than a sentence in a doc comment:
//!
//! 1. **Start a session that was never authenticated** — `start_session` names
//!    `SeatCapability<Authenticated>`; a caller with no proof cannot name the
//!    argument.
//! 2. **Reuse one authentication for two sessions** — everything is consumed
//!    by value and nothing is `Clone`.
//! 3. **A denial upgraded to success by a later call** — no
//!    `Denied → Authenticated` transition exists anywhere. This is the classic
//!    greeter retry-loop bug, and it is not guarded against; it is not
//!    expressible.
//! 4. **A third auth state invented downstream** — `SeatState` is sealed.
//! 5. **A syscall in spec code** — `libc` is not a dependency, so naming it
//!    does not resolve.
//!
//! ## What is NOT a type, and why saying so matters
//!
//! Two of `MUKAE.md`'s sixteen illegal states are *only mitigated*, and the
//! reason is the same in both: they are facts about the world, not about our
//! abstractions. Missing a libseat disable-ack deadline is a deadline; a
//! greeter that painted nothing is a claim about photons. Neither becomes a
//! type by trying harder, and grading them as sealed would be the round-up
//! this crate exists to avoid.

#![forbid(unsafe_code)]

pub mod bridge;
pub mod capability;
pub mod conversation;
pub mod coverage;
pub mod env;
pub mod ids;
pub mod mock;
pub mod session;
pub mod surface;

pub use capability::{AuthMethod, AuthProof, Authenticated, Denied, SeatCapability, SeatState};
pub use conversation::{Ask, Conversation, Face, Outcome, capability_from};
pub use coverage::{COVERAGE, Phase, live_actions, phase_of};
pub use env::{Answer, PamAnswer, PamStep, SeatEnv};
pub use ids::{PamHandleId, Seat0Witness, SeatId, ServiceName, Uid, UserName};
pub use session::{Argv, SessionHandle, SessionPlan, start_session};
pub use surface::{Drivable, Gap, Key, Verdict, diff};
