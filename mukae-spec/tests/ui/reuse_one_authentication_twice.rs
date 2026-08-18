//! ILLEGAL STATE [2] — reuse one authentication for two sessions.
//!
//! `start_session` consumes the capability BY VALUE and `SeatCapability` is
//! neither `Clone` nor `Copy`. One authentication yields exactly one session.
//! Note this is strictly stronger than taking it by reference, which is what
//! the analogous fleet primitive (escuta's lock) does — there, many writes
//! under one proof is correct; here it is the bug.
//!
//! ★ THE CAPABILITY IS OBTAINED FOR REAL, and that matters. The first draft of
//! this case wrote `let proof: AuthProof = unimplemented!();` — which makes
//! every following statement unreachable, so rustc never runs the move
//! analysis and the case COMPILED. A compile-fail test that passes for the
//! wrong reason proves nothing; the code below is live.
use mukae_spec::conversation::{Ask, Conversation, Face, capability_from};
use mukae_spec::env::{EnvSet, PamAnswer};
use mukae_spec::ids::{PamHandleId, SeatId, Uid};
use mukae_spec::mock::{MockSeatEnv, Script};
use mukae_spec::session::{Argv, SessionPlan, start_session};
use std::ffi::OsString;

struct Yes;
impl Face for Yes {
    fn respond(&mut self, ask: &Ask) -> Option<PamAnswer> {
        match ask {
            Ask::Secret(_) => Some(PamAnswer::Secret(
                mukae_spec::capability::Passphrase::new("x".into()),
            )),
            Ask::Visible(_) => Some(PamAnswer::Visible("x".into())),
            Ask::Tell(_) => None,
        }
    }
}

fn main() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let seat = SeatId::parse("seat0").unwrap();
    let mut face = Yes;

    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat.clone());
        c.run(
            &mukae_spec::ids::ServiceName::parse("mukae").unwrap(),
            None,
            16,
        )
        .unwrap()
    };
    let cap = capability_from(outcome, seat, PamHandleId(1)).unwrap();

    let plan = || SessionPlan {
        argv: Argv::new(vec![OsString::from("/bin/sh")]).unwrap(),
        env: EnvSet::default(),
    };
    let _first = start_session(&mut env, cap, plan());
    // The capability was consumed above. There is no second one.
    let _second = start_session(&mut env, cap, plan());
}
