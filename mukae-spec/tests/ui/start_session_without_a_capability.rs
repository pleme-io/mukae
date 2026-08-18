//! ILLEGAL STATE [1] — start a session that was never authenticated.
//!
//! `start_session` names `SeatCapability<Authenticated>` as a parameter type.
//! The only constructor is `mint(AuthProof, …)`; `AuthProof` has no public
//! constructor and its payload is a private enum. So a caller with no proof
//! cannot NAME the argument — this is not a check that fails, it is an
//! expression that does not exist.
use mukae_spec::env::EnvSet;
use mukae_spec::ids::Uid;
use mukae_spec::mock::{MockSeatEnv, Script};
use mukae_spec::session::{Argv, SessionPlan, start_session};
use std::ffi::OsString;

fn main() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let plan = SessionPlan {
        argv: Argv::new(vec![OsString::from("/bin/sh")]).unwrap(),
        env: EnvSet::default(),
    };
    // No capability. There is nothing to pass.
    start_session(&mut env, plan);
}
