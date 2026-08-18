//! M0's done-predicate (a): a whole login, driven to a `SessionHandle`, with
//! no PAM, no root and no machine.
//!
//! These are the assertions a real login cannot easily be asked to make. On a
//! real machine you find out that `pam_setcred` ran after the privilege drop
//! when someone's kerberos tickets are missing a week later; here it is a
//! vector comparison.

use mukae_spec::capability::Passphrase;
use mukae_spec::conversation::{Ask, Conversation, Face, Outcome, capability_from};
use mukae_spec::env::{
    Answer, CredFlag, EnvSet, MsgStyle, PamAnswer, PamClass, PamError, PublicProfile, SeatEnv,
};
use mukae_spec::ids::{SeatId, ServiceName, Uid, UserName};
use mukae_spec::mock::{Call, MockSeatEnv, Script};
use mukae_spec::session::{Argv, SessionPlan, start_session};
use std::ffi::OsString;

/// A face that answers whatever it is asked and remembers what it saw.
#[derive(Default)]
struct ScriptedFace {
    seen: Vec<Ask>,
    answer: String,
    /// Walk away instead of answering.
    abandon: bool,
}

impl Face for ScriptedFace {
    fn respond(&mut self, ask: &Ask) -> Option<PamAnswer> {
        self.seen.push(ask.clone());
        if self.abandon {
            return None;
        }
        match ask {
            Ask::Secret(_) => Some(PamAnswer::Secret(Passphrase::new(self.answer.clone()))),
            Ask::Visible(_) => Some(PamAnswer::Visible(self.answer.clone())),
            // A `Tell` wants no answer, and returning one here would be a
            // protocol error the mock rejects.
            Ask::Tell(_) => None,
        }
    }
}

fn seat() -> SeatId {
    SeatId::parse("seat0").unwrap()
}

fn svc() -> ServiceName {
    ServiceName::parse("mukae").unwrap()
}

fn plan() -> SessionPlan {
    SessionPlan {
        argv: Argv::new(vec![
            OsString::from("/run/current-system/sw/bin/omoya"),
            OsString::from("--mode"),
            OsString::from("session"),
        ])
        .unwrap(),
        env: EnvSet(std::collections::BTreeMap::from([(
            "MUKAE_SEAT".to_string(),
            "seat0".to_string(),
        )])),
    }
}

/// ★ M0's DONE-PREDICATE (a). A scripted three-step conversation — secret,
/// then info, then complete — drives the mock all the way to a
/// `SessionHandle`.
#[test]
fn a_three_step_conversation_reaches_a_session() {
    let mut env = MockSeatEnv::new(Script::secret_then_info_then_complete(Uid(1000)));
    let mut face = ScriptedFace {
        answer: "hunter2".into(),
        ..Default::default()
    };

    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), Some(&UserName::parse("drzzln").unwrap()), 16)
            .unwrap()
    };

    assert!(matches!(outcome, Outcome::Authenticated { .. }));

    // The face was asked for a secret AND told something. A greeter that only
    // handles the first swallows "your password expires in 3 days".
    assert!(matches!(face.seen[0], Ask::Secret(_)));
    assert!(matches!(face.seen[1], Ask::Tell(_)));

    let cap = capability_from(outcome, seat(), mukae_spec::ids::PamHandleId(1)).unwrap();
    let handle = start_session(&mut env, cap, plan()).unwrap();

    assert_eq!(handle.uid, Uid(1000));
    assert_eq!(handle.seat.as_str(), "seat0");
    assert_eq!(env.forked().len(), 1, "exactly one session was started");
}

/// ★ THE PAM ORDERING, ASSERTED. This is the half of a login where the real
/// bugs live, and every step below is here because doing it in another order
/// breaks something SILENTLY.
///
/// `setcred(Establish)` must come before the session opens — it is what
/// acquires the kerberos ticket, and after the privilege drop there is nothing
/// left to acquire it with. `getenvlist` must come after `open_session`, or it
/// reads the environment before the session modules have contributed to it.
#[test]
fn the_pam_call_order_is_the_one_that_does_not_break_kerberos() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let mut face = ScriptedFace {
        answer: "x".into(),
        ..Default::default()
    };
    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), None, 16).unwrap()
    };
    let cap = capability_from(outcome, seat(), mukae_spec::ids::PamHandleId(1)).unwrap();
    start_session(&mut env, cap, plan()).unwrap();

    let idx = |c: &Call| env.calls.iter().position(|x| x == c).unwrap();

    let setcred = idx(&Call::SetCred(CredFlag::Establish));
    let putenv = idx(&Call::PutEnv("MUKAE_SEAT".into()));
    let open = idx(&Call::OpenSession);
    let getenv = idx(&Call::GetEnvList);
    let fork = idx(&Call::Fork);

    assert!(
        setcred < open,
        "setcred(Establish) must precede open_session, or kerberos tickets are \
         acquired after the privilege that acquires them is gone"
    );
    assert!(
        putenv < open,
        "putenv must precede open_session, or the session modules read an \
         environment that does not yet have our variables in it"
    );
    assert!(
        open < getenv,
        "getenvlist must FOLLOW open_session, or it reads the environment \
         before the session modules contributed to it"
    );
    assert!(
        getenv < fork,
        "the child must inherit the final environment"
    );
}

/// The session inherits what the session modules contributed — which is only
/// true because of the ordering asserted above.
#[test]
fn the_child_inherits_the_session_modules_contribution() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let mut face = ScriptedFace {
        answer: "x".into(),
        ..Default::default()
    };
    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), None, 16).unwrap()
    };
    let cap = capability_from(outcome, seat(), mukae_spec::ids::PamHandleId(1)).unwrap();
    let handle = start_session(&mut env, cap, plan()).unwrap();

    assert_eq!(
        handle.env.0.get("XDG_SESSION_TYPE").map(String::as_str),
        Some("tty"),
        "the session module's variable must reach the child"
    );
    assert_eq!(
        handle.env.0.get("MUKAE_SEAT").map(String::as_str),
        Some("seat0"),
        "and so must ours"
    );
}

/// ★ A DENIAL YIELDS NO CAPABILITY. The compile-fail suite proves there is no
/// `Denied -> Authenticated` method; this proves the runtime path agrees —
/// `capability_from` returns `None`, so there is nothing to pass on.
#[test]
fn a_denial_produces_no_capability() {
    let mut env = MockSeatEnv::new(Script::denied(PamClass::AuthError));
    let mut face = ScriptedFace {
        answer: "wrong".into(),
        ..Default::default()
    };
    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), None, 16).unwrap()
    };
    assert!(matches!(
        outcome,
        Outcome::Denied {
            class: PamClass::AuthError,
            ..
        }
    ));
    assert!(
        capability_from(outcome, seat(), mukae_spec::ids::PamHandleId(1)).is_none(),
        "a denial must not yield a capability"
    );
    assert!(env.forked().is_empty(), "and nothing may have been started");
}

/// ★ WALKING AWAY IS NOT A FAILED ATTEMPT. Collapsing the two is how a greeter
/// locks an account because someone pressed escape three times.
#[test]
fn abandoning_is_distinct_from_being_denied() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let mut face = ScriptedFace {
        abandon: true,
        ..Default::default()
    };
    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), None, 16).unwrap()
    };
    assert!(matches!(outcome, Outcome::Abandoned));
    // And it closed the transaction rather than leaking it.
    assert!(env.calls.contains(&Call::End));
}

/// ★ AN EXPIRED PASSWORD IS A SUCCESSFUL AUTHENTICATION. Treating
/// `NewAuthTokRequired` as a failure locks a user out on the exact day they
/// most need to log in — the day their password expires.
#[test]
fn an_expired_password_is_a_token_change_not_a_denial() {
    let mut script = Script::password_ok(Uid(1000));
    script.acct = Some(mukae_spec::env::AcctVerdict::NewAuthTokRequired);
    let mut env = MockSeatEnv::new(script);
    let mut face = ScriptedFace {
        answer: "x".into(),
        ..Default::default()
    };
    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), None, 16).unwrap()
    };
    assert!(
        matches!(outcome, Outcome::TokenChangeRequired { .. }),
        "expired must not be a denial"
    );
    // No capability, because a session may not start until the token changes —
    // but the user is NOT told their password was wrong.
    assert!(capability_from(outcome, seat(), mukae_spec::ids::PamHandleId(1)).is_none());
}

/// ★ THE ENVIRONMENT REFUSES TO MINT A PROOF FROM AN UNFINISHED
/// CONVERSATION. The type system stops a caller minting a capability without a
/// proof; this is the other half — the environment will not hand out the proof
/// itself. Both are needed: one is about who may call, the other about what is
/// true when they do.
#[test]
fn a_proof_cannot_be_minted_before_the_conversation_completes() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let h = env.pam_start(&svc(), None).unwrap();
    // Deliberately skip the conversation entirely.
    let err = env.mint_proof(h, Uid(1000)).unwrap_err();
    assert!(
        matches!(err, PamError::OutOfOrder(m) if m.contains("unfinished")),
        "got {err:?}"
    );
}

/// ★ A BOUNDED LOOP. A greeter that hangs is an unusable machine, and plo has
/// no console fallback. A script that never completes must degrade into a
/// typed failure rather than spin.
#[test]
fn a_conversation_that_never_completes_is_bounded() {
    let mut script = Script::default();
    // 100 prompts, no Complete. A real one of these is a misconfigured PAM
    // stack, and it must not hang the only way into the machine.
    script.steps = (0..100)
        .map(|_| mukae_spec::env::PamStep::Prompt {
            style: MsgStyle::PromptEchoOff,
            msg: mukae_spec::env::PromptText("again: ".into()),
        })
        .collect();
    let mut env = MockSeatEnv::new(script);
    let mut face = ScriptedFace {
        answer: "x".into(),
        ..Default::default()
    };
    let mut c = Conversation::new(&mut env, &mut face, seat());
    let err = c.run(&svc(), None, 8).unwrap_err();
    assert!(matches!(err, PamError::OutOfOrder(m) if m.contains("max_steps")));
}

/// ★ BLIND IS NOT EMPTY. "NSS timed out" and "there is no such user" are
/// different facts, and every existing greeter renders both as a blank list.
#[test]
fn an_unreachable_directory_is_blind_not_empty() {
    let env = MockSeatEnv::new(Script::password_ok(Uid(1000))).enumerating(Answer::Blind {
        because: "nss timeout after 5s".into(),
    });
    let a = env.enumerate_principals();
    assert!(!a.is_finding(), "a timeout must not read as a finding");
    assert!(matches!(a, Answer::Blind { .. }));

    let empty = MockSeatEnv::new(Script::password_ok(Uid(1000))).enumerate_principals();
    assert!(empty.is_finding(), "an empty directory IS a finding");
}

#[test]
fn a_known_principal_resolves_and_an_unknown_one_is_empty() {
    let me = UserName::parse("drzzln").unwrap();
    let env =
        MockSeatEnv::new(Script::password_ok(Uid(1000))).with_principals(vec![PublicProfile {
            uid: Uid(1000),
            name: me.clone(),
            display_name: Some("drzzln".into()),
        }]);
    assert!(matches!(env.resolve_principal(&me), Answer::Found(_)));
    assert!(matches!(
        env.resolve_principal(&UserName::parse("nobody").unwrap()),
        Answer::Empty { .. }
    ));
}

/// A failure at fork does not leave a half-started session claiming success.
#[test]
fn an_injected_fork_failure_surfaces_rather_than_returning_a_handle() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000))).failing_on(Call::Fork);
    let mut face = ScriptedFace {
        answer: "x".into(),
        ..Default::default()
    };
    let outcome = {
        let mut c = Conversation::new(&mut env, &mut face, seat());
        c.run(&svc(), None, 16).unwrap()
    };
    let cap = capability_from(outcome, seat(), mukae_spec::ids::PamHandleId(1)).unwrap();
    assert!(start_session(&mut env, cap, plan()).is_err());
}

/// Closing the session is what removes `/run/user/<uid>` on a real machine.
/// M3 asserts that with `ls`; here it is the mock's own bookkeeping, so the
/// call is at least proven to happen.
#[test]
fn closing_a_session_actually_closes_it() {
    let mut env = MockSeatEnv::new(Script::password_ok(Uid(1000)));
    let h = env.pam_start(&svc(), None).unwrap();
    env.pam_open_session(h).unwrap();
    assert!(env.session_open(h));
    env.pam_close_session(h).unwrap();
    assert!(!env.session_open(h), "pam_close_session must have run");
}
