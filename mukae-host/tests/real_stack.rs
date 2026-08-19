//! The one thing unit tests cannot prove: that **libpam calls our callback**.
//!
//! ── ★ WHAT WAS STILL UNPROVEN, AND WHY IT MATTERED ────────────────────────
//! `bridging_conv` has a thorough unit suite, and every one of those tests
//! invokes it DIRECTLY. That proves the function is sound for the shapes we
//! hand it; it proves nothing about whether libpam ever hands it those shapes,
//! or whether it agrees with us about `pam_conv`'s layout, the `appdata_ptr`
//! round-trip, or Linux-PAM's array-of-pointers `msg` convention.
//!
//! `authenticate`'s unit test uses a service nobody configured, so it fails
//! inside `pam_start`/`pam_authenticate` before a conversation ever begins.
//!
//! So the entire FFI contract — the part where a mistake is a segfault inside
//! a login screen rather than a red test — rested on reading a header
//! correctly. This closes it: a real stack, a real prompt crossing a real
//! rendezvous channel, a real answer marshalled back through `malloc`.
//!
//! ── ★ WHY `#[ignore]` AND NOT AN ENV-VAR SKIP ─────────────────────────────
//! There is no `/etc/pam.d` inside a nix build sandbox, and a test that
//! silently returns when its precondition is missing is a **vacuous green** —
//! it reports success for having done nothing, which is worse than not
//! existing because it occupies the space where a real check would go.
//!
//! `#[ignore]` makes the non-run VISIBLE: cargo prints `ignored`, never
//! `ok`. Run it where a stack exists:
//!
//! ```text
//! cargo test -p mukae-host --test real_stack -- --ignored --nocapture
//! ```

use mukae_host::authenticate::authenticate;
use mukae_spec::capability::Passphrase;
use mukae_spec::env::{MsgStyle, PamAnswer, PamClass, PamStep};
use mukae_spec::ids::{ServiceName, UserName};

/// A username no account can hold. Deliberately not a plausible one: the point
/// is to exercise the CONVERSATION, and a real account would make the test
/// depend on a credential.
const NOBODY: &str = "mukae-test-account-that-cannot-exist";

#[test]
#[ignore = "needs a real PAM stack (/etc/pam.d/login); run with --ignored"]
fn libpam_actually_calls_our_conversation_and_takes_the_answer() {
    let svc = ServiceName::parse("login").expect("`login` is a bare name");
    let user = UserName::parse(NOBODY).expect("a plain username parses");

    let mut face = authenticate(&svc, Some(&user)).expect("pam_start on `login` should succeed");

    // ★ THE ASSERTION THIS FILE EXISTS FOR.
    //
    // Receiving a prompt means: libpam invoked `bridging_conv` on its own
    // stack, our reading of `pam_conv`'s layout was right, the `appdata_ptr`
    // survived the round trip as a live `&ConvSide`, we walked Linux-PAM's
    // array-of-pointers `msg` correctly, and the message crossed the
    // rendezvous channel to this thread. None of that is provable by calling
    // the callback ourselves.
    let step = face.next();
    let PamStep::Prompt { style, msg } = step else {
        panic!("expected a prompt from the `login` stack, got {step:?}");
    };

    // pam_unix prompts for a password even for an account that does not
    // exist — deliberately, so that the *presence* of a prompt is not a
    // username oracle. That property is what lets this test run without a
    // real account, and it is the same property mukae's own surfaces keep.
    assert_eq!(
        style,
        MsgStyle::PromptEchoOff,
        "a password prompt must be echo-off; got {style:?} for {msg:?}"
    );

    // A wrong answer, marshalled through `malloc_cstr` into memory libpam
    // will `free()`. If contract rule 1 were violated — a Rust allocation
    // handed to C — this is where the heap corruption would be planted.
    face.answer(PamAnswer::Secret(Passphrase::new(
        "not-the-password".to_string(),
    )))
    .expect("the worker is alive and blocked on this answer");

    // ── ★ THE CLASS IS THE ASSERTION, NOT MERELY `Failed` ─────────────────
    // This test previously asserted `Failed` and PASSED FOR THE WRONG REASON.
    // `bridging_conv` was refusing every `Secret` outright and returning
    // `PAM_CONV_ERR`, so PAM failed because we never answered — which is
    // indistinguishable from a wrong password if you only check that it
    // failed. The password had never once reached the stack.
    //
    // `AuthError` is PAM's verdict on an answer it EVALUATED. A conversation
    // failure surfaces as `Abort` instead, so asserting the class is what
    // separates "we delivered a wrong password" from "we delivered nothing".
    // Without this line the whole file is theatre.
    let verdict = face.next();
    match verdict {
        PamStep::Failed {
            class: PamClass::AuthError,
        } => {}
        PamStep::Failed {
            class: PamClass::Abort,
        } => panic!(
            "PAM aborted the conversation rather than judging the answer — \
             the passphrase did not reach the stack"
        ),
        other => panic!("expected AuthError from an evaluated wrong password; got {other:?}"),
    }
}
