//! The `(defmukae …)` surface, exercised against the committed spec file.
//!
//! Two kinds of assertion here, and the distinction matters:
//!
//! - **the form parses and lowers** — the ordinary path
//! - **the form CANNOT SAY certain things** — the interesting path. Each of
//!   these is an illegal state from `theory/MUKAE.md` §4.4 that a data
//!   language cannot express as a type, so it is enforced at the one boundary
//!   where the typed information exists: lowering.

use mukae_lisp::{
    Backoff, Console, ConsoleKind, LowerError, MukaeForm, RestartPolicy, StartupMode, SwitchPolicy,
};

/// The committed spec — the real one, not a fixture. If this file stops
/// parsing, the surface has drifted from what an operator would actually
/// write, which is the only drift that matters.
const SPEC: &str = include_str!("../specs/fleet-entrance.mukae.lisp");

fn spec() -> MukaeForm {
    MukaeForm::from_source(SPEC).expect("the committed spec must parse")
}

/// ★ THE WHOLE CONFIGURATION IS DATA, AND IT ROUND-TRIPS TO TYPES.
#[test]
fn the_committed_spec_parses_and_lowers() {
    let m = spec().lower().expect("must lower");
    assert_eq!(m.name, "fleet-entrance");
    assert_eq!(m.seats.len(), 2);
    assert_eq!(m.retry_attempts, 5);
    assert_eq!(m.retry_window_secs, 60);
    assert_eq!(m.backoff, Backoff::Exponential);

    let seat0 = &m.seats[0];
    assert_eq!(seat0.id.as_str(), "seat0");
    assert_eq!(
        seat0.console,
        Console::Vt {
            number: 1,
            switch: SwitchPolicy::Required,
            conflicts: Some("getty@tty1.service".into()),
        }
    );
    assert_eq!(seat0.pam_greeter.as_str(), "mukae-greeter");

    // The second seat is seatless, necessarily.
    assert_eq!(m.seats[1].console, Console::Seatless);
}

/// ★ WORLD-FACT W8, ENFORCED WHERE THE WITNESS LIVES. Lisp cannot carry a
/// `Seat0Witness`, so a VT on a non-seat0 seat is caught at lowering — and the
/// error names the seat and says what to write instead.
#[test]
fn a_vt_console_on_a_non_seat0_seat_is_refused() {
    let src = SPEC.replace(
        "(defconsole :kind :seatless)",
        "(defconsole :kind :vt :number 2)",
    );
    let err = MukaeForm::from_source(&src)
        .expect("it still PARSES — this is a lowering fact, not a syntax one")
        .lower()
        .expect_err("a VT on seat-lab must not lower");
    assert!(
        matches!(&err, LowerError::VtOnNonSeat0 { seat } if seat == "seat-lab"),
        "got {err:?}"
    );
    assert!(
        err.to_string().contains("seatless"),
        "the error must say what to write instead: {err}"
    );
}

/// ★ THE greetd BOOLEAN-PAIR BUG HAS NO REPRESENTATION TO LOWER FROM.
/// greetd's own nix module couples `restart` and `initial_session` by hand;
/// here the autologin arm has no restart field, so the combination dies.
#[test]
fn autologin_with_a_restart_policy_is_refused() {
    let src = SPEC.replace(
        "(defstartup :mode :greeter :restart :always)",
        "(defstartup :mode :autologin :restart :always :user \"drzzln\")",
    );
    let err = MukaeForm::from_source(&src)
        .unwrap()
        .lower()
        .expect_err("autologin + restart must not lower");
    assert!(
        matches!(err, LowerError::AutologinWithRestart),
        "got {err:?}"
    );
}

#[test]
fn autologin_without_a_user_is_refused() {
    let src = SPEC.replace(
        "(defstartup :mode :greeter :restart :always)",
        "(defstartup :mode :autologin)",
    );
    assert!(matches!(
        MukaeForm::from_source(&src).unwrap().lower(),
        Err(LowerError::AutologinWithoutUser)
    ));
}

/// A greeter has no user to log in as. Accepting one would mean an operator
/// believed something false about what they had configured.
#[test]
fn a_greeter_with_a_user_is_refused() {
    let src = SPEC.replace(
        "(defstartup :mode :greeter :restart :always)",
        "(defstartup :mode :greeter :restart :always :user \"drzzln\")",
    );
    assert!(matches!(
        MukaeForm::from_source(&src).unwrap().lower(),
        Err(LowerError::GreeterWithUser)
    ));
}

/// A seatless console carrying a VT number is not harmless — it is an author
/// who thinks that seat has a VT, and silently ignoring the field would leave
/// them thinking so.
#[test]
fn a_seatless_console_with_vt_fields_is_refused() {
    let src = SPEC.replace(
        "(defconsole :kind :seatless)",
        "(defconsole :kind :seatless :number 3)",
    );
    assert!(matches!(
        MukaeForm::from_source(&src).unwrap().lower(),
        Err(LowerError::SeatlessWithVtFields { .. })
    ));
}

#[test]
fn a_vt_console_without_a_number_is_refused() {
    let src = SPEC.replace(
        ":kind :vt\n                          :number 1",
        ":kind :vt",
    );
    let form = MukaeForm::from_source(&src).unwrap();
    assert!(matches!(
        form.lower(),
        Err(LowerError::VtWithoutNumber { .. })
    ));
}

/// ★ THE SILENT-TYPO TRAP, RE-ASSERTED FOR THIS DOMAIN.
///
/// `MUKAE.md` §4.2 warns that a mistyped keyword yields an empty `Vec`
/// reported as SUCCESS, and calls a lint "not optional here". That warning
/// describes tatara-lisp's *manual* extraction path. On the DERIVE path the
/// emitted `__TATARA_ALLOWED_KEYWORDS` gate rejects it with a did-you-mean.
///
/// This is pinned per-domain rather than trusted from upstream because the
/// consequence here is specific and severe: this spec has 20+ optional
/// keywords, and a login configuration that parses green while missing half
/// its fields is a machine nobody can get into.
#[test]
fn a_typod_keyword_is_rejected_with_a_suggestion() {
    let err = MukaeForm::from_source(&SPEC.replace(":seats", ":seets"))
        .expect_err("a typo'd kwarg must not compile")
        .to_string();
    assert!(err.contains("seets"), "must name the bad key: {err}");
    assert!(err.contains("seats"), "must suggest the right key: {err}");
}

/// An unknown enum VALUE is rejected too — a different mechanism from the
/// kwarg gate, and worth its own case.
#[test]
fn an_unknown_enum_value_is_rejected() {
    assert!(
        MukaeForm::from_source(&SPEC.replace(":backoff :exponential", ":backoff :quadratic"))
            .is_err()
    );
}

/// ★ THE NAMING RULE THAT WILL BITE, PINNED. Values lowercase with NO
/// separator; field names go snake → kebab. Two opposite conventions in one
/// language, and §4.2's sketch got it wrong (`:sealed-memfd`,
/// `:physical-presence`). This test is what stops the design's spelling
/// creeping back in.
#[test]
fn enum_values_have_no_separator_but_field_names_do() {
    // The field IS kebab-cased: `window_secs` -> `:window-secs`.
    assert!(SPEC.contains(":window-secs"));
    assert!(spec().lower().is_ok());

    // A hyphenated VALUE does not parse, which is the half a designer gets
    // wrong. `:seatless` is one word on purpose.
    let src = SPEC.replace(":kind :seatless", ":kind :seat-less");
    assert!(
        MukaeForm::from_source(&src).is_err(),
        "a hyphenated enum value must not parse"
    );
}

#[test]
fn a_duplicate_seat_is_refused() {
    // Two seats with the same id is a config whose second half silently wins.
    let src = SPEC.replace("\"seat-lab\"", "\"seat0\"");
    assert!(matches!(
        MukaeForm::from_source(&src).unwrap().lower(),
        Err(LowerError::DuplicateSeat(_))
    ));
}

/// A malformed seat id dies at the border's parse boundary, not here — the
/// point being that lowering reuses `mukae-spec`'s newtypes rather than
/// re-validating with a second, drifting copy of the rules.
#[test]
fn a_malformed_id_is_refused_by_the_borders_own_parser() {
    let src = SPEC.replace("\"seat-lab\"", "\"../etc\"");
    assert!(matches!(
        MukaeForm::from_source(&src).unwrap().lower(),
        Err(LowerError::Id(_))
    ));
}

/// The form's own shape, so a field rename shows up here rather than in a
/// consumer.
#[test]
fn the_form_carries_what_the_spec_declares() {
    let f = spec();
    assert_eq!(f.name, "fleet-entrance");
    assert_eq!(f.seats.len(), 2);
    assert_eq!(f.seats[0].console.kind, ConsoleKind::Vt);
    assert_eq!(f.seats[1].console.kind, ConsoleKind::Seatless);
    assert_eq!(f.auth.startup.mode, StartupMode::Greeter);
    assert_eq!(f.auth.startup.restart, Some(RestartPolicy::Always));
}
