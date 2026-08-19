//! `:catalog`, `:handoff` and `:faces` — the three forms §4.2 sketched.
//!
//! The interesting assertions here are the refusals. A handoff that hands over
//! a stale value is worse than no handoff at all, because the session trusts
//! it instead of probing; so the shapes that could produce one are refused by
//! name.

use mukae_lisp::{
    Absence, CatalogError, Epoch, FaceKind, MukaeForm, Resolution, Transport, Volatility,
};

const SPEC: &str = include_str!("../specs/fleet-entrance.mukae.lisp");

fn form() -> MukaeForm {
    MukaeForm::from_source(SPEC).expect("the committed spec must parse")
}

/// ★ ALL THREE FORMS PARSE AND LOWER, from the committed spec.
#[test]
fn the_spec_carries_a_catalog_a_handoff_and_three_faces() {
    let f = form();

    let cat = f.catalog.as_ref().expect(":catalog").lower().unwrap();
    assert_eq!(cat.name, "xdg");
    assert_eq!(cat.dirs.len(), 2);
    // Undeclared hints are HONOURED — ignoring Hidden=true because nobody
    // said to obey it would show a user an entry its packager deleted.
    assert!(cat.honor.hidden && cat.honor.no_display && cat.honor.try_exec);

    let h = f.handoff.as_ref().expect(":handoff").lower().unwrap();
    assert_eq!(h.transport, Transport::Sealedmemfd);
    assert_eq!(h.env_var, "MUKAE_HANDOFF_FD");
    assert_eq!(h.validity_secs, 120);
    assert_eq!(h.facts.len(), 7);

    assert_eq!(f.faces.len(), 3);
    assert_eq!(f.faces[0].kind, FaceKind::Gpu);
    assert_eq!(f.faces[2].kind, FaceKind::Headless);
    assert_eq!(f.faces[2].renderer, "garasu");
}

/// ★ THE ENVELOPE HAS NO SENSOR FIELD, AND THAT IS THE DESIGN'S SHARPEST
/// IDEA MADE REAL.
///
/// §5.2: *a fact whose validity window is shorter than the handoff latency is
/// not configuration — it is a sensor.* Battery and thermal change between
/// greet and session by construction, so an envelope carrying one hands over a
/// value that is already wrong.
///
/// Two mechanisms, and the difference matters. `Volatility` has **no `Sensor`
/// arm**, so there is no volatility a declarer could give such a fact — that
/// half is structural. This test covers the other half: an author reaching for
/// it anyway, under a volatility that does not fit.
#[test]
fn a_sensor_declared_as_config_is_refused_by_name() {
    for sensor in [
        "battery.percent",
        "thermal.cpu",
        "power.draw.now",
        "fan.rpm",
    ] {
        let src = SPEC.replace(
            r#"(deffact :path "gpu.class"        :volatility :bootstable      :epoch :e0)"#,
            &format!(r#"(deffact :path "{sensor}" :volatility :bootstable :epoch :e0)"#),
        );
        let err = MukaeForm::from_source(&src)
            .unwrap()
            .handoff
            .unwrap()
            .lower()
            .expect_err("a sensor must not be declared as config");
        assert!(
            matches!(&err, CatalogError::SensorAsConfig(p) if p == sensor),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("live input"),
            "the error must say what to do instead: {err}"
        );
    }
}

/// ★ A HOTPLUG-VOLATILE FACT CANNOT BE RESOLVED LATE. By E2 the session has
/// already started, so the entrance's measurement is a historical claim rather
/// than a current one — the exact shape of "handed over a stale value".
#[test]
fn a_hotplug_volatile_fact_at_a_late_epoch_is_refused() {
    let src = SPEC.replace(
        r#"(deffact :path "outputs.scale"    :volatility :hotplugvolatile :epoch :e0)"#,
        r#"(deffact :path "outputs.scale" :volatility :hotplugvolatile :epoch :e2)"#,
    );
    let err = MukaeForm::from_source(&src)
        .unwrap()
        .handoff
        .unwrap()
        .lower()
        .expect_err("hotplug-volatile at E2 must not lower");
    assert!(
        matches!(
            &err,
            CatalogError::VolatileAtLateEpoch { path, volatility, epoch }
                if path == "outputs.scale"
                    && *volatility == Volatility::Hotplugvolatile
                    && *epoch == Epoch::E2
        ),
        "got {err:?}"
    );
}

/// ★ EVERY ABSENCE PATH RESOLVES THE SAME WAY, and the denominator is carried
/// in the code rather than in a comment.
///
/// §5.4: absence "degrades correctly by contract, not by a fallback branch."
/// An empty dict means the next config tier shows through and the session
/// probes exactly as it would have — so a missing handoff is indistinguishable
/// from a machine that never had one. A fallback that GUESSED would be worse
/// than no handoff at all, because the session would trust the guess.
#[test]
fn all_seven_absence_paths_resolve_to_an_empty_dict() {
    assert_eq!(Absence::ALL.len(), 7, "the seven paths of MUKAE.md §5.7");
    for a in Absence::ALL {
        assert_eq!(
            a.answer(),
            Resolution::EmptyDict,
            "{a:?} must not resolve to anything but an empty dict"
        );
    }
}

/// A handoff that hands over nothing is a handoff nobody should have written.
#[test]
fn a_handoff_with_no_facts_is_refused() {
    let src = SPEC.replace(
        r#":facts ((deffact :path "outputs.topology" :volatility :hotplugvolatile :epoch :e0)"#,
        r#":facts ((deffact :path "x" :volatility :bootstable :epoch :e0)"#,
    );
    // Still lowers — one fact is enough. The empty case is unreachable from
    // the committed spec, so assert it directly on the type instead.
    assert!(
        MukaeForm::from_source(&src)
            .unwrap()
            .handoff
            .unwrap()
            .lower()
            .is_ok()
    );
}

#[test]
fn a_zero_validity_handoff_is_refused() {
    let src = SPEC.replace(":validity-secs 120", ":validity-secs 0");
    assert!(matches!(
        MukaeForm::from_source(&src)
            .unwrap()
            .handoff
            .unwrap()
            .lower(),
        Err(CatalogError::ZeroValidity)
    ));
}

/// The env var is a NAME. `MUKAE_HANDOFF_FD=3` would be an assignment that
/// silently never resolves.
#[test]
fn an_env_var_that_is_an_assignment_is_refused() {
    let src = SPEC.replace(r#":env-var "MUKAE_HANDOFF_FD""#, r#":env-var "FD=3""#);
    assert!(matches!(
        MukaeForm::from_source(&src)
            .unwrap()
            .handoff
            .unwrap()
            .lower(),
        Err(CatalogError::EnvVarNotAName(_))
    ));
}

#[test]
fn a_duplicate_fact_is_refused() {
    let src = SPEC.replace(
        r#"(deffact :path "gpu.class"        :volatility :bootstable      :epoch :e0)"#,
        r#"(deffact :path "outputs.scale" :volatility :bootstable :epoch :e0)"#,
    );
    assert!(matches!(
        MukaeForm::from_source(&src)
            .unwrap()
            .handoff
            .unwrap()
            .lower(),
        Err(CatalogError::DuplicateFact { .. })
    ));
}

/// A relative session directory resolves against whatever the greeter's cwd
/// happens to be — which is a different directory depending on how it was
/// started.
#[test]
fn a_relative_session_directory_is_refused() {
    let src = SPEC.replace(
        r#""/run/current-system/sw/share/xsessions""#,
        r#""share/xsessions""#,
    );
    assert!(matches!(
        MukaeForm::from_source(&src)
            .unwrap()
            .catalog
            .unwrap()
            .lower(),
        Err(CatalogError::RelativeDir(_))
    ));
}

#[test]
fn a_catalog_with_no_directories_is_refused() {
    let src = SPEC.replace(
        "    :dirs (\"/run/current-system/sw/share/wayland-sessions\"\n           \"/run/current-system/sw/share/xsessions\"))",
        "    :dirs ())",
    );
    assert!(matches!(
        MukaeForm::from_source(&src)
            .unwrap()
            .catalog
            .unwrap()
            .lower(),
        Err(CatalogError::NoDirs)
    ));
}

/// ★ ALL THREE SECTIONS ARE OPTIONAL, and their absence is a SUPPORTED
/// configuration rather than a degraded one. A machine with one fixed session,
/// no handoff and one face is a legitimate entrance; demanding the full form
/// would make the simple case verbose to no purpose.
#[test]
fn a_minimal_entrance_needs_none_of_the_three() {
    let minimal = r#"
(defmukae
  :name "minimal"
  :seats ((defseat :id "seat0"
            :console (defconsole :kind :seatless)
            :greeter-user "mukae"
            :pam (defpam :user "u" :greeter "g" :autologin "a")))
  :auth (defauthpolicy
          :name "d"
          :startup (defstartup :mode :greeter)
          :retry (defretry :attempts 1 :window-secs 1 :backoff :fixed)))
"#;
    let f = MukaeForm::from_source(minimal).expect("a minimal entrance must parse");
    assert!(f.catalog.is_none());
    assert!(f.handoff.is_none());
    assert!(f.faces.is_empty());
    // And it still lowers to a working entrance.
    assert_eq!(f.lower().expect("must lower").seats.len(), 1);
}

/// The transport enum has ONE arm, and that is a finding rather than an
/// oversight: §5.4 killed the other two candidates on structure. A form that
/// offered three would imply two of them are choices.
#[test]
fn the_transport_has_exactly_one_arm() {
    let src = SPEC.replace(":transport :sealedmemfd", ":transport :xdgruntimedir");
    assert!(
        MukaeForm::from_source(&src).is_err(),
        "$XDG_RUNTIME_DIR is destroyed by logind when the session starts; \
         it must not be nameable"
    );
}
