//! ★ A MEASUREMENT, kept because it corrects a natural misreading.
//!
//! The fleet's notes on tatara-lisp say "six closed atom kinds, **no map, no
//! vector**", and that is easy to read as *a list-valued field is impossible*.
//! It is not. The language has no vector TYPE; a `Vec<String>` FIELD lowers
//! perfectly well from a bare parenthesised run.
//!
//! Kept rather than deleted because the alternative reading costs real design:
//! believing this impossible is what pushes an author into wrapping every
//! string in its own `(def…)` form, which is how `:dirs ("/a" "/b")` becomes
//! `:dirs ((defdir :path "/a") (defdir :path "/b"))` for no gain.
//!
//! Measured 2026-08-18 against tatara-lisp 0.3.
use tatara_lisp::{DeriveTataraDomain, TataraDomain};

#[derive(Debug, PartialEq, Eq, DeriveTataraDomain)]
#[tatara(keyword = "defprobe")]
struct Probe {
    name: String,
    dirs: Vec<String>,
}

#[test]
fn a_plain_vec_of_strings_lowers_from_a_bare_run() {
    let src = r#"(defprobe :name "xdg" :dirs ("/a" "/b"))"#;
    let forms = tatara_lisp::read(src).expect("reads");
    match Probe::compile_from_sexp(&forms[0]) {
        Ok(p) => assert_eq!(p.dirs, vec!["/a".to_string(), "/b".to_string()]),
        Err(e) => panic!(
            "Vec<String> stopped working as a bare run: {e}\n\
             If this is a deliberate upstream change, `:dirs` in \
             (defsessions …) needs re-shaping — see this file's header."
        ),
    }
}
