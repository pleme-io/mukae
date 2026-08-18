//! M0's done-predicate (b) — the compile-time seals, as recorded compiler
//! diagnostics rather than sentences in a doc comment.
//!
//! Each case under `tests/ui/` is a program that MUST NOT COMPILE, and its
//! committed `.stderr` is the proof. A claim like "illegal state [3] is
//! unrepresentable" is worth exactly as much as the diagnostic that backs it;
//! without this file, the claim is prose.
//!
//! ## The known cost of this suite
//!
//! `.stderr` snapshots are rustc-version-sensitive. A toolchain bump can
//! reword a diagnostic and turn these red without anything being wrong — and
//! the fleet's rustc FLOATS (substrate selects the literal string `stable`, so
//! which compiler is in use is decided by whichever `fenix` rev is locked, and
//! that moves on routine lock bumps).
//!
//! That is an accepted cost, not an oversight. Regenerate with
//! `TRYBUILD=overwrite cargo test --test compile_fail` and READ THE DIFF: if
//! the error CODE changed, the seal changed and that is a real finding; if only
//! the wording moved, commit the new snapshot. The codes are what matter, and
//! they are named in each case's header.
//!
//! Recorded here rather than discovered later: this suite was written against
//! rustc 1.91.1.

#[test]
fn illegal_states_do_not_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
