//! ILLEGAL STATE [14] — a syscall reached through the spec crate.
//!
//! ## What this case proves, and what it does NOT
//!
//! It proves that `mukae-spec` does not re-export or otherwise leak a path to
//! `libc`, so a consumer cannot reach a syscall THROUGH the border.
//!
//! It does NOT prove the stronger statement — that no syscall exists inside
//! `mukae-spec` itself. trybuild compiles this file as a separate crate, so it
//! cannot make a claim about the host crate's own body. Those are two
//! different facts and only one of them is checked here.
//!
//! The stronger statement rests on two things that ARE checked: the crate's
//! dependency list, which names no `libc`/`nix`/`pam-sys`/`wgpu` and is
//! commented as an invariant rather than a convenience, and
//! `#![forbid(unsafe_code)]` in `lib.rs` — a raw syscall needs `unsafe`, so
//! the lint is the second lock on the same door.
fn main() {
    let _ = mukae_spec::libc::fork();
}
