//! ILLEGAL STATE [8] — a session command re-split by a shell (greetd's R1).
//!
//! `Argv` has no `Display`, no `From<String>`, no `join` and no
//! `as_shell_string`. There is no expression producing something a shell could
//! re-parse, so a session path containing a space cannot become two arguments.
use mukae_spec::session::Argv;
use std::ffi::OsString;

fn main() {
    let a = Argv::new(vec![OsString::from("/bin/sh"), OsString::from("a b")]).unwrap();
    // None of these exist.
    println!("{}", a);
}
