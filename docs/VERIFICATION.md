# mukae-spec — what is verified, and at what tier

Measured 2026-08-18 on rustc 1.91.1, aarch64-darwin. **Re-measure rather than
infer**: the fleet's rustc floats (substrate selects the literal string
`stable`), so both the codes and the snapshot wording below are pinned to a
compiler that will move.

## M0's done-predicate, item by item

`theory/MUKAE.md` §7 defines M0 as three things. All three are met.

| | | state |
|---|---|---|
| (a) | a scripted three-prompt conversation driving `MockSeatEnv` to a `SessionHandle` | **green** — `tests/login_flow.rs::a_three_step_conversation_reaches_a_session` |
| (b) | a committed `trybuild` suite proving the compile-time seals | **green** — 6 cases, snapshots under `mukae-spec/tests/ui/` |
| (c) | one recorded red run per gate against a deliberately-broken input | **green** — the table below |

27 tests: 26 unit + integration, plus the compile-fail suite.

## The compile-time seals, with their MEASURED codes

Each row is a committed `.stderr` snapshot, not a claim.

| case | illegal state | code | predicted |
|---|---|---|---|
| `start_session_without_a_capability` | [1] start an unauthenticated session | **E0061** | E0061 ✓ |
| `forge_an_auth_proof` | [1] the mechanism — a proof cannot be made | **E0624** | not predicted |
| `reuse_one_authentication_twice` | [2] one auth, two sessions | **E0382** | E0382 ✓ |
| `denied_upgraded_to_authenticated` | [3] a denial upgraded to success | **E0599** | E0599 ✓ |
| `third_auth_state_invented_downstream` | [4] a third auth state | **E0277** | E0405 ✗ |
| `argv_to_shell_string` | [8] a command re-split by a shell | **E0277** | not predicted |
| `syscall_in_spec_consumer` | [14] a syscall through the border | **E0433** | E0433 ✓ |

**Correction to `theory/MUKAE.md` §4.4, row 4.** The doc predicts **E0405**
("cannot find trait") for a downstream crate implementing `SeatState`. The
measured code is **E0277** — sealing produces an unsatisfied *trait bound*, not
an unresolved name, because `SeatState` itself is public and only its
supertrait is not. rustc's own note names the pattern: *"`SeatState` is a
'sealed trait', because to implement it you also need to implement
`sealed::Sealed`, which is not accessible"*. The seal is exactly as strong as
claimed; the predicted code was wrong.

## The red runs — is each case non-vacuous?

A compile-fail case that would fail even with its seal removed proves nothing
while reading as a guarantee. So each seal was deliberately broken and the case
re-run. Harness: a one-shot script, not repo-resident; re-derive it rather than
trusting this table if the border changes.

| case | the seal that was broken | verdict | codes |
|---|---|---|---|
| `denied_upgraded_to_authenticated` | there is no `Denied → Authenticated` transition | **GOOD** | sealed=E0599 broken=COMPILED |
| `third_auth_state_invented_downstream` | `SeatState` requires the private `Sealed` supertrait | **GOOD** | sealed=E0277 broken=COMPILED |
| `argv_to_shell_string` | `Argv` has no `Display` | **GOOD** | sealed=E0277 broken=COMPILED |
| `syscall_in_spec_consumer` | no path to `libc` is reachable through the border | **GOOD** | sealed=E0433 broken=COMPILED |
| `forge_an_auth_proof` | every `AuthProof` constructor is `pub(crate)` | **GOOD** | sealed=E0624 broken=COMPILED |
| `reuse_one_authentication_twice` | `start_session` consumes the capability BY VALUE | **SHIFTED** | sealed=E0382 broken=E0308 |

**GOOD** means breaking the seal makes the case compile — the case fails only
because of the seal. **SHIFTED** means the claimed error code disappears but
the case still fails for another reason: real evidence the seal participates,
one notch weaker, and reported as such rather than rounded up.

`reuse_one_authentication_twice` is SHIFTED because its seal has two parts —
by-value consumption *and* the absence of `Clone` — and no single edit to the
library breaks both. Changing the parameter to `&SeatCapability<..>` makes
E0382 disappear (the move-check stops firing, which is the claim) but
introduces E0308 at the unchanged call site. Making the type `Copy` would be
the clean perturbation and is not available: `SeatCapability` holds a `SeatId`,
which holds a `String`.

### Three findings from building the harness

The harness earned its keep before it ever guarded anything — its first run
returned three VACUOUS verdicts, and each was a different kind of mistake:

1. **`unimplemented!()` made a whole case unreachable.** The first draft of
   `reuse_one_authentication_twice` obtained its capability via
   `let proof: AuthProof = unimplemented!();`. Everything after that is dead
   code, so rustc never ran the move analysis and **the case compiled** — a
   compile-fail test that passed for the wrong reason. It now obtains the
   capability by actually running a mock conversation.
2. **Two perturbations broke the wrong thing.** Deriving `Clone` does not
   auto-clone at a call site, and making the `sealed` module public does not
   make an outside type implement `Sealed`. Both left the case failing
   identically and were misread as vacuity in the case rather than in the
   perturbation.
3. **One case tested a symptom rather than a mechanism.**
   `start_session_without_a_capability` proves a caller cannot pass two
   arguments to a three-argument function — true, and it still fails when the
   capability requirement is removed, because the perturbed library no longer
   builds. The mechanism it was supposed to establish is that an `AuthProof`
   cannot be constructed at all, so `forge_an_auth_proof` was added to test
   that directly. Both are kept: one is the symptom a caller meets, the other
   is the cause.

## What is NOT sealed, and why

Two of `MUKAE.md`'s sixteen illegal states are **only-mitigated**, and both for
the same reason: they are facts about the world rather than about our
abstractions, so they do not become types by trying harder.

| # | state | why not a type |
|---|---|---|
| 16 | missing the libseat disable-ack deadline | a deadline is a fact about time. `seat_poll` takes a mandatory deadline and a miss is `SeatError::AckDeadlineMissed` |
| 17 | a greeter that painted nothing and reported healthy | a claim about photons. `assert_no_magenta_pixels` passes an all-black frame, so the positive proof is a committed golden frame hash — M6 |

## Scope — what M0 is not

Absent and deliberately **not stubbed**, because a `todo!()` behind a signature
that reads as implemented is worse than an absent method: only one of the two
is a compile error at the call site.

| | phase |
|---|---|
| the seat / device / VT half of `SeatEnv`, with its `Controlled` / `Disabling` / `Disabled` typestate | M4 |
| PAM linkage (`HostSeatEnv`) | M3 |
| any face — TTY or GPU | M5 / M6 |
| the handoff envelope and the epoch typestate | M2 / M7 |
| the `(defmukae …)` tatara-lisp surface | not M0; the border is plain typed Rust today |

**The tatara-lisp surface is the one to watch.** `MUKAE.md` §4.2 designs
`(defmukae …)` / `(defseat …)` forms over a `#[derive(TataraDomain)]` border,
and none of that is here. Saying "the typed border exists" is true; saying "the
authoring surface exists" would not be.
