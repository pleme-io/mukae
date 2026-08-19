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

## Two operational notes for whoever runs this next

**`TRYBUILD=overwrite` creates a `wip/` directory at the repo root.** It is
transient — it exists only while snapshots are being regenerated — and it is
deliberately NOT in `.gitignore`, because that file is a repo-forge boilerplate
artifact regenerated wholesale by `migrate --apply`, so a line added there does
not survive. Delete it after regenerating; if it is ever committed, that is the
signal the snapshot run was interrupted.

**Two pre-commit guards fired on the first commit and neither was bypassed.**
`let secret = matches!(…)` (a bool) tripped the credential guard's whole-word
`secret` arm and was renamed to `is_secret`. The literal `"Password: "` — the
prompt PAM shows a human — tripped its `pass(word)` arm, which structurally
cannot tell a prompt from an assignment; `mock.rs` therefore carries the
guard's own `SYNTHETIC-FIXTURE` marker. That is narrower than `--no-verify`:
it declares one file a fixture and leaves every other file checked.

## The reconciliation adapter — and why it is an adapter

`surface.rs` makes the login surface reconcilable: desired, observed, and the
gap between them, as pure data. **There is no loop in it**, deliberately. The
fleet has one convergence engine (`lava-viggy`'s seven beats, which `bancadad`
already runs on) and writing a second here would be exactly the duplication
that adoption removed.

**On "bancadad gains a `World` impl in a few lines" — I said that twice and it
is two-thirds true.** `observe` and `describe` genuinely are trivial;
`apply_calls` is exactly as real as the `SeatEnv` behind it. At M0 that is
`MockSeatEnv`, so wiring it up today yields a reconciler correctly driving a
mock — real progress, not a live desktop. Only `login-close-session` has an
implementation path that does not wait for M3, and rounding the two together is
how a mock-backed loop gets cited later as a working one.

**A login surface is not like the rest of the desktop, and the type says so.**

| | |
|---|---|
| `login.session.open` | **CloseOnly** — a loop may end a session, never start one |
| `login.session.owner` | **ObserveOnly** — decided by who authenticated |
| `login.enabled` | **Both** |

The `CloseOnly` asymmetry is the safety property. Closing needs no secret;
opening needs an `AuthProof`, which only a human interaction produces — and the
capability chain already makes a machine-minted one unconstructable. Stating it
here means a *planner* never emits an action the type system would refuse.

Three further shape decisions, each because a login is not idempotent:

- **`NeedsHuman` does not block convergence.** A seat declaring "someone should
  be logged in" is not broken while nobody is; it is waiting. A loop reporting
  that as failure every tick trains its operator to ignore it.
- **The surface is tiny** — 3 keys against 31 catalog actions — because most
  login actions are events in a conversation, not state, and re-running one
  costs a retry budget or locks an account. A test fails if it grows past a
  quarter of the catalog without someone re-checking that.
- **An unobserved key is unknown, never `false`.** Same distinction
  `Answer::Blind` draws for identity.

`observe()` returns all-unknown on an M0 world, and that is a correct value
rather than a `todo!()`: the seat-scoped session query arrives with the seat
half at M4, so today every key honestly reads as unseen.

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
| ~~the `(defmukae …)` tatara-lisp surface~~ | **SHIPPED** — `mukae-lisp`, 13 tests over the committed spec |

## The authoring surface — `mukae-lisp`, and what it corrected

`(defmukae …)` ships. `mukae-lisp/specs/fleet-entrance.mukae.lisp` is a real
two-seat entrance, and 13 tests exercise it — the committed file itself, not a
fixture, so drift from what an operator would actually write is what breaks.

It is a SEPARATE CRATE on purpose. `mukae-spec`'s dependency list is the
mechanism that closes illegal state [14], so every crate added there deletes a
proof; the authoring surface sits above the border and depends on it.

**Three measured corrections to `MUKAE.md` §4.2's sketch.**

1. **Enum values must be single words.** `DeriveKeywordSexp` lowercases the
   identifier with *no separator*, while field names go snake → kebab. Two
   opposite conventions in one language. §4.2 writes `:sealed-memfd`,
   `:physical-presence` and `:no-display` as *values* — none of those parse.
   Pinned by `enum_values_have_no_separator_but_field_names_do`.
2. **A typo'd kwarg IS rejected on the derive path.** §4.2 calls a lint "not
   optional here" because of the silent empty-`Vec` trap. That trap is real on
   the *manual* extraction path; `DeriveTataraDomain` emits a
   `__TATARA_ALLOWED_KEYWORDS` gate that errors with a did-you-mean. Re-pinned
   per-domain because the consequence is severe: a login config that parses
   green while missing half its fields is a machine nobody can get into.
3. **A `Vec<T>` is a bare run of forms** — the language has neither a map nor a
   vector, so every nested value is its own named domain.

**What lowering enforces that the data language cannot.** A form is data; the
invariants live in the lowering, at the one boundary where the typed
information exists:

| refused | why it cannot be a type in the lisp |
|---|---|
| a VT console on a non-`seat0` seat | lisp cannot carry a `Seat0Witness`; `as_seat0()` is its only producer |
| autologin *and* restart-on-exit | greetd's boolean pair; the autologin arm has no `restart` field to lower into |
| a greeter with a `:user` | greeters have none |
| a seatless console with VT fields | not harmless — the author believes that seat has a VT |
| a duplicate seat id | the second would silently win |

### `:catalog`, `:handoff` and `:faces` — shipped, at three different tiers

All three of §4.2's remaining sections now exist, and they are **not equally
real**. Saying so is the point:

| section | tier | why |
|---|---|---|
| `:faces` | **live** | pure data — which renderer serves which face |
| `:catalog` | **live logic, M3 reader** | the rules are typed and proven; the filesystem impl is M3, same standing as the login conversation |
| `:handoff` | **DECLARATION ONLY** | the envelope's shape and invariants are here; the layer that feeds a config fold is not, and cannot be until shikumi grows an `Attested` tier |

**I said last pass that these needed hardware. That was wrong**, and it is
worth naming as the error it was: `:catalog` is a filesystem read behind a
mockable seam and `:faces` is data — neither goes near a GPU. What the handoff
is actually blocked on is §5.5's **S1**, an upstream shikumi change measured at
~1453 `ConfigTierKind` sites, because an injected `Discovered` fact is
currently overwritten by `prescribed_default()` (ordinals `Bare, Discovered,
Default, Custom`). That is a real dependency and a large one — but it is *our
own abstraction*, not a fact about the world, and the two deserve different
words.

**What the handoff form refuses, and why each would produce a stale value:**

| refused | consequence if allowed |
|---|---|
| a sensor path (`battery.*`, `thermal.*`, `power.draw`, `fan.*`) | hands over a value already wrong on arrival |
| a hotplug-volatile fact at epoch E2 | by E2 the session has started; the measurement is history |
| zero validity | stale on arrival by definition |
| an env var containing `=` | an assignment, not a name — never resolves |
| a duplicate fact path | one silently wins |

The sensor rule has **two mechanisms, not one**. `Volatility` has no `Sensor`
arm, so there is no volatility a declarer could give such a fact — structural.
The name check catches an author reaching for it anyway under a volatility that
does not fit.

**Every one of the seven absence paths resolves to an empty dict**, with the
denominator carried in `Absence::ALL` rather than in prose. That is §5.4's
contract verbatim: a missing handoff must be indistinguishable from a machine
that never had one, so the session re-probes exactly as it would have. A
fallback that guessed would be worse than no handoff, because the session would
trust the guess.

### One modelling correction to §4.2, made on merit

§4.2 writes `:honor (:hidden :no-display :try-exec)` — a list, implying an open
set. The XDG Desktop Entry spec defines exactly those three and no more, so the
shipped form is three named optional flags. An unknown hint has nowhere to go
and the same hint cannot be named twice. Undeclared means **honoured**:
ignoring `Hidden=true` because nobody opted into obedience would show a user an
entry its packager deliberately deleted.

### And a measured correction to the fleet's own notes on tatara-lisp

"No map, no vector" reads naturally as *a list-valued field is impossible*. It
is not — the language has no vector TYPE, while a `Vec<String>` FIELD lowers
fine from a bare run. `mukae-lisp/tests/vec_of_strings.rs` is the probe, kept
rather than deleted because the wrong reading costs real design: it is what
pushes an author into `:dirs ((defdir :path "/a") (defdir :path "/b"))`.
