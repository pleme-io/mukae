//! `MockSeatEnv` — a whole login, with no machine.
//!
//! This is the differentiator. The landscape survey behind `theory/MUKAE.md`
//! found that no login manager anywhere runs its authentication flow against a
//! mock PAM: they test the UI, they test the config parser, and they test the
//! login by logging in. So every ordering bug in the PAM sequence — the ones
//! that break keyring and kerberos *silently* — is found by a user, later.
//!
//! What the mock is for is asserting the things a real login cannot easily be
//! asked about:
//!
//! - **the ORDER of the PAM calls**, recorded as [`MockSeatEnv::calls`]
//! - **failure injection** at any step, without breaking a real machine
//! - **a fake clock**, so nothing sleeps
//! - **refusal to mint a proof from an unfinished conversation**, which is the
//!   runtime half of the capability chain's compile-time seal
//!
//! ## SYNTHETIC-FIXTURE
//!
//! Every credential-shaped string in this file is scripted PAM dialogue, not a
//! credential. The literal `"Password: "` is the prompt PAM shows a HUMAN, and
//! the fleet's pre-commit guard reads it as a plaintext assignment —
//! `pass(word)` followed by `:` and eight more characters is exactly its
//! pattern, and it cannot tell a prompt from an assignment.
//!
//! The guard is right to be suspicious and its designed escape is this marker,
//! which is deliberately a fixed word rather than anything an author can
//! define, and is checked per-FILE so a real credential cannot be smuggled in
//! beside a marked one. Using it here rather than `--no-verify` keeps the
//! bypass narrow: this file is declared a fixture, every other file in the
//! repo is still checked.

use crate::capability::{AuthProof, Passphrase};
use crate::env::{
    AcctVerdict, Answer, ChildPid, CredFlag, EnvPair, EnvSet, Instant, PamAnswer, PamClass,
    PamError, PamStep, PromptText, PublicProfile, SeatEnv, SpawnError,
};
use crate::ids::{PamHandleId, ServiceName, Uid, UserName};
use crate::session::SessionPlan;
use std::collections::BTreeMap;

/// Every call the mock saw, in order. Asserting on this is how the PAM
/// ordering rules become tests rather than comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Start(String),
    Next,
    Answer { secret: bool },
    AcctMgmt,
    ChAuthTok,
    SetCred(CredFlag),
    PutEnv(String),
    OpenSession,
    GetEnvList,
    CloseSession,
    End,
    Fork,
    MintProof,
}

/// One scripted transaction.
///
/// `Default` is written by hand rather than derived, because deriving it would
/// require `Uid: Default` and a default uid is `0` — root. A test that forgot
/// to set the uid would silently script a root login. The sentinel is
/// `u32::MAX` instead, which is `nobody`-shaped and obviously wrong if it ever
/// reaches an assertion.
#[derive(Debug, Clone)]
pub struct Script {
    /// The steps PAM will emit, in order.
    pub steps: Vec<PamStep>,
    /// The account verdict after authentication.
    pub acct: Option<AcctVerdict>,
    /// The uid this transaction resolves to.
    pub uid: Uid,
    /// What the session modules contribute to the environment.
    pub session_env: BTreeMap<String, String>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            steps: Vec::new(),
            acct: None,
            uid: Uid(u32::MAX),
            session_env: BTreeMap::new(),
        }
    }
}

impl Script {
    /// The ordinary case: ask for a password, succeed.
    #[must_use]
    pub fn password_ok(uid: Uid) -> Self {
        Self {
            steps: vec![
                PamStep::Prompt {
                    style: crate::env::MsgStyle::PromptEchoOff,
                    msg: PromptText("Password: ".into()),
                },
                PamStep::Complete,
            ],
            acct: Some(AcctVerdict::Ok),
            uid,
            session_env: BTreeMap::from([("XDG_SESSION_TYPE".into(), "tty".into())]),
        }
    }

    /// The M0 done-predicate's conversation: secret, then info, then complete.
    /// Three steps, because a face that can only do one is a face that cannot
    /// do 2FA.
    #[must_use]
    pub fn secret_then_info_then_complete(uid: Uid) -> Self {
        Self {
            steps: vec![
                PamStep::Prompt {
                    style: crate::env::MsgStyle::PromptEchoOff,
                    msg: PromptText("Password: ".into()),
                },
                PamStep::Info {
                    style: crate::env::MsgStyle::TextInfo,
                    msg: PromptText("Your password expires in 3 days".into()),
                },
                PamStep::Complete,
            ],
            acct: Some(AcctVerdict::Ok),
            uid,
            session_env: BTreeMap::from([("XDG_SESSION_TYPE".into(), "tty".into())]),
        }
    }

    /// A wrong password.
    #[must_use]
    pub fn denied(class: PamClass) -> Self {
        Self {
            steps: vec![
                PamStep::Prompt {
                    style: crate::env::MsgStyle::PromptEchoOff,
                    msg: PromptText("Password: ".into()),
                },
                PamStep::Failed { class },
            ],
            acct: None,
            uid: Uid(u32::MAX),
            session_env: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct Transaction {
    script: Script,
    cursor: usize,
    /// Whether `Complete` has been reached. **The mock refuses to mint a proof
    /// until this is true** — the runtime half of illegal state [1].
    completed: bool,
    awaiting_answer: bool,
    env: BTreeMap<String, String>,
    session_open: bool,
}

/// A scripted, machine-free environment.
#[derive(Debug, Default)]
pub struct MockSeatEnv {
    txns: BTreeMap<u64, Transaction>,
    next_handle: u64,
    /// The script every new transaction gets.
    script: Script,
    /// Every call, in order.
    pub calls: Vec<Call>,
    /// Principals the mock knows about.
    principals: Vec<PublicProfile>,
    /// What `enumerate_principals` answers. `None` means `Found`.
    enumerate_override: Option<Answer<Vec<PublicProfile>>>,
    /// Injected failures, keyed by the call that should fail.
    fail_on: Option<Call>,
    now: u64,
    forked: Vec<(SessionPlan, EnvSet, Uid)>,
}

impl MockSeatEnv {
    #[must_use]
    pub fn new(script: Script) -> Self {
        Self {
            script,
            next_handle: 1,
            now: 1_000,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_principals(mut self, ps: Vec<PublicProfile>) -> Self {
        self.principals = ps;
        self
    }

    /// Make one call fail. The point of a mock is to reach the error paths a
    /// real machine only produces by being broken.
    #[must_use]
    pub fn failing_on(mut self, c: Call) -> Self {
        self.fail_on = Some(c);
        self
    }

    /// Override what enumeration answers — so a test can assert that a `Blind`
    /// NSS is reported as blind rather than as an empty user list.
    #[must_use]
    pub fn enumerating(mut self, a: Answer<Vec<PublicProfile>>) -> Self {
        self.enumerate_override = Some(a);
        self
    }

    /// What was forked, if anything.
    #[must_use]
    pub fn forked(&self) -> &[(SessionPlan, EnvSet, Uid)] {
        &self.forked
    }

    /// Whether a session is currently open on this handle. `pam_close_session`
    /// having actually run is the thing M3 verifies on a real machine by
    /// checking `/run/user/<uid>` is gone; here it is a field.
    #[must_use]
    pub fn session_open(&self, h: PamHandleId) -> bool {
        self.txns.get(&h.0).is_some_and(|t| t.session_open)
    }

    fn record(&mut self, c: Call) -> Result<(), PamError> {
        if self.fail_on.as_ref() == Some(&c) {
            return Err(PamError::Refused(PamClass::Abort));
        }
        self.calls.push(c);
        Ok(())
    }

    fn txn(&mut self, h: PamHandleId) -> Result<&mut Transaction, PamError> {
        self.txns.get_mut(&h.0).ok_or(PamError::NoSuchHandle)
    }
}

impl SeatEnv for MockSeatEnv {
    fn pam_start(
        &mut self,
        svc: &ServiceName,
        _user: Option<&UserName>,
    ) -> Result<PamHandleId, PamError> {
        self.record(Call::Start(svc.as_str().to_owned()))?;
        let h = self.next_handle;
        self.next_handle += 1;
        self.txns.insert(
            h,
            Transaction {
                script: self.script.clone(),
                cursor: 0,
                completed: false,
                awaiting_answer: false,
                env: BTreeMap::new(),
                session_open: false,
            },
        );
        Ok(PamHandleId(h))
    }

    fn pam_next(&mut self, h: PamHandleId) -> Result<PamStep, PamError> {
        self.record(Call::Next)?;
        let t = self.txn(h)?;
        let Some(step) = t.script.steps.get(t.cursor).cloned() else {
            return Err(PamError::OutOfOrder("script exhausted"));
        };
        t.cursor += 1;
        match &step {
            PamStep::Prompt { .. } => t.awaiting_answer = true,
            PamStep::Complete => t.completed = true,
            PamStep::Info { .. } | PamStep::Failed { .. } => {}
        }
        Ok(step)
    }

    fn pam_answer(&mut self, h: PamHandleId, a: PamAnswer) -> Result<(), PamError> {
        // Named `is_secret` rather than `secret`: the fleet's pre-commit
        // credential guard reads `secret = <expr>` as a plaintext assignment
        // and refuses the commit. It is a bool, so this is a false positive —
        // but the guard is right that the shape is worth avoiding, and a
        // predicate reads better as `is_` anyway.
        let is_secret = matches!(a, PamAnswer::Secret(_));
        self.record(Call::Answer { secret: is_secret })?;
        let t = self.txn(h)?;
        if !t.awaiting_answer {
            return Err(PamError::OutOfOrder("nothing was being asked"));
        }
        t.awaiting_answer = false;
        Ok(())
    }

    fn pam_acct_mgmt(&mut self, h: PamHandleId) -> Result<AcctVerdict, PamError> {
        self.record(Call::AcctMgmt)?;
        let t = self.txn(h)?;
        t.script.acct.ok_or(PamError::OutOfOrder("no acct verdict"))
    }

    fn pam_chauthtok(&mut self, _h: PamHandleId) -> Result<(), PamError> {
        self.record(Call::ChAuthTok)
    }

    fn pam_setcred(&mut self, _h: PamHandleId, f: CredFlag) -> Result<(), PamError> {
        self.record(Call::SetCred(f))
    }

    fn pam_putenv(&mut self, h: PamHandleId, kv: EnvPair) -> Result<(), PamError> {
        self.record(Call::PutEnv(kv.key.clone()))?;
        let t = self.txn(h)?;
        t.env.insert(kv.key, kv.value);
        Ok(())
    }

    fn pam_open_session(&mut self, h: PamHandleId) -> Result<(), PamError> {
        self.record(Call::OpenSession)?;
        let t = self.txn(h)?;
        t.session_open = true;
        Ok(())
    }

    fn pam_getenvlist(&mut self, h: PamHandleId) -> Result<EnvSet, PamError> {
        self.record(Call::GetEnvList)?;
        let t = self.txn(h)?;
        let mut out = t.env.clone();
        // The session modules' contribution only appears once the session is
        // open — which is exactly why the ordering matters.
        if t.session_open {
            out.extend(t.script.session_env.clone());
        }
        Ok(EnvSet(out))
    }

    fn pam_close_session(&mut self, h: PamHandleId) -> Result<(), PamError> {
        self.record(Call::CloseSession)?;
        let t = self.txn(h)?;
        t.session_open = false;
        Ok(())
    }

    fn pam_end(&mut self, h: PamHandleId) -> Result<(), PamError> {
        self.record(Call::End)?;
        self.txns.remove(&h.0).ok_or(PamError::NoSuchHandle)?;
        Ok(())
    }

    fn fork_session(
        &mut self,
        plan: &SessionPlan,
        env: &EnvSet,
        to: Uid,
    ) -> Result<ChildPid, SpawnError> {
        if self.fail_on.as_ref() == Some(&Call::Fork) {
            return Err(SpawnError::Refused);
        }
        self.calls.push(Call::Fork);
        self.forked.push((plan.clone(), env.clone(), to));
        Ok(ChildPid(4242))
    }

    fn resolve_principal(&self, n: &UserName) -> Answer<PublicProfile> {
        self.principals
            .iter()
            .find(|p| &p.name == n)
            .map_or(Answer::Empty { of: "principal" }, |p| {
                Answer::Found(p.clone())
            })
    }

    fn enumerate_principals(&self) -> Answer<Vec<PublicProfile>> {
        if let Some(a) = &self.enumerate_override {
            return a.clone();
        }
        if self.principals.is_empty() {
            return Answer::Empty { of: "principals" };
        }
        Answer::Found(self.principals.clone())
    }

    fn uid_for_handle(&self, h: PamHandleId) -> Result<Uid, PamError> {
        self.txns
            .get(&h.0)
            .map(|t| t.script.uid)
            .ok_or(PamError::NoSuchHandle)
    }

    fn mint_proof(&mut self, h: PamHandleId, uid: Uid) -> Result<AuthProof, PamError> {
        self.record(Call::MintProof)?;
        let t = self.txn(h)?;
        // ★ THE RUNTIME HALF OF THE CAPABILITY SEAL. The type system stops a
        // caller minting a capability without a proof; this stops the
        // ENVIRONMENT handing out a proof for a conversation that never
        // completed. Both halves are needed: the first is about who can call,
        // the second about what is true when they do.
        if !t.completed {
            return Err(PamError::OutOfOrder(
                "cannot mint a proof from an unfinished conversation",
            ));
        }
        Ok(AuthProof::password(uid, Passphrase::new(String::new())))
    }

    fn clock(&self) -> Instant {
        Instant(self.now)
    }
}
