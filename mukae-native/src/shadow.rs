//! `/etc/shadow`, as a type rather than as a line.
//!
//! ── ★ WHY THIS IS ITS OWN MODULE AND NOT AN INLINE SPLIT ──────────────────
//! The file is nine colon-separated fields and it is tempting to `split(':')`
//! at the call site. Three of those fields decide whether an account may log
//! in AT ALL, independently of the password, and every one of them is a
//! fail-open if forgotten. Parsing into a type means the verifier cannot
//! reach a passphrase check without having answered them.

use zeroize::Zeroize;

/// One account's shadow entry, reduced to what authentication needs.
pub struct ShadowEntry {
    pub name: String,
    /// The hash field VERBATIM, including its `$id$salt$` prefix.
    hash: String,
    /// Field 3 — days since the epoch when the password was last changed.
    ///
    /// `Some(0)` is shadow(5)'s sentinel for "must be changed at next login";
    /// `None` is the field left empty, which disables aging.
    last_change: Option<i64>,
    /// Field 5 — how many days a password stays valid.
    max_age: Option<i64>,
    /// Field 7 — days of grace AFTER the password expires before the account
    /// itself stops being usable.
    inactive: Option<i64>,
    /// Field 8 — days since the epoch when the ACCOUNT expires, regardless of
    /// the password.
    expires: Option<i64>,
}

/// Whether an account may log in today, independently of its password.
///
/// ── ★ THIS TYPE IS WHAT THE HEADER ABOVE PROMISED, THREE YEARS LATE ─────
/// The module opens with "three of those fields decide whether an account may
/// log in AT ALL … every one of them is a fail-open if forgotten. Parsing into
/// a type means the verifier cannot reach a passphrase check without having
/// answered them." `parse_line` took fields 1 and 2 and dropped 3–9, so all
/// three were forgotten and all three failed open: `chage -E 2020-01-01`,
/// `chage -I 1` past the window, and an aged-out password each logged in with
/// a full logind session. The stack mukae replaced refuses every one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Nothing in the aging fields blocks a login.
    Ok,
    /// Field 8 has passed: the account is gone, and no password change
    /// recovers it.
    AccountExpired,
    /// The password aged out and the field-7 grace elapsed. Distinct from
    /// [`Self::MustChangePassword`] because the answer is different: this one
    /// cannot be fixed at the prompt.
    InactiveElapsed,
    /// The password aged out, or field 3 is the `0` sentinel. A login is
    /// permitted only to change it.
    MustChangePassword,
}

impl Drop for ShadowEntry {
    fn drop(&mut self) {
        // A password HASH is not a password, and it is still the thing an
        // offline cracker wants. Costless to clear; leaving it in a freed page
        // for the length of a login session is a choice with no upside.
        self.hash.zeroize();
    }
}

/// Why an entry cannot authenticate, before any passphrase is considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// `!` or `!!` — the account is locked. `!` also PREFIXES an otherwise
    /// valid hash, which is the trap: a naive verifier strips nothing, fails
    /// to match, and reports a wrong password for a locked account. A less
    /// naive one strips the `!` and **logs a locked account in**.
    Locked,
    /// `*` — login disabled, conventionally a system account.
    Disabled,
    /// Empty — no password set. ★ Refused rather than treated as "any
    /// passphrase matches". `pam_unix` accepts this under `nullok`, which is
    /// in this machine's stack; mukae does not, because a seat that logs
    /// anyone in as a passwordless account is not a seat.
    NoPassword,
}

impl ShadowEntry {
    /// Parse one line. Returns `None` for a blank or malformed line rather
    /// than erroring: a shadow file with a comment in it must not fail the
    /// whole login.
    #[must_use]
    pub fn parse_line(line: &str) -> Option<Self> {
        let mut f = line.split(':');
        let name = f.next()?;
        let hash = f.next()?;
        if name.is_empty() {
            return None;
        }
        // ★ AN UNSET FIELD AND AN UNPARSEABLE ONE ARE BOTH `None`, and that is
        // shadow(5)'s own rule rather than a shortcut: an empty field means
        // the feature is disabled, and glibc's `getspnam` likewise yields -1
        // for a field it cannot read. Being stricter here would refuse logins
        // on a file that every other tool on the host accepts.
        let mut day = || -> Option<i64> { f.next().and_then(|v| v.trim().parse::<i64>().ok()) };
        let last_change = day();
        let _min_age = day(); // field 4 — a floor on CHANGES, not on logins.
        let max_age = day();
        let _warn = day(); // field 6 — when to warn, not when to refuse.
        let inactive = day();
        let expires = day();
        Some(Self {
            name: name.to_string(),
            hash: hash.to_string(),
            last_change,
            max_age,
            inactive,
            expires,
        })
    }

    /// Whether this account may log in on day `today` (days since the epoch),
    /// independently of its password.
    ///
    /// ★ THE DAY IS AN ARGUMENT. Reading the clock in here would make every
    /// case below untestable without either mocking time or writing a fixture
    /// whose expected answer changes tomorrow — and the arithmetic is the
    /// whole risk, so it is the part that has to be pinned.
    ///
    /// Order matters and follows `pam_unix`: account expiry outranks password
    /// expiry (no change at the prompt recovers it), and the `0` sentinel
    /// outranks aging (it is set precisely to force a change now).
    #[must_use]
    pub fn validity(&self, today: i64) -> Validity {
        if let Some(exp) = self.expires
            && exp >= 0
            && today >= exp
        {
            return Validity::AccountExpired;
        }
        if self.last_change == Some(0) {
            return Validity::MustChangePassword;
        }
        let (Some(changed), Some(max)) = (self.last_change, self.max_age) else {
            return Validity::Ok;
        };
        // A negative or absurd max is aging switched off — `99999` is the
        // conventional "never", and anything at or past it behaves the same.
        if max < 0 || max >= 99_999 {
            return Validity::Ok;
        }
        if today <= changed + max {
            return Validity::Ok;
        }
        // Past the password's life. Whether that is recoverable depends on
        // field 7: with no grace declared there is none, so the account is
        // merely asking for a new password; with a grace that has elapsed it
        // is dead.
        match self.inactive {
            Some(grace) if grace >= 0 && today > changed + max + grace => Validity::InactiveElapsed,
            _ => Validity::MustChangePassword,
        }
    }

    /// The hash, or why this account cannot authenticate at all.
    ///
    /// # Errors
    /// [`Unusable`] when the entry is locked, disabled, or has no password.
    pub fn usable_hash(&self) -> Result<&str, Unusable> {
        match self.hash.as_str() {
            "" => Err(Unusable::NoPassword),
            "*" => Err(Unusable::Disabled),
            h if h.starts_with('!') => Err(Unusable::Locked),
            h => Ok(h),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_account_is_locked_even_with_a_valid_hash_behind_the_bang() {
        // ★ THE TRAP. `!` PREFIXES an otherwise-valid hash rather than
        // replacing it, so a verifier that strips it authenticates a locked
        // account with its old password. Refusing on the prefix — before the
        // hash is even looked at — is the only reading that cannot go wrong.
        let e = ShadowEntry::parse_line("bob:!$y$j9T$abc$def:20000:0:99999:7:::")
            .expect("a well-formed line parses");
        assert_eq!(e.usable_hash(), Err(Unusable::Locked));
    }

    #[test]
    fn an_empty_password_is_refused_not_accepted() {
        // pam_unix's `nullok` — which IS in this machine's login stack —
        // treats this as "any passphrase matches". A seat must not.
        let e = ShadowEntry::parse_line("svc::20000:0:99999:7:::").expect("parses");
        assert_eq!(e.usable_hash(), Err(Unusable::NoPassword));
    }

    #[test]
    fn a_disabled_account_is_refused() {
        let e = ShadowEntry::parse_line("daemon:*:20000::::::").expect("parses");
        assert_eq!(e.usable_hash(), Err(Unusable::Disabled));
    }

    #[test]
    fn a_normal_entry_yields_its_hash_verbatim() {
        // Verbatim including the $id$salt$ prefix: the scheme is chosen FROM
        // the stored hash, never from a caller's expectation.
        let e = ShadowEntry::parse_line("ann:$6$salt$hash:20000:0:99999:7:::").expect("parses");
        assert_eq!(e.usable_hash(), Ok("$6$salt$hash"));
    }

    #[test]
    fn a_blank_line_is_skipped_not_fatal() {
        assert!(ShadowEntry::parse_line("").is_none());
    }

    // ── ★ THE AGING FIELDS. Every case below logged in before 2026-09-20.

    /// `chage -E 2020-01-01 bob` → field 8 = 18262.
    #[test]
    fn an_expired_account_is_refused_and_a_password_change_does_not_help() {
        let e = ShadowEntry::parse_line("bob:$6$s$h:20000:0:99999:7::18262:").expect("parses");
        assert_eq!(e.validity(20_000), Validity::AccountExpired);
        // The day itself counts as expired — `>=`, matching shadow(5).
        assert_eq!(e.validity(18_262), Validity::AccountExpired);
        assert_eq!(e.validity(18_261), Validity::Ok);
    }

    /// The `0` sentinel `chage -d 0` sets: change it now, whatever else says.
    #[test]
    fn the_zero_sentinel_forces_a_change_even_with_aging_off() {
        let e = ShadowEntry::parse_line("bob:$6$s$h:0:0:99999:7:::").expect("parses");
        assert_eq!(e.validity(20_000), Validity::MustChangePassword);
    }

    #[test]
    fn a_password_past_its_max_age_must_be_changed() {
        // changed day 20000, valid 90 days.
        let e = ShadowEntry::parse_line("bob:$6$s$h:20000:0:90:7:::").expect("parses");
        assert_eq!(e.validity(20_090), Validity::Ok, "the last valid day");
        assert_eq!(e.validity(20_091), Validity::MustChangePassword);
    }

    /// `chage -I 1` — one day of grace after expiry, then the account is dead.
    #[test]
    fn the_inactive_grace_turns_an_expired_password_into_a_dead_account() {
        let e = ShadowEntry::parse_line("bob:$6$s$h:20000:0:90:7:1::").expect("parses");
        assert_eq!(e.validity(20_091), Validity::MustChangePassword, "in grace");
        assert_eq!(e.validity(20_092), Validity::InactiveElapsed, "grace gone");
    }

    #[test]
    fn aging_off_is_the_common_case_and_must_stay_ok() {
        // The NixOS default shape: 99999 max, empty inactive and expire.
        let e = ShadowEntry::parse_line("ann:$6$s$h:20000:0:99999:7:::").expect("parses");
        assert_eq!(e.validity(99_999_999), Validity::Ok);
        // And a line with every aging field empty.
        let bare = ShadowEntry::parse_line("ann:$6$s$h:::::::").expect("parses");
        assert_eq!(bare.validity(99_999_999), Validity::Ok);
        // A short line — no aging fields at all — must not refuse a login.
        let short = ShadowEntry::parse_line("ann:$6$s$h").expect("parses");
        assert_eq!(short.validity(99_999_999), Validity::Ok);
    }

    #[test]
    fn a_garbage_aging_field_reads_as_unset_rather_than_refusing() {
        // shadow(5) treats an empty field as "disabled" and glibc yields -1
        // for one it cannot read. Being stricter would refuse a login on a
        // file every other tool on the host accepts.
        let e = ShadowEntry::parse_line("ann:$6$s$h:notanumber:0:x:7:y:z:").expect("parses");
        assert_eq!(e.validity(99_999_999), Validity::Ok);
    }
}
