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
        Some(Self {
            name: name.to_string(),
            hash: hash.to_string(),
        })
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
}
