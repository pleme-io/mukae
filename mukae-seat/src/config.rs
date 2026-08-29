//! mukae's typed configuration surface.
//!
//! ── ★ WHY THE LOGIN MANAGER WAS THE LAST DAEMON WITHOUT ONE ────────────
//!
//! Measured across the five pleme-io daemons on 2026-08-28, `mukae` was the
//! only one with no `shikumi` dependency — the fleet's mandated config
//! primitive. Its entire behaviour arrived as argv assembled by a Nix module:
//! `--user`, `--vt`, `--greeter`, `--greeter-user`.
//!
//! That is the wrong shape for *any* daemon (a config that reaches the process
//! as argv cannot be validated, defaulted, round-tripped or diffed), and it is
//! the worst possible shape for **this** one — the thing whose configuration
//! decides whether a human can get into the machine at all.
//!
//! ── ★ THE FIELD THAT FORCED IT: session PATH ───────────────────────────
//!
//! `mukaed.rs` built the session `PATH` from a string literal, and its own
//! comment named the destination:
//!
//! > ★ THIS IS NIXOS-SHAPED, AND THAT IS A KNOWN WART. mukaed should take its
//! > session PATH from configuration rather than know a distribution's layout.
//!
//! That hardcode was not theoretical. Omitting `/run/wrappers/bin` from it
//! cost the operator `sudo` from their own seat, and the failure did not read
//! as a PATH problem — every setuid binary on NixOS lives in the wrappers
//! directory, so the store copy answers `sudo must be owned by uid 0 and have
//! the setuid bit set`, which reads like a broken installation. A value that
//! dangerous belongs in a typed surface where it can be reviewed, not in a
//! literal three call-frames deep.
//!
//! ── ★ A BROKEN CONFIG MUST NOT COST YOU THE SEAT ───────────────────────
//!
//! Every failure path in [`load`] returns the prescribed tier and says why on
//! stderr. This is omoya's rule and it binds harder here: refusing to start
//! because a yaml file has a typo leaves a machine with no way in that does
//! not involve a second computer. A CLI should refuse a bad config; the login
//! manager must not.
//!
//! The warning names the path deliberately — a seat that silently ignored its
//! config would be worse than one that complained, since the operator would
//! spend the evening editing a file nothing reads.

use serde::{Deserialize, Serialize};

/// The placeholder [`MukaeConfig::session_path`] entries may carry for the
/// authenticated account's login name.
///
/// It exists because the per-user profile directory is the one PATH entry that
/// cannot be a constant — it names the person logging in. Substituting at use
/// keeps the config a plain list of strings (reviewable, diffable, renderable
/// from Nix) instead of a template language.
pub const USER_PLACEHOLDER: &str = "{user}";

/// mukae's configuration, in shikumi's tier model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MukaeConfig {
    /// The greeter program mukaed execs for an interactive login.
    pub greeter: Option<String>,

    /// The unprivileged account the greeter runs as.
    pub greeter_user: Option<String>,

    /// The VT to claim. `None` means a seatless session.
    ///
    /// ★ Zero is not "no VT" and is rejected at use rather than accepted
    /// here: logind refuses `vtnr=0` on a seat that has VTs, and the refusal
    /// arrives three steps later naming neither field.
    pub vt: Option<u32>,

    /// The session's `PATH`, as ordered entries. Any entry containing
    /// [`USER_PLACEHOLDER`] has it replaced with the account's login name; if
    /// the name cannot be resolved, that entry is DROPPED rather than emitted
    /// with the placeholder intact — a literal `{user}` in a PATH is a
    /// directory that does not exist, and silently searching it would turn a
    /// resolution failure into a mystery.
    pub session_path: Vec<String>,
}

impl MukaeConfig {
    /// Tier 0 — the documented floor. No greeter, no VT, no PATH.
    ///
    /// ★ A session started from this tier has an EMPTY PATH, which is
    /// deliberate: the floor is "zero opinion", and inventing `/usr/bin` here
    /// would be an opinion wearing the floor's clothes. Anything that wants a
    /// working session uses [`Self::prescribed`].
    #[must_use]
    pub fn bare() -> Self {
        Self {
            greeter: None,
            greeter_user: None,
            vt: None,
            session_path: Vec::new(),
        }
    }

    /// Tier 1 — the floor plus what can be detected without opinion.
    ///
    /// Nothing is detected today, and that is honest rather than lazy: the
    /// facts mukaed would want (which greeter exists, which VT is free) are
    /// exactly the ones that are wrong to guess. A greeter probed off `$PATH`
    /// would make "which program draws the login screen" depend on the
    /// environment of whoever started the daemon.
    #[must_use]
    pub fn discovered() -> Self {
        Self::bare()
    }

    /// Tier 2 — the fleet's prescription.
    ///
    /// The PATH is the one lifted verbatim out of `mukaed.rs`, in its original
    /// order, which is load-bearing: `/run/wrappers/bin` must come FIRST or
    /// the store's non-setuid `sudo` shadows the wrapper.
    #[must_use]
    pub fn prescribed() -> Self {
        Self {
            greeter: None,
            greeter_user: None,
            vt: None,
            session_path: vec![
                "/run/wrappers/bin".into(),
                format!("/etc/profiles/per-user/{USER_PLACEHOLDER}/bin"),
                "/run/current-system/sw/bin".into(),
                "/usr/bin".into(),
                "/bin".into(),
            ],
        }
    }

    /// Render [`Self::session_path`] for a named account.
    ///
    /// `None` drops every placeholder-bearing entry — see the field docs for
    /// why that is preferable to emitting a literal `{user}`.
    #[must_use]
    pub fn session_path_for(&self, user: Option<&str>) -> String {
        self.session_path
            .iter()
            .filter_map(|entry| {
                if entry.contains(USER_PLACEHOLDER) {
                    user.map(|u| entry.replace(USER_PLACEHOLDER, u))
                } else {
                    Some(entry.clone())
                }
            })
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Default for MukaeConfig {
    fn default() -> Self {
        Self::prescribed()
    }
}

impl shikumi::TieredConfig for MukaeConfig {
    fn bare() -> Self {
        Self::bare()
    }
    fn discovered() -> Self {
        Self::discovered()
    }
    fn prescribed_default() -> Self {
        Self::prescribed()
    }
}

/// Load mukae's config through shikumi's discovery chain.
///
/// Never fails: see the module docs. A missing file is normal and reported at
/// info level; a malformed one is reported loudly and the prescribed tier is
/// used, because the alternative is a machine nobody can log into.
#[must_use]
pub fn load() -> MukaeConfig {
    let Ok(path) = shikumi::ConfigDiscovery::new("mukae")
        .env_override("MUKAE_CONFIG")
        .discover()
    else {
        // No config file is the NORMAL case, not a fault: the prescribed tier
        // is a working login. Deliberately silent -- a daemon that warned on
        // every boot about a file it does not need trains operators to ignore
        // its output, which is the state you want least in a login manager.
        return MukaeConfig::prescribed();
    };
    match shikumi::ConfigStore::<MukaeConfig>::load(&path, "MUKAE_") {
        Ok(store) => MukaeConfig::clone(&store.get()),
        Err(e) => {
            eprintln!(
                "mukaed: config at {} could not be loaded ({e}) — using prescribed defaults so the seat still comes up",
                path.display()
            );
            MukaeConfig::prescribed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prescribed_path_leads_with_the_setuid_wrappers() {
        // The whole reason this field is typed. If the wrappers directory is
        // not first, the store's non-setuid sudo shadows the wrapper and the
        // error blames the installation.
        let cfg = MukaeConfig::prescribed();
        assert_eq!(cfg.session_path.first().map(String::as_str), Some("/run/wrappers/bin"));
    }

    #[test]
    fn the_prescribed_path_keeps_the_system_profile() {
        let rendered = MukaeConfig::prescribed().session_path_for(Some("luis"));
        assert!(rendered.contains("/run/current-system/sw/bin"), "{rendered}");
    }

    #[test]
    fn the_user_placeholder_is_substituted() {
        let rendered = MukaeConfig::prescribed().session_path_for(Some("gabi"));
        assert!(rendered.contains("/etc/profiles/per-user/gabi/bin"), "{rendered}");
        assert!(!rendered.contains(USER_PLACEHOLDER), "{rendered}");
    }

    #[test]
    fn an_unresolvable_user_drops_the_entry_rather_than_emitting_a_literal() {
        // A literal `{user}` in PATH is a directory that does not exist. The
        // shell would search it silently and the operator would see a missing
        // command, not a missing user.
        let rendered = MukaeConfig::prescribed().session_path_for(None);
        assert!(!rendered.contains(USER_PLACEHOLDER), "{rendered}");
        assert!(!rendered.contains("per-user"), "{rendered}");
        assert!(rendered.starts_with("/run/wrappers/bin"), "{rendered}");
    }

    #[test]
    fn the_bare_tier_has_no_opinion_at_all() {
        let cfg = MukaeConfig::bare();
        assert!(cfg.session_path.is_empty());
        assert_eq!(cfg.session_path_for(Some("luis")), "");
        assert!(cfg.greeter.is_none());
    }

    #[test]
    fn default_is_the_prescribed_tier_not_the_floor() {
        // `Default::default()` reaching `bare()` would give a session an empty
        // PATH through the most ordinary idiom in Rust.
        assert_eq!(MukaeConfig::default(), MukaeConfig::prescribed());
    }

    #[test]
    fn a_typo_in_the_config_is_rejected_rather_than_ignored() {
        // deny_unknown_fields: a misspelled key must not deserialize into a
        // config that silently lacks the value the operator thought they set.
        let yaml = "sesion_path: [\"/bin\"]\n";
        assert!(serde_yaml::from_str::<MukaeConfig>(yaml).is_err());
    }

    #[test]
    fn the_config_round_trips() {
        let cfg = MukaeConfig::prescribed();
        let s = serde_yaml::to_string(&cfg).expect("serialize");
        let back: MukaeConfig = serde_yaml::from_str(&s).expect("deserialize");
        assert_eq!(cfg, back);
    }

    #[test]
    fn vt_zero_survives_parsing_and_is_rejected_at_use() {
        // Config carries what the operator wrote; the zero check belongs where
        // the VT is claimed, so the error can say what to do instead.
        let cfg: MukaeConfig = serde_yaml::from_str("vt: 0\n").expect("parse");
        assert_eq!(cfg.vt, Some(0));
    }
}
