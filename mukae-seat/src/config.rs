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

/// The placeholder for the authenticated account's home directory.
///
/// Sibling to [`USER_PLACEHOLDER`], and needed for the same reason one level
/// along: two of the six nix profile directories are rooted in `$HOME`, and a
/// systemd `Environment=` line cannot expand `$HOME` — the unit runs as root,
/// so even systemd's `%h` specifier resolves to `/root`. The value is only
/// knowable once PAM has said who logged in, which is precisely where mukaed
/// stands.
pub const HOME_PLACEHOLDER: &str = "{home}";

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

    /// The session's `XDG_DATA_DIRS`, as ordered entries.
    ///
    /// ── ★ WHY A LOGIN MANAGER HAS TO SET THIS AT ALL ─────────────────────
    /// Because nothing else in the chain can. On NixOS the real value is
    /// assembled from `environment.profiles` by `/etc/profile`, which a LOGIN
    /// SHELL sources — and mukaed `execve`s the compositor directly, so the
    /// session and every child it spawns get whatever the unit's
    /// `Environment=` says and nothing more. Measured on plo 2026-09-03: the
    /// live seat's `XDG_DATA_DIRS` was **unset**, while a login shell on the
    /// same machine resolved six profile directories.
    ///
    /// The visible consequence was a launcher with no applications in it.
    /// `tobira`'s discovery is spec-correct — `$XDG_DATA_HOME/applications`
    /// plus each `$XDG_DATA_DIRS` entry — so with the variable unset it fell
    /// back to the freedesktop default (`/usr/local/share:/usr/share`), which
    /// on NixOS holds nothing. The operator's 24 desktop entries, `mado.desktop`
    /// among them, sat in `/etc/profiles/per-user/<user>/share/applications`
    /// and `~/.nix-profile/share/applications` — present, correct, and
    /// unreachable.
    ///
    /// ★ Two of the six entries are per-user, which is why this cannot be a
    /// constant in the unit file and belongs here: the account is not known
    /// until PAM has answered. Same argument as [`Self::session_path`], one
    /// variable along — and the same resolution, so the two cannot drift.
    ///
    /// Entries may carry [`USER_PLACEHOLDER`] or [`HOME_PLACEHOLDER`]; an
    /// entry whose placeholder cannot be resolved is DROPPED rather than
    /// emitted literally, because a search path containing `{home}` is a
    /// directory that does not exist and searching it silently would turn a
    /// resolution failure into a mystery.
    pub session_data_dirs: Vec<String>,
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
            session_data_dirs: Vec::new(),
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
            // ★ THE SAME SIX DIRECTORIES `environment.profiles` NAMES, in
            // NixOS's own order (most specific first), with `/share`
            // appended per `environment.profileRelativeSessionVariables`.
            // Transcribed from the live value a login shell resolves rather
            // than invented, and verified against
            // `nix eval .#nixosConfigurations.plo.config.environment.profiles`.
            //
            // `${XDG_STATE_HOME}/nix/profile` is deliberately ABSENT: NixOS
            // lists it, but it is a shell-expanded duplicate of the
            // `{home}/.local/state/nix/profile` entry below whenever
            // XDG_STATE_HOME is unset (the normal case), and mukaed has no
            // XDG_STATE_HOME to expand at this point anyway.
            session_data_dirs: vec![
                format!("{HOME_PLACEHOLDER}/.nix-profile/share"),
                format!("{HOME_PLACEHOLDER}/.local/state/nix/profile/share"),
                format!("/etc/profiles/per-user/{USER_PLACEHOLDER}/share"),
                "/nix/var/nix/profiles/default/share".into(),
                "/run/current-system/sw/share".into(),
            ],
        }
    }

    /// Render [`Self::session_data_dirs`] for a named account.
    ///
    /// Shares [`Self::session_path_for`]'s shape and its drop-on-unresolved
    /// rule, so the two search paths cannot acquire different semantics.
    #[must_use]
    pub fn session_data_dirs_for(&self, user: Option<&str>, home: Option<&str>) -> String {
        self.session_data_dirs
            .iter()
            .filter_map(|entry| {
                let mut out = entry.clone();
                if out.contains(USER_PLACEHOLDER) {
                    out = out.replace(USER_PLACEHOLDER, user?);
                }
                if out.contains(HOME_PLACEHOLDER) {
                    out = out.replace(HOME_PLACEHOLDER, home?);
                }
                Some(out)
            })
            .collect::<Vec<_>>()
            .join(":")
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

/// The env var naming an explicit config path.
pub const DISCOVERY_VAR: &str = "MUKAE_CONFIG";

/// The prefix under which individual FIELDS may be overridden by env.
///
/// ★ It must not be a prefix of [`DISCOVERY_VAR`] — see the note in [`load`]
/// and the `the_discovery_var_is_not_a_field_override` test, which is the
/// seal rather than the comment.
pub const FIELD_ENV_PREFIX: &str = "MUKAE_OPT_";

/// Load mukae's config through shikumi's discovery chain.
///
/// Never fails: see the module docs. A missing file is normal and reported at
/// info level; a malformed one is reported loudly and the prescribed tier is
/// used, because the alternative is a machine nobody can log into.
#[must_use]
/// WHERE the running configuration came from.
///
/// ★ THIS EXISTS BECAUSE THE DAEMON COULD NOT ANSWER IT. `load()` returns a
/// `MukaeConfig` and nothing else, so "which tier won" was unknowable from
/// outside — and an introspection surface deliberately refused to publish a
/// `config_tier` leaf rather than guess one, since a guessed provenance is
/// indistinguishable from a measured one.
///
/// Three arms, because three things genuinely happen and they mean different
/// things to an operator: no file at all is the NORMAL case, a file that
/// loaded is the interesting one, and a file that FAILED to load is the one
/// worth waking up for — the seat still comes up on prescribed defaults, so
/// nothing else on the machine will ever say the operator's file was ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// No config file was discovered. The prescribed tier is a working login.
    Prescribed,
    /// A file was discovered and loaded.
    File,
    /// A file was discovered and REFUSED; prescribed defaults are in use.
    FileRejected,
}

impl ConfigSource {
    /// A stable name for publishing over an introspection surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prescribed => "prescribed",
            Self::File => "file",
            Self::FileRejected => "file-rejected",
        }
    }
}

/// [`load`], plus where the result came from.
///
/// `load()` is kept as the ergonomic form for every caller that does not care;
/// this is the one that lets the daemon publish an honest `config_source`.
#[must_use]
pub fn load_with_source() -> (MukaeConfig, ConfigSource) {
    let Ok(path) = shikumi::ConfigDiscovery::new("mukae")
        .env_override(DISCOVERY_VAR)
        .discover()
    else {
        return (MukaeConfig::prescribed(), ConfigSource::Prescribed);
    };
    match shikumi::ConfigStore::<MukaeConfig>::load(&path, FIELD_ENV_PREFIX) {
        Ok(store) => (MukaeConfig::clone(&store.get()), ConfigSource::File),
        Err(e) => {
            eprintln!(
                "mukaed: config at {} could not be loaded ({e}) — using prescribed defaults so the seat still comes up",
                path.display()
            );
            (MukaeConfig::prescribed(), ConfigSource::FileRejected)
        }
    }
}

pub fn load() -> MukaeConfig {
    let Ok(path) = shikumi::ConfigDiscovery::new("mukae")
        .env_override(DISCOVERY_VAR)
        .discover()
    else {
        // No config file is the NORMAL case, not a fault: the prescribed tier
        // is a working login. Deliberately silent -- a daemon that warned on
        // every boot about a file it does not need trains operators to ignore
        // its output, which is the state you want least in a login manager.
        return MukaeConfig::prescribed();
    };
    // ── ★ THE FIELD-OVERRIDE PREFIX MUST NOT CONTAIN THE DISCOVERY VAR ──
    // `MUKAE_OPT_`, not `MUKAE_`. shikumi's env layer maps `<PREFIX><FIELD>`
    // onto fields, so with the prefix `MUKAE_` the discovery variable
    // `MUKAE_CONFIG` is itself read as a field named `config` -- which does
    // not exist here, so `deny_unknown_fields` refuses the WHOLE load and
    // this falls back to prescribed defaults with a warning.
    //
    // The documented way to point mukae at a config file was therefore the
    // one way to guarantee it ignored the file.
    //
    // Latent since the surface was written: it fires only when someone
    // actually uses the override, and nobody had. Found 2026-08-28 by RUNNING
    // annai (which had copied this idiom) rather than by reading any of the
    // three copies of it.
    match shikumi::ConfigStore::<MukaeConfig>::load(&path, FIELD_ENV_PREFIX) {
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
        assert_eq!(
            cfg.session_path.first().map(String::as_str),
            Some("/run/wrappers/bin")
        );
    }

    #[test]
    fn the_prescribed_path_keeps_the_system_profile() {
        let rendered = MukaeConfig::prescribed().session_path_for(Some("luis"));
        assert!(
            rendered.contains("/run/current-system/sw/bin"),
            "{rendered}"
        );
    }

    #[test]
    fn the_prescribed_data_dirs_reach_the_per_user_profile() {
        // ★ THE WHOLE POINT, and the row that was missing: `mado.desktop` and
        // 14 of the operator's other entries live in
        // /etc/profiles/per-user/<user>/share/applications. A search path that
        // omits it is a launcher with nothing in it, which is exactly what plo
        // had — the entries were present and correct, and unreachable.
        let d = MukaeConfig::prescribed().session_data_dirs_for(Some("luis"), Some("/home/luis"));
        assert!(
            d.contains("/etc/profiles/per-user/luis/share"),
            "the per-user profile must be searched: {d}"
        );
        assert!(
            d.contains("/home/luis/.nix-profile/share"),
            "the home profile must be searched: {d}"
        );
        assert!(
            d.contains("/run/current-system/sw/share"),
            "the system profile must be searched: {d}"
        );
        assert!(
            !d.contains('{'),
            "no placeholder may survive into the value: {d}"
        );
        // Order is load-bearing the same way PATH's is: freedesktop resolves
        // a duplicate id from the FIRST directory that holds it, so the
        // per-user profile must precede the system one or a user's override
        // of a system entry silently loses.
        let per_user = d.find("/etc/profiles/per-user").unwrap();
        let system = d.find("/run/current-system").unwrap();
        assert!(
            per_user < system,
            "per-user must precede system so an override wins: {d}"
        );
    }

    #[test]
    fn an_unresolvable_placeholder_drops_its_entry_rather_than_emitting_it() {
        // A search path containing a literal `{home}` names a directory that
        // does not exist; searching it silently would turn a resolution
        // failure into a mystery. Same rule as `session_path_for`.
        let cfg = MukaeConfig::prescribed();
        let no_user = cfg.session_data_dirs_for(None, Some("/home/luis"));
        assert!(!no_user.contains("per-user"), "got {no_user}");
        assert!(!no_user.contains('{'), "got {no_user}");
        let no_home = cfg.session_data_dirs_for(Some("luis"), None);
        assert!(!no_home.contains(".nix-profile"), "got {no_home}");
        assert!(!no_home.contains('{'), "got {no_home}");
        // ...but the account-independent entries survive both, so a failed
        // lookup degrades to a usable seat rather than an empty search path.
        assert!(no_user.contains("/run/current-system/sw/share"));
        assert!(no_home.contains("/run/current-system/sw/share"));
    }

    #[test]
    fn the_bare_tier_sets_no_data_dirs_and_that_is_a_choice() {
        // The bare tier deliberately emits nothing, so `mukaed` inserts no
        // XDG_DATA_DIRS at all rather than an empty one — an empty value is
        // NOT the same as unset to freedesktop consumers, which fall back to
        // the spec default only when the variable is absent.
        assert_eq!(
            MukaeConfig::bare().session_data_dirs_for(Some("luis"), Some("/home/luis")),
            ""
        );
    }

    #[test]
    fn the_two_search_paths_resolve_the_same_account() {
        // PATH and XDG_DATA_DIRS both carry a per-user entry, and they are
        // rendered by two functions. If those ever disagreed about whose
        // session this is, the symptom would be a seat that can run a binary
        // it cannot find the launcher entry for.
        let cfg = MukaeConfig::prescribed();
        let p = cfg.session_path_for(Some("luis"));
        let d = cfg.session_data_dirs_for(Some("luis"), Some("/home/luis"));
        assert!(p.contains("/etc/profiles/per-user/luis/bin"));
        assert!(d.contains("/etc/profiles/per-user/luis/share"));
    }

    #[test]
    fn the_user_placeholder_is_substituted() {
        let rendered = MukaeConfig::prescribed().session_path_for(Some("gabi"));
        assert!(
            rendered.contains("/etc/profiles/per-user/gabi/bin"),
            "{rendered}"
        );
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

    #[test]
    fn the_discovery_var_is_not_a_field_override() {
        // THE SEAL for the collision found 2026-08-28. If FIELD_ENV_PREFIX is
        // a prefix of DISCOVERY_VAR, shikumi reads `MUKAE_CONFIG` as a field
        // named `config`; that field does not exist, `deny_unknown_fields`
        // refuses the entire load, and mukae silently falls back to prescribed
        // defaults -- making the documented way to supply a config the one way
        // to guarantee it is ignored.
        //
        // Asserted against the CONSTANTS `load` actually uses, so the two
        // cannot drift apart.
        assert!(
            !DISCOVERY_VAR.starts_with(FIELD_ENV_PREFIX),
            "{DISCOVERY_VAR} is inside the {FIELD_ENV_PREFIX} namespace — \
             the documented config override would disable itself"
        );
    }
}
