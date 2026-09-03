//! MCP face for mukae — the login screen, OBSERVABLE but never driveable.
//!
//! ── ★ WHY THIS IS READ-ONLY, AND WHY THAT IS A TYPE DECISION ────────────
//! omoya's MCP face ships synthetic keyboard, pointer and click, because
//! driving a desktop session is the whole point of instrumenting it. This
//! file deliberately ships NONE of that, and the asymmetry is the design
//! rather than an omission to be filled in later.
//!
//! A greeter is the authentication boundary. An agent that can type into it
//! is an agent that can attempt logins — at machine speed, against a
//! `failures` counter it can also read, on a host it reached over the
//! network. There is no diagnostic question that requires synthetic input
//! at a login prompt: everything an operator needs to troubleshoot a stuck
//! or misbehaving greeter is a READ (which step is it on, what is it
//! prompting for, is echo off, how many attempts have failed).
//!
//! So the write surface does not exist here. Not gated, not behind a flag,
//! not `may_drive`-checked at runtime — absent, so there is no code path to
//! reach. `mukae`'s own `may_drive` leaf remains READABLE, because whether
//! the greeter believes it may be driven is itself a fact worth
//! diagnosing.
//!
//! ── ★ THE LEAF THAT MATTERS MOST ────────────────────────────────────────
//! `echo`. mukae's own introspect comments say it plainly: a greeter that
//! echoes a password is the single worst bug this program can have. It is
//! exposed here as its own tool rather than buried in a generic read, so
//! that "is the password field masked right now, on the live seat" is one
//! obvious call and not a thing an operator has to know to ask for.
//!
//! ── ★ kotae OUTCOMES ────────────────────────────────────────────────────
//! `blind` (no greeter running) is never rendered as an empty or false
//! reading. "The greeter reports echo = false" and "there is no greeter"
//! must not look alike, least of all on the leaf that guards password
//! masking.

use kanshou::Query;
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;

/// Matches `kanshou::Server::spawn_sidecar("mukae", ...)` in main.rs.
const APP: &str = "mukae";

/// Every leaf `mukae::introspect` answers. Hand-maintained for the same
/// reason as omoya's: kanshou does not dispatch `schema()` over the wire.
const LEAVES: &[&str] = &[
    "mode",
    "may_drive",
    "attempts",
    "failures",
    "successes",
    "step",
    "prompt",
    "echo",
];

async fn ask(path: Vec<String>) -> String {
    let q = Query {
        path: path.clone(),
        args: vec![],
    };
    ask_app(APP, path).await
}

/// The same forward, against a named kanshou app.
///
/// ★ TWO APPS, ONE BINARY, AND THE UID DECIDES WHICH IS REACHABLE. kanshou
/// discovery only walks the CALLING uid's socket directories, so an MCP
/// server run as the greeter user (982) sees `mukae` and an MCP server run as
/// root sees `mukaed` — never both from one process. That is why this file
/// carries two tool families rather than one merged surface: which family
/// answers is a fact about how the server was launched, and pretending
/// otherwise would render "wrong uid" as "nothing is running".
async fn ask_app(app: &'static str, path: Vec<String>) -> String {
    let q = Query {
        path: path.clone(),
        args: vec![],
    };
    let outcome = kanshou::mcp::forward_status(app, &q, || {
        Err(kanshou::QueryError::unknown_field("no live instance"))
    })
    .await;

    match outcome {
        kanshou::mcp::ForwardOutcome::Live { pid, value } => serde_json::json!({
            "outcome": "found",
            "mukae_pid": pid,
            "query": path.join("/"),
            "value": value,
        })
        .to_string(),
        // ★ A LIVE GREETER THAT REFUSED IS NOT BLINDNESS, AND COLLAPSING THE
        // TWO COSTS A DIAGNOSIS. `blind` means nobody answered; this arm means
        // a process answered and said no. Rendering them alike is exactly the
        // defect omoya fixed on 2026-08-28, when `stale_scan` reported "no live
        // omoya" against a compositor that was running perfectly and simply did
        // not know that leaf yet.
        //
        // The pid is what makes it actionable: a refusal from a LIVE pid, on a
        // leaf this binary advertises, means the running greeter is OLDER than
        // the MCP server asking — a version skew, not an absence. Without the
        // pid an operator cannot tell those apart and goes looking for a dead
        // process that is running.
        kanshou::mcp::ForwardOutcome::LiveError { pid, error } => serde_json::json!({
            "outcome": "refused",
            "mukae_pid": pid,
            "query": path.join("/"),
            "because": format!("{error:?}"),
            "legal": LEAVES,
            "hint": "a live greeter refused this leaf. If the leaf is listed in \
                     `legal`, the running greeter predates this MCP server — \
                     compare its build with `mukae --version`.",
        })
        .to_string(),
        _ => serde_json::json!({
            "outcome": "blind",
            "query": path.join("/"),
            "reason": "no live mukae greeter reachable over kanshou on this host",
            "hint": "the greeter runs only while someone is at the login screen; \
                     an active session means there is nothing to observe",
        })
        .to_string(),
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadInput {
    /// The leaf to read. Call `mukae_leaves` for the list.
    pub leaf: String,
}

#[derive(Clone)]
pub struct MukaeMcp {
    tool_router: ToolRouter<Self>,
}

impl Default for MukaeMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl MukaeMcp {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "The whole login state in one call: mode, step, prompt, echo, and the \
                       attempt/failure/success counters. START HERE when a seat is stuck at \
                       login — it distinguishes 'waiting for a password', 'looping on \
                       failures', and 'no greeter running at all'."
    )]
    async fn mukae_login_state(&self) -> String {
        // The empty path is mukae's own full-snapshot leaf.
        ask(vec![String::new()]).await
    }

    #[tool(
        description = "Is the password field masked RIGHT NOW on the live greeter? A greeter \
                       that echoes a password is the worst defect this program can have, so \
                       this is its own tool rather than a generic read. `blind` (no greeter \
                       running) is never rendered as a false reading."
    )]
    async fn mukae_echo(&self) -> String {
        ask(vec!["echo".into()]).await
    }

    #[tool(
        description = "Read one login-flow leaf from the live greeter. READ-ONLY: mukae has no \
                       MCP write surface at all, deliberately — see this module's header."
    )]
    async fn mukae_read(&self, Parameters(input): Parameters<ReadInput>) -> String {
        ask(vec![input.leaf]).await
    }

    #[tool(
        description = "The DAEMON's whole state in one call: the login flow it \
                       republished, the greeter it spawned, the seat and VT it \
                       claimed, who is logged in, and its own uptime. Unlike \
                       the greeter surface this ANSWERS ON A LOGGED-IN SEAT — \
                       mukaed outlives every greeter it spawns. Requires the \
                       MCP server to run as root; mukaed's socket is in \
                       /tmp/kanshou-0."
    )]
    async fn mukaed_state(&self) -> String {
        ask_app("mukaed", vec![String::new()]).await
    }

    #[tool(
        description = "Read ONE leaf from the daemon. Call `mukaed_leaves` for \
                       the list. `coverage` is the high-value one: it answers \
                       which milestone this machine is actually running, as a \
                       query rather than a doc read."
    )]
    async fn mukaed_read(&self, Parameters(input): Parameters<ReadInput>) -> String {
        ask_app("mukaed", vec![input.leaf]).await
    }

    #[tool(description = "List every readable leaf on the daemon.")]
    async fn mukaed_leaves(&self) -> String {
        serde_json::json!({
            "outcome": "found",
            "count": DAEMON_LEAVES.len(),
            "leaves": DAEMON_LEAVES,
            "note": "read-only surface; mukaed exposes no synthetic input over MCP, \
                     and it is the ROOT daemon — the argument against a write \
                     surface at the authentication boundary applies here a fortiori",
        })
        .to_string()
    }

    #[tool(description = "List every readable login-flow leaf.")]
    async fn mukae_leaves(&self) -> String {
        serde_json::json!({
            "outcome": "found",
            "count": LEAVES.len(),
            "leaves": LEAVES,
            "note": "read-only surface; mukae exposes no synthetic input over MCP",
        })
        .to_string()
    }
}

/// Every leaf `mukae_seat::introspect` answers. Mirrors that crate's `LEAVES`
/// for the reason the greeter's list mirrors its own: kanshou does not
/// dispatch `schema()` over the wire. The pair of bidirectional tests lives
/// beside the source of truth, in mukae-seat.
const DAEMON_LEAVES: &[&str] = &[
    "attempts",
    "coverage",
    "drift_keys",
    "echo",
    "failures",
    "greeter_pid",
    "greeter_spawns",
    "greeter_user",
    "last_user",
    "may_drive",
    "mode",
    "prompt",
    "seat",
    "session_open",
    "session_owner",
    "session_data_dirs",
    "session_path",
    "step",
    "successes",
    "uptime_s",
    "version",
    "vt",
];

#[tool_handler]
impl ServerHandler for MukaeMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "mukae (迎え) — the pleme-io login face. OBSERVE ONLY: read which PAM step the \
                 greeter is on, what it is prompting for, whether echo is masked, and the \
                 attempt counters. There is deliberately no synthetic-input surface at the \
                 authentication boundary. `blind` means no greeter is running."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

/// Run the MCP server over stdio. stdout is the JSON-RPC framing channel.
pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let service = MukaeMcp::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The security property this module exists to hold, pinned as a test
    /// rather than left to a comment: no tool name may imply a write.
    #[test]
    fn exposes_no_write_surface() {
        // ★ CUT AT THE TEST BOUNDARY, OR THE SCAN MATCHES ITSELF. The
        // forbidden names below are string literals IN THIS FILE, so scanning
        // the whole of it always finds them and the assertion can never pass.
        //
        // It never did. The `mcp` feature was off by default until 2026-09-02,
        // so this test was never compiled and never ran — a security property
        // pinned by a test that was structurally incapable of going green, and
        // nothing said so. Discovered by turning the feature on.
        //
        // Everything above `#[cfg(test)]` is the shipped surface; everything
        // below is this scanner talking about it.
        let whole = include_str!("mcp.rs");
        let src = whole
            .split_once("#[cfg(test)]")
            .map_or(whole, |(shipped, _)| shipped);
        for forbidden in [
            "fn mukae_type",
            "fn mukae_key",
            "fn mukae_click",
            "fn mukae_do",
        ] {
            assert!(
                !src.contains(forbidden),
                "mukae must expose no synthetic-input tool; found `{forbidden}`"
            );
        }
    }

    #[test]
    fn catalog_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for l in LEAVES {
            assert!(seen.insert(*l), "duplicate leaf: {l}");
        }
    }
}
