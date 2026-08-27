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
    "mode", "may_drive", "attempts", "failures", "successes", "step", "prompt", "echo",
];

async fn ask(path: Vec<String>) -> String {
    let q = Query {
        path: path.clone(),
        args: vec![],
    };
    let outcome = kanshou::mcp::forward_status(APP, &q, || {
        Err(kanshou::QueryError::unknown_field("no live mukae"))
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
        let src = include_str!("mcp.rs");
        for forbidden in ["fn mukae_type", "fn mukae_key", "fn mukae_click", "fn mukae_do"] {
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
