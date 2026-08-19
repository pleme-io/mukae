//! The greetd transport — the second producer of mukae's conversation.
//!
//! ── ★ WHY THIS EXISTS ALONGSIDE THE PAM BACKEND, NOT INSTEAD OF IT ────────
//! `mukae-host` talks to libpam directly. That is the destination: mukae owns
//! the whole login, greetd is retired, and nothing foreign sits between a
//! person and their seat. It is not finished — it authenticates and does not
//! open a session (`pending-mukae-session`).
//!
//! greetd already does the parts that are missing, and does them correctly:
//! it runs the PAM stack, manages the VT, drops privileges, and execs the
//! session. What it does NOT own is the face — that is `tuigreet`, a foreign
//! binary you cannot ask what step it is on.
//!
//! So this transport lands the half that is finished. The face, the Nord it is
//! painted in, the masking rules and the introspection socket all become ours
//! today, while greetd keeps the seat mechanics until the PAM backend can take
//! them. One guest instead of two, and the guest that remains is the one whose
//! job we have not yet done.
//!
//! ── ★ WHY `Session` DOES NOT KNOW WHICH BACKEND IT HAS ────────────────────
//! Both produce a [`mukae_spec::bridge::Bridge`]. That type was in the PAM
//! crate and contained no PAM, which is what made this possible without a
//! redesign: it is the CONVERSATION, and libpam and greetd are two ways of
//! having it. The face, the mask decision and the published surface are
//! identical on both paths because they are literally the same code.
//!
//! ── ★ TWO PROTOCOL FACTS THAT ARE NOT GUESSES ─────────────────────────────
//! 1. **The length prefix is NATIVE endian**, not big. kanshou's wire — the
//!    other length-prefixed socket in this program — is big-endian, so writing
//!    one from memory of the other produces a frame greetd reads as a
//!    four-gigabyte message and hangs on. They are different protocols and the
//!    difference is invisible on a little-endian machine only until the frame
//!    is large.
//! 2. **greetd asks for the username up front**, in `create_session`. PAM asks
//!    for it through the conversation like anything else. So this transport
//!    emits a SYNTHETIC first prompt to collect it — see `USERNAME_PROMPT`.
//!    That is the protocol's shape, not an assumption about login screens.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use mukae_spec::bridge::{Bridge, ConvSide};
use mukae_spec::env::{MsgStyle, PamAnswer, PamClass, PamStep, PromptText};

/// The prompt this transport invents to collect a username.
///
/// ★ Marked as synthetic on purpose. Every other prompt a face renders came
/// from an authentication stack; this one came from us, because greetd's
/// `create_session` takes the username as a parameter rather than asking for
/// it. Anyone reading a transcript should be able to tell which is which.
const USERNAME_PROMPT: &str = "login:";

/// The environment variable greetd sets on a greeter it execs.
const SOCK_ENV: &str = "GREETD_SOCK";

// ── THE WIRE ──────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
    CreateSession { username: String },
    PostAuthMessageResponse { response: Option<String> },
    StartSession { cmd: Vec<String>, env: Vec<String> },
    CancelSession,
}

#[derive(serde::Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    Success,
    Error {
        error_type: String,
        description: String,
    },
    AuthMessage {
        auth_message_type: String,
        auth_message: String,
    },
}

/// Write one framed message.
fn send(sock: &mut UnixStream, req: &Request) -> Result<(), String> {
    let body = serde_json::to_vec(req).map_err(|e| format!("encoding a request: {e}"))?;
    let len = u32::try_from(body.len()).map_err(|_| "a request larger than 4GiB".to_string())?;
    // ★ NATIVE endian. See the module header — this is the fact that differs
    // from the other length-prefixed socket in this program.
    sock.write_all(&len.to_ne_bytes())
        .map_err(|e| format!("writing a frame header: {e}"))?;
    sock.write_all(&body)
        .map_err(|e| format!("writing a frame: {e}"))?;
    sock.flush().map_err(|e| format!("flushing: {e}"))
}

/// Read one framed message.
fn recv(sock: &mut UnixStream) -> Result<Response, String> {
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr)
        .map_err(|e| format!("reading a frame header: {e}"))?;
    let len = u32::from_ne_bytes(hdr) as usize;
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)
        .map_err(|e| format!("reading a frame: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("decoding a response: {e}"))
}

// ── THE TRANSPORT ─────────────────────────────────────────────────────────

/// What to run once the person is in.
#[derive(Debug, Clone)]
pub struct SessionCmd {
    pub cmd: Vec<String>,
    pub env: Vec<String>,
}

/// Start a greetd conversation and return the face's half.
///
/// # Errors
/// The reason the socket could not be reached at all. Failures *during* the
/// conversation arrive as a `PamStep::Failed` on the bridge, because the face
/// has to render them and a `Result` would make them a different shape from
/// every other step.
pub fn connect(session: SessionCmd) -> Result<Bridge, String> {
    let path = std::env::var(SOCK_ENV)
        .map_err(|_| format!("{SOCK_ENV} is unset — this is not running under greetd"))?;
    let sock = UnixStream::connect(&path).map_err(|e| format!("connecting to {path}: {e}"))?;

    let (face, conv) = Bridge::new();
    std::thread::spawn(move || run(sock, conv, session));
    Ok(face)
}

/// The worker: greetd's protocol, driven against the conversation channels.
fn run(mut sock: UnixStream, conv: ConvSide, session: SessionCmd) {
    // Step 1 — the synthetic username prompt. greetd needs it before it will
    // start a session, so it cannot come through the auth stack.
    let Ok(answer) = conv.ask(
        MsgStyle::PromptEchoOn,
        PromptText(USERNAME_PROMPT.to_string()),
    ) else {
        // The face vanished before answering. Nothing to authenticate.
        conv.finish(PamStep::Failed {
            class: PamClass::Abort,
        });
        return;
    };
    let username = match answer {
        PamAnswer::Visible(v) => v,
        // A username is not a secret, and this transport must never send one
        // through the field that is. Refusing is the honest outcome: the face
        // routed by MsgStyle and got it wrong, which is a bug to see, not to
        // paper over by exposing a Passphrase.
        PamAnswer::Secret(_) => {
            conv.finish(PamStep::Failed {
                class: PamClass::Abort,
            });
            return;
        }
    };

    if let Err(e) = send(&mut sock, &Request::CreateSession { username }) {
        fail(conv, &mut sock, &e);
        return;
    }

    // Step 2 — pump greetd's messages until it succeeds or refuses.
    loop {
        let resp = match recv(&mut sock) {
            Ok(r) => r,
            Err(e) => {
                fail(conv, &mut sock, &e);
                return;
            }
        };

        match resp {
            Response::AuthMessage {
                auth_message_type,
                auth_message,
            } => {
                let style = match auth_message_type.as_str() {
                    // ★ The mask decision, and the only place it is made on
                    // this path. `secret` is greetd's spelling of echo-off; a
                    // transport that mapped it to anything else would echo a
                    // password, which is the worst bug this program can have.
                    "secret" => MsgStyle::PromptEchoOff,
                    "visible" => MsgStyle::PromptEchoOn,
                    "error" => MsgStyle::ErrorMsg,
                    _ => MsgStyle::TextInfo,
                };

                let reply = match style {
                    MsgStyle::PromptEchoOff | MsgStyle::PromptEchoOn => {
                        match conv.ask(style, PromptText(auth_message)) {
                            Ok(a) => Some(a),
                            Err(_) => {
                                fail(conv, &mut sock, "the face vanished mid-conversation");
                                return;
                            }
                        }
                    }
                    // Info and error want no answer, but greetd still expects
                    // a post_auth_message_response to advance — with a null
                    // response. Skipping it wedges the conversation.
                    _ => {
                        let _ = conv.tell(style, PromptText(auth_message));
                        None
                    }
                };

                let response = reply.map(|a| match a {
                    PamAnswer::Visible(v) => v,
                    // ★ THE ONE PLACE A SECRET LEAVES THE PROGRAM ON THIS
                    // PATH. `expose` is `pub(crate)` to mukae-spec, so this
                    // crate cannot read it — the conversion happens inside the
                    // border via `into_wire`, and the plaintext exists here
                    // only as the String greetd is about to receive.
                    PamAnswer::Secret(s) => mukae_spec::capability::into_wire(s),
                });

                if let Err(e) = send(&mut sock, &Request::PostAuthMessageResponse { response }) {
                    fail(conv, &mut sock, &e);
                    return;
                }
            }

            Response::Success => {
                // ★ Authenticated. NOT yet logged in — greetd will not start
                // anything until it is told to, and a transport that reported
                // Complete here would claim a session that does not exist.
                if let Err(e) = send(
                    &mut sock,
                    &Request::StartSession {
                        cmd: session.cmd.clone(),
                        env: session.env.clone(),
                    },
                ) {
                    fail(conv, &mut sock, &e);
                    return;
                }
                match recv(&mut sock) {
                    // NOW there is a session.
                    Ok(Response::Success) => conv.finish(PamStep::Complete),
                    Ok(Response::Error { description, .. }) => {
                        // The person authenticated and the session would not
                        // start — a machine problem, not a credential one, and
                        // the message says so rather than "login incorrect".
                        let _ = conv.tell(MsgStyle::ErrorMsg, PromptText(description));
                        // `Abort`, not `AuthError`. There is no arm for "the
                        // credentials were fine and the session would not
                        // start", and reaching for AuthError would render as
                        // "login incorrect" — telling someone their password
                        // is wrong when the machine is broken. Abort does not
                        // mislead; the ErrorMsg above carries the detail.
                        conv.finish(PamStep::Failed {
                            class: PamClass::Abort,
                        });
                    }
                    Ok(Response::AuthMessage { .. }) | Err(_) => {
                        conv.finish(PamStep::Failed {
                            class: PamClass::Abort,
                        });
                    }
                }
                return;
            }

            Response::Error {
                error_type,
                description: _,
            } => {
                // ★ The description is DROPPED, deliberately. greetd's PAM
                // stack knows whether the account exists and says so in that
                // string; forwarding it to the screen is a username oracle.
                // The type is enough to tell a wrong password from a broken
                // machine, which is the only distinction a person needs.
                let class = if error_type == "auth_error" {
                    PamClass::AuthError
                } else {
                    PamClass::Abort
                };
                // greetd requires the session be cancelled before another can
                // be created; without this a retry is refused for a reason
                // that looks nothing like the cause.
                let _ = send(&mut sock, &Request::CancelSession);
                conv.finish(PamStep::Failed { class });
                return;
            }
        }
    }
}

/// Report a transport failure and leave greetd in a state a retry can use.
///
/// Takes the `ConvSide` BY VALUE because `finish` consumes it — a terminal
/// step is the last thing this side of the conversation ever says, and the
/// type enforces that rather than trusting the caller not to say more.
fn fail(conv: ConvSide, sock: &mut UnixStream, _why: &str) {
    let _ = send(sock, &Request::CancelSession);
    conv.finish(PamStep::Failed {
        class: PamClass::Abort,
    });
}
