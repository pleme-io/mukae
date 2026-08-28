//! The seam between the greeter and the daemon — mukae's own, not greetd's.
//!
//! ── ★ WHY A NEW PROTOCOL AND NOT greetd-ipc ──────────────────────────────
//! `MUKAE.md` §3 settled this: greetd's wire is a *deletable compatibility
//! adapter*, kept so an operator with an existing setup can point it at
//! mukae, and so mukae's faces could drive an upstream greetd while `mukaed`
//! was not yet trusted with root. Both of those are scaffolds. The internal
//! seam is this, and it is typed.
//!
//! The decisive difference from magma-and-Terraform: greetd's protocol has no
//! unrebuildable peer. Both endpoints are ours. Speaking a foreign wire
//! between two of our own processes buys nothing and costs the ability to say
//! what a message means.
//!
//! ── ★ THE PRIVILEGE SPLIT THIS EXISTS TO ENFORCE ─────────────────────────
//! The greeter draws, and drawing means fonts, a terminal, and input parsing
//! — a large surface that must NOT run as root. The daemon holds root and
//! touches none of it. So they are two processes, and everything that crosses
//! between them crosses here, where it can be typed and reviewed.
//!
//! ── ★ THE PLAINTEXT FACT, STATED RATHER THAN HIDDEN ──────────────────────
//! `Frame::Answer` carries a passphrase in the clear when the prompt was a
//! secret one. That is true of every login manager — greetd's wire does the
//! same — and it is bounded by exactly what it must be: a `socketpair(2)`
//! created by the daemon before the fork, never a filesystem path, never a
//! listening socket, never reachable by any process that is not one of these
//! two. It never touches disk and never reaches argv.
//!
//! The alternative — hashing in the greeter — is worse and is the mistake
//! this note exists to forestall: it would put the hash format, the salt, and
//! the shadow file's shape into the unprivileged process, and turn a captured
//! greeter into an offline cracking oracle.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;

use mukae_spec::bridge::{Bridge, ConvSide};
use mukae_spec::env::{MsgStyle, PamAnswer, PamClass, PamStep, PromptText};

/// One message. Both directions in one enum so a mismatched pair is a
/// `serde` error at the boundary rather than a silent misread.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Frame {
    /// daemon → greeter: answer this.
    Prompt {
        /// Whether the face must mask it. Not a free bool — it is
        /// [`MsgStyle::PromptEchoOff`] crossing the wire, and the greeter
        /// routes on it exactly as it would from libpam.
        secret: bool,
        msg: String,
    },
    /// daemon → greeter: show this, expect nothing back.
    Info { msg: String },
    /// daemon → greeter: the conversation ended.
    Outcome { ok: bool },
    /// greeter → daemon: the answer to the last prompt.
    ///
    /// ★ Carries plaintext for a secret prompt. See the module header for the
    /// bound on that, and for why hashing in the greeter would be worse.
    Answer { text: String },
    /// greeter → daemon: the person gave up, or the face died.
    Cancel,
}

/// Length-prefixed frames, u32 big-endian.
///
/// The same framing kanshou uses across the fleet, and big-endian for the same
/// reason: a wire whose length field is native-endian is a wire that works
/// until someone reads it from a different architecture, and then fails in a
/// way that looks like corruption.
fn send(sock: &mut UnixStream, f: &Frame) -> Result<(), String> {
    let body = serde_json::to_vec(f).map_err(|e| format!("encoding a frame: {e}"))?;
    let len = u32::try_from(body.len()).map_err(|_| "frame too large".to_string())?;
    sock.write_all(&len.to_be_bytes())
        .and_then(|()| sock.write_all(&body))
        .map_err(|e| format!("writing a frame: {e}"))
}

fn recv(sock: &mut UnixStream) -> Result<Frame, String> {
    let mut hdr = [0u8; 4];
    sock.read_exact(&mut hdr)
        .map_err(|e| format!("reading a frame header: {e}"))?;
    let len = u32::from_be_bytes(hdr) as usize;
    // A cap, because the peer is a process and processes go wrong. Without it
    // a corrupt header is an allocation the size of whatever those four bytes
    // happened to say.
    if len > 64 * 1024 {
        return Err(format!("frame of {len} bytes is implausible"));
    }
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)
        .map_err(|e| format!("reading a frame body: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("decoding a frame: {e}"))
}

/// **Greeter side.** Turn a socket from the daemon into the [`Bridge`] the
/// face already knows how to drive.
///
/// The face is unchanged: `Session::from_bridge` takes a conversation from
/// anywhere, and this is a third source beside libpam and greetd. That is the
/// abstraction earning its keep rather than being decorative.
///
/// # Errors
/// Only the reason the socket could not be adopted. Failures *during* the
/// conversation arrive as a `PamStep::Failed` on the bridge, because the face
/// has to render them and a `Result` would make them a different shape from
/// every other step.
pub fn connect(sock: UnixStream) -> Result<Bridge, String> {
    let (face, conv) = Bridge::new();
    std::thread::spawn(move || greeter_side(sock, conv));
    Ok(face)
}

fn greeter_side(mut sock: UnixStream, conv: ConvSide) {
    loop {
        let frame = match recv(&mut sock) {
            Ok(f) => f,
            Err(_) => {
                // The daemon went away mid-conversation. That is a real
                // outcome — a supervisor can restart it — and the face must
                // be told rather than left waiting on a channel forever.
                conv.finish(PamStep::Failed {
                    class: PamClass::Abort,
                });
                return;
            }
        };
        match frame {
            Frame::Prompt { secret, msg } => {
                let style = if secret {
                    MsgStyle::PromptEchoOff
                } else {
                    MsgStyle::PromptEchoOn
                };
                let Ok(answer) = conv.ask(style, PromptText(msg)) else {
                    let _ = send(&mut sock, &Frame::Cancel);
                    conv.finish(PamStep::Failed {
                        class: PamClass::Abort,
                    });
                    return;
                };
                let text = match answer {
                    PamAnswer::Visible(v) => v,
                    // ★ The ONE place a secret leaves this process, and it
                    // leaves only because the prompt asked for one. A face
                    // that routed by style and got it wrong is a bug to see,
                    // not to paper over.
                    PamAnswer::Secret(p) => {
                        if !secret {
                            let _ = send(&mut sock, &Frame::Cancel);
                            conv.finish(PamStep::Failed {
                                class: PamClass::Abort,
                            });
                            return;
                        }
                        mukae_spec::capability::expose_authtok_for_transport(&p).to_string()
                    }
                };
                if send(&mut sock, &Frame::Answer { text }).is_err() {
                    conv.finish(PamStep::Failed {
                        class: PamClass::Abort,
                    });
                    return;
                }
            }
            Frame::Info { msg } => {
                let _ = conv.tell(MsgStyle::TextInfo, PromptText(msg));
            }
            Frame::Outcome { ok } => {
                conv.finish(if ok {
                    PamStep::Complete
                } else {
                    PamStep::Failed {
                        class: PamClass::AuthError,
                    }
                });
                return;
            }
            // The daemon does not send these; a peer that does is confused
            // and the honest response is to stop rather than guess.
            Frame::Answer { .. } | Frame::Cancel => {
                conv.finish(PamStep::Failed {
                    class: PamClass::Abort,
                });
                return;
            }
        }
    }
}

/// **Daemon side.** Run one login conversation over the socket against a
/// [`mukae_spec::env::SeatEnv`], returning the handle on success.
///
/// # Errors
/// The reason the conversation could not be completed. A refused login is
/// `Ok(None)` rather than an error: a wrong passphrase is an outcome, not a
/// malfunction, and collapsing the two is how a lockout counter ends up
/// counting broken sockets.
pub fn serve<E: mukae_spec::env::SeatEnv>(
    sock: &mut UnixStream,
    env: &mut E,
    h: mukae_spec::ids::PamHandleId,
) -> Result<Option<()>, String> {
    loop {
        match env.pam_next(h).map_err(|e| format!("{e}"))? {
            PamStep::Prompt { style, msg } => {
                send(
                    sock,
                    &Frame::Prompt {
                        secret: style == MsgStyle::PromptEchoOff,
                        msg: msg.0,
                    },
                )?;
                match recv(sock)? {
                    Frame::Answer { text } => {
                        let a = if style == MsgStyle::PromptEchoOff {
                            PamAnswer::Secret(mukae_spec::capability::Passphrase::new(text))
                        } else {
                            PamAnswer::Visible(text)
                        };
                        env.pam_answer(h, a).map_err(|e| format!("{e}"))?;
                    }
                    Frame::Cancel => return Ok(None),
                    other => return Err(format!("the greeter sent {other:?} to a prompt")),
                }
            }
            PamStep::Info { msg, .. } => send(sock, &Frame::Info { msg: msg.0 })?,
            PamStep::Complete => {
                send(sock, &Frame::Outcome { ok: true })?;
                return Ok(Some(()));
            }
            PamStep::Failed { .. } => {
                // One message for every denial: `class` is recorded, never
                // rendered. Telling the person at the keyboard whether the
                // USER or the PASSPHRASE was wrong is the oracle that turns a
                // guess into an enumeration.
                send(sock, &Frame::Outcome { ok: false })?;
                return Ok(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_round_trips_over_a_socketpair() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        send(
            &mut a,
            &Frame::Prompt {
                secret: true,
                msg: "Password".into(),
            },
        )
        .unwrap();
        match recv(&mut b).unwrap() {
            Frame::Prompt { secret, msg } => {
                assert!(secret, "the mask flag must survive the wire");
                assert_eq!(msg, "Password");
            }
            other => panic!("got {other:?}"),
        }
    }

    /// A corrupt length must be refused rather than allocated.
    #[test]
    fn an_implausible_frame_length_is_refused_not_allocated() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&u32::MAX.to_be_bytes()).unwrap();
        let e = recv(&mut b).unwrap_err();
        assert!(
            e.contains("implausible"),
            "a corrupt header must not become a 4 GiB allocation: {e}"
        );
    }

    #[test]
    fn the_wire_is_big_endian_so_it_cannot_depend_on_the_reader() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        send(&mut a, &Frame::Cancel).unwrap();
        let mut hdr = [0u8; 4];
        b.read_exact(&mut hdr).unwrap();
        assert_eq!(hdr[0], 0, "a small frame must have its high bytes first");
        assert_eq!(hdr[1], 0);
    }
}
