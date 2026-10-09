//! Phase 34.1 - the listening half of a node (ADR-0145).
//!
//! A node behind no NAT, with a public address, can wait for the hub instead of
//! dialling it. Nothing about what a node does changes: the hub still only
//! *proposes*, and the node's own config still decides what is written. Only the
//! direction of the TCP connection does.
//!
//! The listener speaks exactly two requests, both `POST`, both over TLS 1.3 with a
//! certificate the node generated at enrollment and the hub pinned there:
//!
//! * `/node/v1/poll` - the hub asks. The node observes its targets and answers with
//!   the same `Beat` a dialling node would send, signed with its own key.
//! * `/node/v1/act` - the hub answers that beat with the same `BeatReply` a hub
//!   would have sent in reply to a dial. The node takes it exactly as it takes any
//!   reply, which includes the checks on approvals and on its own config.
//!
//! Every request must carry the hub's signature (`x-hub-ts`, `x-hub-sig`) over
//! method, path, a millisecond timestamp and the body hash, under a key delivered
//! at enrollment over the token-authenticated channel. The timestamp must be
//! within a minute of this clock and strictly newer than the last accepted, and
//! that mark is written to disk before the request is handled, so neither a replay
//! nor a restart reopens a window. Any failure is the same bare 401: which check
//! failed is information for whoever is guessing.
//!
//! This is a deliberately small HTTP/1.1 reader rather than a server framework: two
//! routes, headers capped at 16 KiB and bodies at 8 MiB, and no chunked bodies.
//!
//! **A stalled stranger must not lock the hub out.** The first version took one
//! connection at a time, so a client that opened a socket and said nothing held
//! the listener for the whole I/O timeout, and one every ten seconds kept the hub
//! from ever polling. Now each connection is read on its own thread under a hard
//! total deadline, at most [`MAX_CONNECTIONS`] at once (the rest are closed at
//! once), and only a request that passed the hub's signature takes the lock on the
//! agent. Pre-authentication work is the TLS handshake, at most 16 KiB of header
//! and 8 MiB of body, each bounded in time.
//!
//! The cap is generous on purpose: a small one lets a few idle sockets starve the
//! hub (an earlier cap of 16 did, and a test caught it). An attacker who can hold
//! 128 sockets open can still delay a poll, so on a public address the port should
//! be allowed from the hub's address only (a firewall rule, as for SSH); nothing a
//! stranger sends is acted on.

use crate::error::{CliError, CliResult};
use crate::node_agent::{self, Agent};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vault_core::nodes::{verify_hub_request, BeatReply, MAX_CLOCK_SKEW_SECS};
use vault_core::tls::rustls;

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// A connection that has not delivered a whole request by then is dropped, however
/// slowly it trickles: the per-read timeout alone lets a byte every nine seconds
/// hold a thread for ever.
const TOTAL_DEADLINE: Duration = Duration::from_secs(10);
/// Concurrent connections served; more are closed unanswered.
pub const MAX_CONNECTIONS: usize = 128;

/// Serve until `stop`. Returns an error only for something that stops the node
/// listening at all (no certificate, cannot bind).
pub fn serve(agent: &mut Agent, stop: &AtomicBool) -> CliResult {
    let listen = agent
        .state()
        .listen
        .clone()
        .ok_or_else(|| CliError::invalid("This node was not enrolled with --listen"))?;
    let dir = agent.dir().to_path_buf();
    let read = |f: &str| {
        std::fs::read_to_string(dir.join(f))
            .map_err(|e| CliError::from(format!("{}: {e}", dir.join(f).display())))
    };
    let cfg = Arc::new(
        vault_core::tls::server_config_tls13(
            &read(node_agent::TLS_CERT_FILE)?,
            &read(node_agent::TLS_KEY_FILE)?,
        )
        .map_err(CliError::from)?,
    );
    let listener = TcpListener::bind(&listen.bind)
        .map_err(|e| CliError::unavailable(format!("Cannot listen on {}: {e}", listen.bind)))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| CliError::from(e.to_string()))?;
    eprintln!(
        "unv node '{}' listening on {} (the hub dials {}); Ctrl+C to stop.",
        agent.state().name,
        listen.bind,
        listen.advertise
    );
    let agent = Mutex::new(agent);
    let active = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((tcp, peer)) => {
                    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(tcp); // over the limit: closed unanswered
                        continue;
                    }
                    let (cfg, agent, active) = (&cfg, &agent, &active);
                    scope.spawn(move || {
                        if let Err(e) = handle(agent, cfg, tcp) {
                            tracing::warn!(%peer, error = %e, "node listener: request failed");
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => tracing::warn!(error = %e, "node listener: accept failed"),
            }
        }
    });
    Ok(())
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn read_request(tls: &mut impl Read, deadline: Instant) -> Result<Request, u16> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER {
            return Err(431);
        }
        if Instant::now() > deadline {
            return Err(408);
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, path) = (
        first.next().unwrap_or("").to_string(),
        first.next().unwrap_or("").to_string(),
    );
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(400);
    }
    let len: usize = match headers.get("content-length") {
        Some(v) => v.parse().map_err(|_| 400u16)?,
        None => 0,
    };
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        if Instant::now() > deadline {
            return Err(408);
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
        if body.len() > MAX_BODY {
            return Err(413);
        }
    }
    body.truncate(len);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn respond(
    tls: &mut impl Write,
    status: u16,
    extra: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    tls.write_all(head.as_bytes())?;
    tls.write_all(body)?;
    tls.flush()
}

fn error_body(msg: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "error": msg })).unwrap_or_default()
}

/// Checks the hub's signature, skew and replay mark, then advances and persists
/// the mark. `Err` is always the same bare 401.
fn authenticate(agent: &mut Agent, req: &Request) -> Result<(), ()> {
    let ls = agent.state().listen.clone().ok_or(())?;
    let ts: i64 = req
        .headers
        .get("x-hub-ts")
        .and_then(|v| v.parse().ok())
        .ok_or(())?;
    let sig = req.headers.get("x-hub-sig").ok_or(())?;
    if !verify_hub_request(
        &ls.hub_node_pubkey,
        &req.method,
        &req.path,
        ts,
        &req.body,
        sig,
    ) {
        return Err(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    if (now - ts).abs() > MAX_CLOCK_SKEW_SECS * 1000 || ts <= ls.last_hub_ts {
        return Err(());
    }
    // Written before the request is acted on: a crash between the two must not
    // leave the same signed request valid again.
    if let Some(l) = agent.state_mut().listen.as_mut() {
        l.last_hub_ts = ts;
    }
    let dir = agent.dir().to_path_buf();
    node_agent::save_state(&dir, agent.state()).map_err(|_| ())
}

fn handle(
    agent: &Mutex<&mut Agent>,
    cfg: &Arc<rustls::ServerConfig>,
    mut tcp: TcpStream,
) -> Result<(), String> {
    let deadline = Instant::now() + TOTAL_DEADLINE;
    tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
    tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut conn = rustls::ServerConnection::new(cfg.clone()).map_err(|e| e.to_string())?;
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let req = match read_request(&mut tls, deadline) {
        Ok(r) => r,
        Err(code) => {
            let _ = respond(&mut tls, code, &[], &error_body("bad request"));
            return Ok(());
        }
    };
    // Only now, with a whole request in hand, is the agent needed.
    let result = {
        let mut guard = agent
            .lock()
            .map_err(|_| "the agent lock is poisoned".to_string())?;
        route(&mut guard, &req)
    };
    let (status, extra, body) = match result {
        Ok(r) => r,
        Err(code) => (
            code,
            Vec::new(),
            error_body(match code {
                401 => "authentication failed",
                404 => "not found",
                405 => "method not allowed",
                _ => "refused",
            }),
        ),
    };
    respond(&mut tls, status, &extra, &body).map_err(|e| e.to_string())?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

type Reply = (u16, Vec<(&'static str, String)>, Vec<u8>);

fn route(agent: &mut Agent, req: &Request) -> Result<Reply, u16> {
    let known = matches!(req.path.as_str(), "/node/v1/poll" | "/node/v1/act");
    if !known {
        return Err(404);
    }
    if req.method != "POST" {
        return Err(405);
    }
    authenticate(agent, req).map_err(|()| 401u16)?;
    match req.path.as_str() {
        "/node/v1/poll" => {
            let beat = agent.build_beat(0);
            let body = serde_json::to_vec(&beat).map_err(|_| 500u16)?;
            // Signed under the node's own key, for the path a dialling beat uses,
            // so the hub verifies it with the code that verifies every beat.
            let (id, ts, sig) = agent.sign("/api/nodes/beat", &body).map_err(|_| 500u16)?;
            Ok((
                200,
                vec![("x-node-id", id), ("x-node-ts", ts), ("x-node-sig", sig)],
                body,
            ))
        }
        _ => {
            let reply: BeatReply = serde_json::from_slice(&req.body).map_err(|_| 400u16)?;
            match agent.accept_reply(&reply) {
                Ok(()) => Ok((204, Vec::new(), Vec::new())),
                // A different hub approval key than the one pinned.
                Err(e) => Ok((409, Vec::new(), error_body(&e.to_string()))),
            }
        }
    }
}
