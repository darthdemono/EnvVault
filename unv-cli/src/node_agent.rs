//! Phase 34 — the node agent: what runs on the managed host (ADR-0140).
//!
//! It holds no vault key and no token that reads the vault. Its whole identity
//! is an Ed25519 key it generated, whose public half the hub registered at
//! enrollment, and it proves itself by signing every request.
//!
//! What it will do is decided by **its own config file** (`[[target]]`): which
//! paths it may write, which of them it may write at all (`apply`), and the
//! only commands it will ever run (`validate`, `reload`). Whatever the hub
//! sends is checked against that file and ignored if it does not fit.

use crate::error::{CliError, CliResult};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vault_core::nodes::{
    sign_request, Action, ApplyResult, Beat, BeatReply, DriftEvent, HostInfo, NodeConfig, Target,
    TargetReport,
};
use vault_core::nodes_apply::{self, Applied};

const RING: usize = 64;
const MAX_UPLOAD: u64 = 1024 * 1024;
const STATE_FILE: &str = "node-state.json";

/// The agent's persisted identity. 0600: the seed is the node's credential.
#[derive(Serialize, Deserialize, Clone)]
pub struct NodeState {
    pub hub_url: String,
    pub node_id: String,
    pub name: String,
    /// Ed25519 seed, hex.
    pub seed: String,
    /// The hub certificate's SHA-256, pinned at enrollment. `None` for a
    /// loopback plain-HTTP hub.
    pub hub_fingerprint: Option<String>,
    /// The hub's approval-signing key, pinned the first time the hub shows it
    /// over this pinned channel (Phase 37). A different key later is refused.
    #[serde(default)]
    pub hub_pubkey: Option<String>,
    /// Set when this node listens and the hub dials it (Phase 34.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<ListenState>,
}

/// What a listening node needs to remember. 0600 with the rest of the state.
#[derive(Serialize, Deserialize, Clone)]
pub struct ListenState {
    /// Address to bind, e.g. `0.0.0.0:9443`.
    pub bind: String,
    /// The `https://` address the hub was told to use.
    pub advertise: String,
    /// The hub's transport key, delivered at enrollment over the channel the
    /// one-time token authenticates. Everything the hub sends is checked against
    /// it; a different key means a different hub.
    pub hub_node_pubkey: String,
    /// Highest hub timestamp accepted. Persisted, so a restart does not reopen a
    /// replay window.
    #[serde(default)]
    pub last_hub_ts: i64,
}

pub const TLS_CERT_FILE: &str = "node-tls.crt";
pub const TLS_KEY_FILE: &str = "node-tls.key";

pub fn state_path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
}

pub fn default_dir() -> PathBuf {
    if let Ok(d) = std::env::var("UNV_NODE_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("unv-node")
}

pub fn load_state(dir: &Path) -> CliResult<NodeState> {
    let p = state_path(dir);
    let text = std::fs::read_to_string(&p).map_err(|e| {
        CliError::not_found(format!(
            "{}: {e}. Enroll first: `unv node enroll --hub URL --token TOKEN`.",
            p.display()
        ))
    })?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid(format!("{} is not a node state file: {e}", p.display())))
}

pub(crate) fn save_state(dir: &Path, st: &NodeState) -> CliResult {
    use std::io::Write;
    std::fs::create_dir_all(dir).map_err(|e| CliError::from(e.to_string()))?;
    let p = state_path(dir);
    let tmp = p.with_extension("json.tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp).map_err(|e| CliError::from(e.to_string()))?;
    f.write_all(
        serde_json::to_string_pretty(st)
            .map_err(|e| CliError::from(e.to_string()))?
            .as_bytes(),
    )
    .map_err(|e| CliError::from(e.to_string()))?;
    f.sync_all().map_err(|e| CliError::from(e.to_string()))?;
    drop(f);
    std::fs::rename(&tmp, &p).map_err(|e| CliError::from(e.to_string()))
}

/// Plain HTTP is allowed to the loopback only. A node is sent rendered config,
/// which holds secrets, and a signature authenticates a request without hiding
/// it.
pub fn check_transport(url: &str) -> CliResult {
    if url.starts_with("https://") {
        return Ok(());
    }
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        CliError::invalid("The hub URL must start with https:// (or http:// to the loopback)")
    })?;
    let host = rest.split(['/', ':']).next().unwrap_or("");
    if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        Ok(())
    } else {
        Err(CliError::invalid(
            "Refusing plain HTTP to a remote hub: a node is sent rendered config, secrets \
             included. Serve the hub with --tls and pin its certificate.",
        ))
    }
}

/// This machine's name, as best it can be told without a dependency.
pub fn hostname() -> String {
    let h = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    if h.is_empty() {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".into())
    } else {
        h
    }
}

fn host_info(started: Instant) -> HostInfo {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let hostname = hostname();
    let uptime = read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .map_or_else(|| started.elapsed().as_secs(), |f| f as u64);
    HostInfo {
        hostname,
        os: std::env::consts::OS.into(),
        kernel: read("/proc/sys/kernel/osrelease"),
        arch: std::env::consts::ARCH.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: uptime,
    }
}

fn iso_now() -> String {
    vault_core::iso_now()
}

/// `enroll`: spends a token and writes the state file.
pub fn enroll(
    dir: &Path,
    hub: &str,
    token: &str,
    fingerprint: Option<&str>,
    force: bool,
    listen: Option<(&str, &str)>,
) -> CliResult<NodeState> {
    let hub = hub.trim_end_matches('/').to_string();
    check_transport(&hub)?;
    if state_path(dir).exists() && !force {
        return Err(CliError::conflict(format!(
            "{} already exists: this host is enrolled. Revoke the node on the hub, then \
             re-run with --force to replace the identity.",
            state_path(dir).display()
        )));
    }
    if hub.starts_with("https://") && fingerprint.is_none() {
        return Err(CliError::invalid(
            "Name the hub's certificate: --hub-fingerprint SHA256 (what `unv-server --tls` \
             prints), or --tofu to learn it and confirm it by eye.",
        ));
    }
    crate::tls::configure(fingerprint, None)?;
    let (seed, public) = vault_core::nodes::generate_identity();
    // A listening node makes its own certificate and tells the hub which one to
    // pin; the hub learns it from the token-authenticated enrollment, not from
    // whatever answers on the port later.
    let mut listen_body = serde_json::Value::Null;
    if let Some((bind, advertise)) = listen {
        bind.parse::<std::net::SocketAddr>().map_err(|_| {
            CliError::invalid("--listen takes an address like 0.0.0.0:9443 (an IP and a port)")
        })?;
        let host = advertise
            .strip_prefix("https://")
            .unwrap_or("")
            .trim_end_matches('/')
            .rsplit_once(':')
            .map_or_else(
                || {
                    advertise
                        .trim_start_matches("https://")
                        .trim_end_matches('/')
                },
                |(h, _)| h,
            )
            .trim_matches(['[', ']'])
            .to_string();
        let (cert, key, fp) = vault_core::tls::self_signed(vec![host]).map_err(CliError::from)?;
        std::fs::create_dir_all(dir).map_err(|e| CliError::from(e.to_string()))?;
        write_private(&dir.join(TLS_CERT_FILE), cert.as_bytes())?;
        write_private(&dir.join(TLS_KEY_FILE), key.as_bytes())?;
        listen_body = serde_json::json!({ "endpoint": advertise, "cert_sha256": fp });
    }
    let client = crate::tls::build_node_client(Duration::from_secs(30))?;
    let resp = client
        .post(format!("{hub}/api/nodes/enroll"))
        .json(&serde_json::json!({ "token": token, "pubkey": public, "listen": listen_body }))
        .send()
        .map_err(|e| crate::tls::classify_connect_error(&e, &hub))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let msg = body["error"]
            .as_str()
            .unwrap_or("enrollment refused")
            .to_string();
        return Err(if status.as_u16() == 404 {
            CliError::unavailable(
                "The hub answered 404: it was not started with --nodes, or this is not an unv-server."
                    .to_string(),
            )
        } else if status.as_u16() == 401 {
            CliError::denied(msg)
        } else {
            CliError::from(msg)
        });
    }
    let node_id = body["node_id"]
        .as_str()
        .ok_or_else(|| CliError::from("The hub's reply carries no node_id"))?
        .to_string();
    // Cross-check: the certificate the hub says it has is the one we pinned.
    if let (Some(pinned), Some(said)) = (fingerprint, body["hub_fingerprint"].as_str()) {
        if vault_core::tls::normalize_fingerprint(pinned)
            != vault_core::tls::normalize_fingerprint(said)
        {
            return Err(CliError::denied(
                "The hub reports a different certificate fingerprint than the one pinned.",
            ));
        }
    }
    let listen_state = match listen {
        Some((bind, advertise)) => Some(ListenState {
            bind: bind.to_string(),
            advertise: advertise.to_string(),
            hub_node_pubkey: body["hub_node_pubkey"]
                .as_str()
                .filter(|k| k.len() == 64)
                .ok_or_else(|| {
                    CliError::from(
                        "The hub's reply carries no transport key; is it a version that can dial nodes?",
                    )
                })?
                .to_string(),
            last_hub_ts: 0,
        }),
        None => None,
    };
    let st = NodeState {
        hub_url: hub,
        node_id,
        name: body["name"].as_str().unwrap_or("").to_string(),
        seed,
        hub_fingerprint: fingerprint.map(vault_core::tls::normalize_fingerprint),
        hub_pubkey: None,
        listen: listen_state,
    };
    save_state(dir, &st)?;
    Ok(st)
}

fn write_private(path: &Path, bytes: &[u8]) -> CliResult {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| CliError::from(format!("{}: {e}", path.display())))
}

/// The running agent.
pub struct Agent {
    cfg: NodeConfig,
    state: NodeState,
    dir: PathBuf,
    client: reqwest::blocking::Client,
    started: Instant,
    last_ts: i64,
    /// Last hash seen per target, to notice a change between beats.
    seen: HashMap<String, Option<String>>,
    /// Outcome of the last apply per target, reported until the next one.
    last: HashMap<String, (String, Option<String>)>,
    events: Vec<DriftEvent>,
    results: Vec<ApplyResult>,
}

fn push_capped<T>(v: &mut Vec<T>, item: T) {
    if v.len() >= RING {
        v.remove(0);
    }
    v.push(item);
}

impl Agent {
    pub fn new(dir: &Path, config_path: &Path) -> CliResult<Self> {
        let text = std::fs::read_to_string(config_path)
            .map_err(|e| CliError::not_found(format!("{}: {e}", config_path.display())))?;
        let cfg = NodeConfig::parse(&text).map_err(CliError::invalid)?;
        let state = load_state(dir)?;
        check_transport(&state.hub_url)?;
        crate::tls::configure(state.hub_fingerprint.as_deref(), None)?;
        let client = crate::tls::build_node_client(Duration::from_secs(60))?;
        Ok(Self {
            cfg,
            state,
            dir: dir.to_path_buf(),
            client,
            started: Instant::now(),
            last_ts: 0,
            seen: HashMap::new(),
            last: HashMap::new(),
            events: Vec::new(),
            results: Vec::new(),
        })
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.cfg.interval_secs.unwrap_or(60)))
    }

    pub fn state(&self) -> &NodeState {
        &self.state
    }

    /// Hashes every target and notes what changed since last time.
    pub fn observe(&mut self) -> Vec<TargetReport> {
        let mut out = Vec::new();
        for t in &self.cfg.targets {
            let (sha, mut state, mut error) = match nodes_apply::hash_file(&t.path) {
                Ok(Some(h)) => (Some(h), "ok".to_string(), None),
                Ok(None) => (None, "missing".to_string(), None),
                Err(e) => (None, "unreadable".to_string(), Some(e)),
            };
            if let Some(prev) = self.seen.get(&t.id) {
                if prev != &sha {
                    push_capped(
                        &mut self.events,
                        DriftEvent {
                            target: t.id.clone(),
                            at: iso_now(),
                            from: prev.clone(),
                            to: sha.clone(),
                        },
                    );
                }
            }
            self.seen.insert(t.id.clone(), sha.clone());
            if let Some((s, e)) = self.last.get(&t.id) {
                if s == "failed" {
                    state = "failed".into();
                    error = e.clone();
                } else if s == "applied" && sha.is_some() {
                    state = "applied".into();
                }
            }
            out.push(TargetReport {
                id: t.id.clone(),
                project: t.project.clone(),
                exporter: t.exporter.clone(),
                mode: t.mode.clone(),
                apply: t.apply,
                sha256: sha,
                state,
                error,
            });
        }
        out
    }

    fn signed_post(&mut self, path: &str, body: &[u8]) -> CliResult<reqwest::blocking::Response> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        // Strictly increasing even if the clock steps back: the hub rejects a
        // timestamp that is not newer than the last it accepted.
        self.last_ts = now.max(self.last_ts + 1);
        let sig = sign_request(&self.state.seed, "POST", path, self.last_ts, body)
            .map_err(CliError::from)?;
        self.client
            .post(format!("{}{path}", self.state.hub_url))
            .header("content-type", "application/json")
            .header("x-node-id", &self.state.node_id)
            .header("x-node-ts", self.last_ts.to_string())
            .header("x-node-sig", sig)
            .body(body.to_vec())
            .send()
            .map_err(|e| crate::tls::classify_connect_error(&e, &self.state.hub_url))
    }

    /// One heartbeat: report, receive actions, carry them out.
    /// Observes every target and assembles what a heartbeat says. Shared by the
    /// dialling loop and the listener (the hub asks, the node answers with this).
    pub(crate) fn build_beat(&mut self, wait_secs: u32) -> Beat {
        let targets = self.observe();
        Beat {
            host: host_info(self.started),
            targets,
            events: self.events.clone(),
            results: self.results.clone(),
            wait_secs,
        }
    }

    /// Takes the hub's answer to a heartbeat: forgets what it kept, pins its key
    /// and carries out what this node's own config allows.
    pub(crate) fn accept_reply(&mut self, reply: &BeatReply) -> CliResult {
        // Reported once the hub says it kept them; before that they stay, so a
        // locked hub does not lose the record of an apply.
        self.events.clear();
        if reply.results_ack {
            self.results.clear();
        }
        self.pin_hub_key(reply)?;
        self.act(reply);
        Ok(())
    }

    /// Signs a request body the way this node always does, and hands back the
    /// three header values. Strictly increasing, even if the clock steps back.
    pub(crate) fn sign(&mut self, path: &str, body: &[u8]) -> CliResult<(String, String, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        self.last_ts = now.max(self.last_ts + 1);
        let sig = sign_request(&self.state.seed, "POST", path, self.last_ts, body)
            .map_err(CliError::from)?;
        Ok((self.state.node_id.clone(), self.last_ts.to_string(), sig))
    }

    pub(crate) fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn beat_once(&mut self, wait_secs: u32) -> CliResult<BeatReply> {
        let beat = self.build_beat(wait_secs);
        let body = serde_json::to_vec(&beat).map_err(|e| CliError::from(e.to_string()))?;
        let resp = self.signed_post("/api/nodes/beat", &body)?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(CliError::denied(
                "The hub rejected this node: it was revoked, or the key no longer matches. \
                 Re-enroll with a new token.",
            ));
        }
        if !status.is_success() {
            let v: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
            return Err(CliError::unavailable(format!(
                "Hub answered {status}: {}",
                v["error"].as_str().unwrap_or("")
            )));
        }
        let reply: BeatReply = resp
            .json()
            .map_err(|e| CliError::from(format!("Unreadable beat reply: {e}")))?;
        self.accept_reply(&reply)?;
        Ok(reply)
    }

    /// Pins the hub's approval key on first sight, and refuses a different one.
    fn pin_hub_key(&mut self, reply: &BeatReply) -> CliResult {
        let Some(key) = &reply.hub_pubkey else {
            return Ok(());
        };
        match &self.state.hub_pubkey {
            None => {
                self.state.hub_pubkey = Some(key.clone());
                save_state(&self.dir, &self.state)
            }
            Some(pinned) if pinned == key => Ok(()),
            Some(_) => Err(CliError::denied(
                "The hub's approval-signing key changed. A node pins the first one it saw;                  if the hub was rebuilt on purpose, re-enroll this node.",
            )),
        }
    }

    fn nonces_path(&self) -> PathBuf {
        self.dir.join("approvals-seen.json")
    }

    fn seen_nonces(&self) -> Vec<String> {
        std::fs::read_to_string(self.nonces_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn remember_nonce(&self, nonce: &str) {
        let mut seen = self.seen_nonces();
        seen.push(nonce.to_string());
        if seen.len() > 256 {
            seen.drain(..seen.len() - 256);
        }
        if let Ok(text) = serde_json::to_string(&seen) {
            let _ = std::fs::write(self.nonces_path(), text);
        }
    }

    /// Verifies the signed approval a push carries. Returns its nonce.
    fn check_approval(
        &self,
        approval: Option<&vault_core::nodes::SignedApproval>,
        target: &str,
        sha256: &str,
    ) -> Result<String, String> {
        let signed = approval.ok_or("the push carries no approval")?;
        // With `approver` in this node's own config, only a signature from that
        // device counts: the hub's key (pinned or not) is not consulted, so a hub
        // someone else controls cannot approve its own pushes.
        let key = match self.cfg.approver.as_deref() {
            Some(device) => device,
            None => self.state.hub_pubkey.as_deref().ok_or(
                "this node has not yet seen the hub's approval key; it learns it from the next beat",
            )?,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let tok = vault_core::nodes::verify_approval(
            key,
            signed,
            &self.state.node_id,
            target,
            sha256,
            now,
        )?;
        if self.seen_nonces().contains(&tok.nonce) {
            return Err("this approval was already used".into());
        }
        Ok(tok.nonce)
    }

    fn target(&self, id: &str) -> Option<&Target> {
        self.cfg.targets.iter().find(|t| t.id == id)
    }

    fn fail(&mut self, target: &str, sha: &str, error: String) {
        self.last
            .insert(target.to_string(), ("failed".into(), Some(error.clone())));
        push_capped(
            &mut self.results,
            ApplyResult {
                target: target.to_string(),
                at: iso_now(),
                sha256: sha.to_string(),
                ok: false,
                error: Some(error),
            },
        );
    }

    /// Carries out the hub's requests that this node's own config allows.
    pub fn act(&mut self, reply: &BeatReply) {
        for a in &reply.actions {
            match a {
                Action::Push {
                    target,
                    sha256,
                    content_b64,
                    approval,
                } => {
                    let Some(t) = self.target(target).cloned() else {
                        self.fail(
                            target,
                            sha256,
                            "the hub asked for a target this node does not declare".into(),
                        );
                        continue;
                    };
                    // A target that requires approval writes nothing without the
                    // hub's signed yes for exactly these bytes. That setting is in
                    // this host's own config, so the hub cannot turn it off.
                    let mut nonce = None;
                    if t.require_approval {
                        match self.check_approval(approval.as_ref(), target, sha256) {
                            Ok(n) => nonce = Some(n),
                            Err(e) => {
                                self.fail(target, sha256, format!("approval required: {e}"));
                                continue;
                            }
                        }
                    }
                    let bytes = match base64::engine::general_purpose::STANDARD.decode(content_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            self.fail(target, sha256, "push content is not base64".into());
                            continue;
                        }
                    };
                    match nodes_apply::apply(&t, &bytes, sha256, &self.dir) {
                        Ok(applied) => {
                            // Unchanged is success without a result row: nothing
                            // happened, so there is nothing to audit.
                            // The approval is spent by a write, not by an attempt: a
                            // failed validate leaves it usable for the retry.
                            if let Some(n) = &nonce {
                                self.remember_nonce(n);
                            }
                            if applied == Applied::Written {
                                self.last.insert(target.clone(), ("applied".into(), None));
                                push_capped(
                                    &mut self.results,
                                    ApplyResult {
                                        target: target.clone(),
                                        at: iso_now(),
                                        sha256: sha256.clone(),
                                        ok: true,
                                        error: None,
                                    },
                                );
                            }
                        }
                        Err(e) => self.fail(target, sha256, e),
                    }
                }
                Action::Upload { target } => {
                    let Some(t) = self.target(target).cloned() else {
                        continue;
                    };
                    if t.mode != "pull" {
                        continue;
                    }
                    if let Err(e) = self.upload(&t) {
                        self.last
                            .insert(target.clone(), ("failed".into(), Some(e.to_string())));
                    }
                }
            }
        }
    }

    fn upload(&mut self, t: &Target) -> CliResult {
        let len = std::fs::metadata(&t.path)
            .map_err(|e| CliError::from(format!("{}: {e}", t.path.display())))?
            .len();
        if len > MAX_UPLOAD {
            return Err(CliError::invalid(format!(
                "{} is {len} bytes; the pull limit is 1 MiB",
                t.path.display()
            )));
        }
        let bytes = std::fs::read(&t.path)
            .map_err(|e| CliError::from(format!("{}: {e}", t.path.display())))?;
        let body = serde_json::to_vec(&serde_json::json!({
            "target": t.id,
            "content_b64": base64::engine::general_purpose::STANDARD.encode(bytes),
        }))
        .map_err(|e| CliError::from(e.to_string()))?;
        let resp = self.signed_post("/api/nodes/upload", &body)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(CliError::from(format!("Upload refused: {}", resp.status())))
        }
    }

    /// Runs until stopped. Backs off while the hub is unreachable and keeps
    /// observing: drift is buffered, nothing is pushed, nothing is lost.
    pub fn run(&mut self, stop: &std::sync::atomic::AtomicBool) -> CliResult {
        use std::sync::atomic::Ordering;
        let mut backoff = Duration::from_secs(2);
        while !stop.load(Ordering::Relaxed) {
            let t0 = Instant::now();
            let wait = (self.interval().as_secs() as u32 / 2).min(25);
            match self.beat_once(wait) {
                Ok(reply) => {
                    backoff = Duration::from_secs(2);
                    // An apply changes what the next report says; do not make
                    // the hub wait a whole interval to learn it.
                    if !reply.actions.is_empty() {
                        continue;
                    }
                    let left = self.interval().saturating_sub(t0.elapsed());
                    sleep_unless(stop, left);
                }
                Err(e) if e.code == crate::error::Code::Denied => return Err(e),
                Err(e) => {
                    tracing::warn!(error = %e, "beat failed; observing, retrying");
                    // Keep watching local files while the hub is away.
                    let _ = self.observe();
                    sleep_unless(stop, backoff);
                    backoff = (backoff * 2).min(self.interval());
                }
            }
        }
        Ok(())
    }
}

fn sleep_unless(stop: &std::sync::atomic::AtomicBool, d: Duration) {
    use std::sync::atomic::Ordering;
    let end = Instant::now() + d;
    while Instant::now() < end && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200).min(end - Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_for_the_loopback_only() {
        assert!(check_transport("https://hub.example").is_ok());
        assert!(check_transport("http://127.0.0.1:8743").is_ok());
        assert!(check_transport("http://localhost").is_ok());
        assert!(check_transport("http://hub.example").is_err());
        assert!(check_transport("http://10.0.0.5:8743").is_err());
        assert!(check_transport("ftp://x").is_err());
        // A hostname that merely starts like the loopback is not it.
        assert!(check_transport("http://localhost.evil.example").is_err());
    }
}
