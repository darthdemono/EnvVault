//! Phase 34 — Nodes: the protocol, the hub's registry and the node's config.
//!
//! A **hub** is an `unv-server` holding the vault. A **node** is an agent on
//! another host that observes, and when told to, applies config files derived
//! from that vault. This module is everything both ends must agree on; the
//! filesystem side of an apply is in [`crate::nodes_apply`].
//!
//! # What a node is, and is not
//!
//! A node never holds a vault key and never holds a scoped read token. Its
//! identity is an Ed25519 key it generated itself. The hub stores the public
//! half at enrollment and checks a signature on every request, so the hub
//! pins the node's key the way the node pins the hub's certificate (ADR-0140
//! explains why this is request signing and not client certificates).
//!
//! # State is not in the vault
//!
//! The registry is `nodes.json` beside `pools.json`. Heartbeats arrive every
//! minute; putting them through `save_vault` would grow the audit chain without
//! bound (the read-event and pool-cursor mistake, a third time) and turn every
//! beat into a compare-and-swap that can conflict with a human's edit.
//!
//! # Rendered content never touches disk on the hub
//!
//! The registry holds hashes, never file content: a rendered `wg0.conf`
//! contains a private key and `nodes.json` is not encrypted.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// How long an enrollment token lives unless the operator asks otherwise.
pub const ENROLL_TTL_SECS: i64 = 900;
/// A signed request whose timestamp is further than this from the hub's clock
/// is refused. Replays inside the window are stopped by the strictly increasing
/// timestamp, not by the window.
pub const MAX_CLOCK_SKEW_SECS: i64 = 60;
/// Targets one node may declare. A bound, so a hostile beat cannot grow the
/// registry without limit.
pub const MAX_TARGETS: usize = 256;

/// The error `record_beat`'s `desired` callback returns when the hub cannot
/// render at all because the vault is locked. It is not a refusal: the target
/// is simply `unknown` until the hub is unlocked again.
pub const LOCKED: &str = "hub-locked";

/// Exporter names a target may use. `compose-env` is the `.env` Compose
/// substitutes from, which is a separate file and therefore a separate target.
/// True for a built-in exporter name or a stack adapter's (Phase 38).
pub fn valid_exporter(name: &str) -> bool {
    EXPORTERS.contains(&name) || crate::stack::adapter(name).is_some()
}

pub const EXPORTERS: &[&str] = &[
    "wireguard",
    "nginx",
    "apache",
    "haproxy",
    "ansible",
    "postgres",
    "k8s",
    "ssh",
    "traefik",
    "compose",
    "compose-env",
    "env",
];

// ── Identity and request signing ──────────────────────────────────────────────

/// A fresh node identity as `(seed_hex, public_key_hex)`.
pub fn generate_identity() -> (String, String) {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    (hex::encode(seed), hex::encode(public))
}

/// SHA-256 of the raw public key, as hex. What the operator compares.
pub fn key_fingerprint(public_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(public_hex).map_err(|_| "public key is not hex".to_string())?;
    if bytes.len() != 32 {
        return Err("public key must be 32 bytes".into());
    }
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The exact bytes a signature covers. Method and path are inside it so a
/// signature for one route cannot be replayed against another; the body is
/// inside it by hash so the hub never has to re-serialise anything.
fn signing_input(method: &str, path: &str, ts_ms: i64, body: &[u8]) -> Vec<u8> {
    signing_input_for("envv-node-v1", method, path, ts_ms, body)
}

/// The same input under another domain. A hub's request to a node and a node's
/// request to a hub must never be interchangeable, so each direction has its own
/// first line.
fn signing_input_for(domain: &str, method: &str, path: &str, ts_ms: i64, body: &[u8]) -> Vec<u8> {
    format!(
        "{domain}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        ts_ms,
        hex::encode(Sha256::digest(body))
    )
    .into_bytes()
}

/// Signs a request. Returns the signature as hex.
pub fn sign_request(
    seed_hex: &str,
    method: &str,
    path: &str,
    ts_ms: i64,
    body: &[u8],
) -> Result<String, String> {
    let seed: [u8; 32] = hex::decode(seed_hex)
        .map_err(|_| "node key is not hex".to_string())?
        .try_into()
        .map_err(|_| "node key must be 32 bytes".to_string())?;
    let sig = SigningKey::from_bytes(&seed).sign(&signing_input(method, path, ts_ms, body));
    Ok(hex::encode(sig.to_bytes()))
}

/// True only for a valid signature by `public_hex` over exactly this request.
pub fn verify_request(
    public_hex: &str,
    method: &str,
    path: &str,
    ts_ms: i64,
    body: &[u8],
    sig_hex: &str,
) -> bool {
    verify_in(
        "envv-node-v1",
        public_hex,
        method,
        path,
        ts_ms,
        body,
        sig_hex,
    )
}

/// As [`sign_request`], for a hub talking to a node that listens (Phase 34.1).
pub fn sign_hub_request(
    seed_hex: &str,
    method: &str,
    path: &str,
    ts_ms: i64,
    body: &[u8],
) -> Result<String, String> {
    let seed: [u8; 32] = hex::decode(seed_hex)
        .map_err(|_| "hub key is not hex".to_string())?
        .try_into()
        .map_err(|_| "hub key must be 32 bytes".to_string())?;
    let sig = SigningKey::from_bytes(&seed).sign(&signing_input_for(
        "envv-hub-v1",
        method,
        path,
        ts_ms,
        body,
    ));
    Ok(hex::encode(sig.to_bytes()))
}

/// As [`verify_request`], for the hub's requests.
pub fn verify_hub_request(
    public_hex: &str,
    method: &str,
    path: &str,
    ts_ms: i64,
    body: &[u8],
    sig_hex: &str,
) -> bool {
    verify_in(
        "envv-hub-v1",
        public_hex,
        method,
        path,
        ts_ms,
        body,
        sig_hex,
    )
}

fn verify_in(
    domain: &str,
    public_hex: &str,
    method: &str,
    path: &str,
    ts_ms: i64,
    body: &[u8],
    sig_hex: &str,
) -> bool {
    let Ok(pk) = hex::decode(public_hex) else {
        return false;
    };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify(
        &signing_input_for(domain, method, path, ts_ms, body),
        &Signature::from_bytes(&sig),
    )
    .is_ok()
}

// ── Listening nodes (Phase 34.1) ──────────────────────────────────────────────

/// How a hub reaches a node that listens instead of dialling: its address and
/// the SHA-256 of the TLS certificate it generated for that. Recorded at
/// enrollment, over the channel the one-time token already authenticates, and
/// pinned from then on.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ListenInfo {
    pub endpoint: String,
    pub cert_sha256: String,
}

impl ListenInfo {
    /// `https://host[:port]` and nothing else: a path, query, userinfo or
    /// fragment would let an address smuggle something to the hub's client.
    pub fn validate(&self) -> Result<(), String> {
        let rest = self
            .endpoint
            .strip_prefix("https://")
            .ok_or("A listening node must be reachable over https")?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let ok = !rest.is_empty()
            && rest.len() <= 255
            && rest.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
            });
        if !ok {
            return Err("endpoint must be https://host or https://host:port".into());
        }
        if self.cert_sha256.len() != 64 || !self.cert_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("cert_sha256 must be 64 hex characters".into());
        }
        Ok(())
    }

    /// The endpoint without a trailing slash.
    pub fn base(&self) -> &str {
        self.endpoint.strip_suffix('/').unwrap_or(&self.endpoint)
    }
}

// ── Wire types ────────────────────────────────────────────────────────────────

/// One target as the node reports it. Hash and state only; never content.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetReport {
    pub id: String,
    pub project: String,
    pub exporter: String,
    /// `push` (vault to file) or `pull` (file to vault).
    pub mode: String,
    /// Whether this node will write the file. Declared by the operator in the
    /// node's own config; the hub cannot change it.
    pub apply: bool,
    /// SHA-256 of the file on disk, or `None` when it does not exist.
    pub sha256: Option<String>,
    /// `ok`, `missing`, `unreadable`, `applied`, `failed`.
    pub state: String,
    pub error: Option<String>,
}

/// A change the node saw between two beats (hub down, or locked).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DriftEvent {
    pub target: String,
    pub at: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// The outcome of one apply, reported on the next beat. The hub turns each into
/// an audit row; heartbeats themselves write nothing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApplyResult {
    pub target: String,
    pub at: String,
    pub sha256: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub version: String,
    pub uptime_secs: u64,
}

/// The heartbeat. No IP address: the hub has the socket where it needs one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Beat {
    pub host: HostInfo,
    pub targets: Vec<TargetReport>,
    #[serde(default)]
    pub events: Vec<DriftEvent>,
    #[serde(default)]
    pub results: Vec<ApplyResult>,
    /// Seconds the node is willing to wait for the hub to answer. The hub
    /// holds the request open this long when it has nothing to say, so a vault
    /// save reaches the node in about a second instead of one interval.
    #[serde(default)]
    pub wait_secs: u32,
}

/// Something the hub asks a node to do.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Write these bytes to a push target whose `apply` is true. `sha256` is
    /// what the node must recompute and compare before it writes anything.
    Push {
        target: String,
        sha256: String,
        content_b64: String,
        /// The hub's signed statement that a human approved exactly these bytes
        /// for this node and target (Phase 37). Absent when the node needs none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval: Option<SignedApproval>,
    },
    /// Send the content of a pull target once. Requested by a human.
    Upload { target: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct BeatReply {
    pub interval_secs: u32,
    /// True when the hub could not render (vault locked). Observe goes on; push
    /// idles.
    pub hub_locked: bool,
    /// True when the hub recorded the `results` of this beat. A hub that cannot
    /// (locked, so the audit chain is closed) says false and the node sends
    /// them again; clearing them on a reply that did not keep them would lose
    /// the only record that an apply happened.
    #[serde(default)]
    pub results_ack: bool,
    pub actions: Vec<Action>,
    /// Pushes the hub is holding for a human (Phase 37). Informational: the
    /// node shows them, and nothing about them is a command.
    #[serde(default)]
    pub pending: Vec<PendingNote>,
    /// The hub's approval-signing public key (Phase 37). A node pins the first
    /// one it sees over its pinned TLS channel and refuses a different one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_pubkey: Option<String>,
}

// ── The node's own config ─────────────────────────────────────────────────────

/// One `[[target]]` in the node's config. Everything executable is here, on
/// this host, written by the operator. Nothing the hub sends can add to it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub path: PathBuf,
    pub project: String,
    pub exporter: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Observe until deliberately flipped.
    #[serde(default)]
    pub apply: bool,
    pub validate: Option<String>,
    pub reload: Option<String>,
    /// Refuse any push that does not carry the hub's signed approval of exactly
    /// these bytes (Phase 37). Set here, on the host, so a hub bug or a hub
    /// policy change cannot turn it off.
    #[serde(default)]
    pub require_approval: bool,
}

fn default_mode() -> String {
    "push".into()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Seconds between beats when the hub has nothing to say. 10 to 3600.
    pub interval_secs: Option<u32>,
    #[serde(default, rename = "target")]
    pub targets: Vec<Target>,
    /// The public key (hex) of the device whose signature this node accepts as a
    /// human's approval (Phase 37.1). When set, a push that needs approval must
    /// carry a token signed by this key; the hub's own key no longer counts, so a
    /// hub that has been taken over cannot approve its own pushes.
    #[serde(default)]
    pub approver: Option<String>,
}

/// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`
pub fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

fn valid_command(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 512 && !s.contains('\0')
}

impl NodeConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        let cfg: NodeConfig = toml::from_str(text).map_err(|e| format!("node config: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(i) = self.interval_secs {
            if !(10..=3600).contains(&i) {
                return Err("interval_secs must be between 10 and 3600".into());
            }
        }
        if let Some(a) = &self.approver {
            let ok = a.len() == 64
                && hex::decode(a)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .is_some_and(|b| VerifyingKey::from_bytes(&b).is_ok());
            if !ok {
                return Err("approver must be a 64-character hex Ed25519 public key".into());
            }
        }
        if self.targets.len() > MAX_TARGETS {
            return Err(format!("at most {MAX_TARGETS} targets"));
        }
        let mut seen = HashSet::new();
        for t in &self.targets {
            if !valid_id(&t.id) {
                return Err(format!(
                    "target id '{}' must be letters, digits, '_', '.' or '-' (max 63)",
                    t.id
                ));
            }
            if !seen.insert(t.id.clone()) {
                return Err(format!("target id '{}' is used twice", t.id));
            }
            // has_root: "/etc/x" is rooted but not absolute on Windows (no drive), and is still unambiguous on the current drive.
            if !(t.path.is_absolute() || t.path.has_root()) {
                return Err(format!("target '{}': path must be absolute", t.id));
            }
            if t.path.to_string_lossy().contains('\0') {
                return Err(format!("target '{}': path contains NUL", t.id));
            }
            if t.project.trim().is_empty() {
                return Err(format!("target '{}': project is empty", t.id));
            }
            if !valid_exporter(&t.exporter) {
                return Err(format!(
                    "target '{}': unknown exporter '{}'. Supported: {}",
                    t.id,
                    t.exporter,
                    EXPORTERS
                        .iter()
                        .copied()
                        .chain(crate::stack::adapters().iter().map(|a| a.id.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if t.mode != "push" && t.mode != "pull" {
                return Err(format!(
                    "target '{}': mode must be \"push\" or \"pull\"",
                    t.id
                ));
            }
            // A pull target's file is the source of truth. Letting the hub
            // write it would make "pull" mean its opposite.
            if t.mode == "pull"
                && (t.apply || t.validate.is_some() || t.reload.is_some() || t.require_approval)
            {
                return Err(format!(
                    "target '{}': a pull target is only read, so apply, validate, reload and require_approval do not belong on it",
                    t.id
                ));
            }
            for (name, v) in [("validate", &t.validate), ("reload", &t.reload)] {
                if let Some(c) = v {
                    if !valid_command(c) {
                        return Err(format!("target '{}': {name} is empty or too long", t.id));
                    }
                }
            }
        }
        Ok(())
    }
}

// ── The hub's registry ────────────────────────────────────────────────────────

/// What the hub knows about one target on one node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetStatus {
    pub id: String,
    pub project: String,
    pub exporter: String,
    pub mode: String,
    pub apply: bool,
    pub reported_sha: Option<String>,
    /// What the hub would write now. `None` when it could not render (locked,
    /// unknown project, or the config check failed).
    pub desired_sha: Option<String>,
    /// For a pull target: the hash a human last accepted into the vault.
    pub accepted_sha: Option<String>,
    pub state: String,
    pub error: Option<String>,
    /// `in_sync`, `drift`, `pending`, `missing`, `changed`, `unreviewed`,
    /// `unknown`, `refused`.
    pub status: String,
    /// Why the hub withheld a push, when `status` is `refused`.
    pub refusal: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NodeRecord {
    pub id: String,
    pub name: String,
    pub pubkey: String,
    pub fingerprint: String,
    /// Projects this node may be sent. Set by the operator when minting the
    /// token; a node cannot widen it by declaring a target.
    pub projects: Vec<String>,
    pub enrolled_at: String,
    pub last_seen: Option<String>,
    /// Highest request timestamp accepted. Persisted so a restart does not
    /// reopen the replay window.
    pub last_ts_ms: i64,
    pub revoked_at: Option<String>,
    pub host: Option<HostInfo>,
    pub targets: Vec<TargetStatus>,
    /// `required` holds every push to this node for a human (Phase 37); empty or
    /// `none` pushes as soon as a node's own config allows it.
    #[serde(default)]
    pub approval: String,
    /// Set when the node listens and the hub dials it (Phase 34.1). Absent for a
    /// node that dials the hub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<ListenInfo>,
    /// When the hub last polled this node, for a listening node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_polled: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TokenRecord {
    /// SHA-256 of the token. The plaintext is shown once and never stored.
    hash: String,
    name: String,
    projects: Vec<String>,
    expires_at_secs: i64,
    used: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    tokens: Vec<TokenRecord>,
    #[serde(default)]
    nodes: Vec<NodeRecord>,
    #[serde(default)]
    approvals: Vec<ApprovalRecord>,
    /// The hub's transport signing seed for listening nodes (Phase 34.1), created
    /// on first use. It lives here, not in the vault, so a locked hub can still
    /// poll (observation continues); pushes still need the unlocked vault.
    #[serde(default)]
    hub_node_seed: String,
    /// Devices whose signature counts as the owner's approval (Phase 37.1).
    #[serde(default)]
    approvers: Vec<Approver>,
}

#[derive(Debug, PartialEq)]
pub enum AuthError {
    UnknownNode,
    Revoked,
    BadSignature,
    Skew,
    Replay,
}

impl AuthError {
    pub fn message(&self) -> &'static str {
        match self {
            AuthError::UnknownNode | AuthError::BadSignature => "Node authentication failed",
            AuthError::Revoked => "This node has been revoked",
            AuthError::Skew => "Request timestamp is outside the allowed clock skew",
            AuthError::Replay => "Request timestamp is not newer than the last one accepted",
        }
    }
}

pub struct NodeStore {
    path: PathBuf,
    data: StoreFile,
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Writes `bytes` to `path` through a temp file, 0600 on Unix.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

impl NodeStore {
    /// Opens the registry, empty when the file does not exist. A file that
    /// exists and does not parse is an error, not an empty registry: silently
    /// forgetting every enrolled node would re-open every enrollment token.
    pub fn open(path: &Path) -> Result<Self, String> {
        let data = match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t)
                .map_err(|e| format!("{} is not a valid node registry: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreFile::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            data,
        })
    }

    fn save(&self) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(&self.data).map_err(|e| e.to_string())?;
        write_private(&self.path, &text)
    }

    /// Mints a single-use enrollment token. Returns the plaintext once.
    pub fn mint_token(
        &mut self,
        name: &str,
        projects: Vec<String>,
        ttl_secs: i64,
        now_secs: i64,
    ) -> Result<(String, i64), String> {
        if !valid_id(name) {
            return Err("node name must be letters, digits, '_', '.' or '-' (max 63)".into());
        }
        if projects.is_empty() {
            return Err("name at least one project this node may receive".into());
        }
        if self
            .data
            .nodes
            .iter()
            .any(|n| n.name == name && n.revoked_at.is_none())
        {
            return Err(format!("a node named '{name}' is already enrolled"));
        }
        let ttl = ttl_secs.clamp(30, 7 * 86_400);
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = format!("envn_{}", hex::encode(raw));
        let expires = now_secs + ttl;
        // Expired and spent tokens are dead weight; dropping them here keeps
        // the file from growing with every enrollment ever attempted.
        self.data
            .tokens
            .retain(|t| !t.used && t.expires_at_secs > now_secs);
        self.data.tokens.push(TokenRecord {
            hash: token_hash(&token),
            name: name.to_string(),
            projects,
            expires_at_secs: expires,
            used: false,
        });
        self.save()?;
        Ok((token, expires))
    }

    /// Spends a token and registers the node's public key.
    pub fn enroll(
        &mut self,
        token: &str,
        pubkey_hex: &str,
        listen: Option<ListenInfo>,
        now_secs: i64,
        now_iso: &str,
    ) -> Result<NodeRecord, String> {
        if let Some(l) = &listen {
            l.validate()?;
        }
        let fingerprint = key_fingerprint(pubkey_hex)?;
        // A point that is not on the curve can never verify, and storing it
        // would make the node permanently unable to authenticate.
        let raw: [u8; 32] = hex::decode(pubkey_hex)
            .map_err(|_| "public key is not hex".to_string())?
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        VerifyingKey::from_bytes(&raw).map_err(|_| "public key is not a valid Ed25519 key")?;

        let h = token_hash(token);
        let rec = self
            .data
            .tokens
            .iter_mut()
            .find(|t| t.hash == h)
            .ok_or("Invalid or expired enrollment token")?;
        // One message for every way a token can be bad: which one it was is
        // information for whoever is guessing.
        if rec.used || rec.expires_at_secs <= now_secs {
            return Err("Invalid or expired enrollment token".into());
        }
        rec.used = true;
        let node = NodeRecord {
            id: crate::new_uuid(),
            name: rec.name.clone(),
            pubkey: pubkey_hex.to_ascii_lowercase(),
            fingerprint,
            projects: rec.projects.clone(),
            enrolled_at: now_iso.to_string(),
            last_seen: None,
            last_ts_ms: 0,
            revoked_at: None,
            host: None,
            targets: Vec::new(),
            approval: String::new(),
            listen,
            last_polled: None,
        };
        self.data.nodes.push(node.clone());
        self.save()?;
        Ok(node)
    }

    /// Checks a signed request and, on success, advances the node's replay mark.
    pub fn authenticate(
        &mut self,
        node_id: &str,
        method: &str,
        path: &str,
        ts_ms: i64,
        body: &[u8],
        sig_hex: &str,
        now_ms: i64,
    ) -> Result<NodeRecord, AuthError> {
        let node = self
            .data
            .nodes
            .iter_mut()
            .find(|n| n.id == node_id)
            .ok_or(AuthError::UnknownNode)?;
        // Signature first: skew, replay and revocation are only worth telling
        // to somebody who holds the key.
        if !verify_request(&node.pubkey, method, path, ts_ms, body, sig_hex) {
            return Err(AuthError::BadSignature);
        }
        if node.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        if (now_ms - ts_ms).abs() > MAX_CLOCK_SKEW_SECS * 1000 {
            return Err(AuthError::Skew);
        }
        if ts_ms <= node.last_ts_ms {
            return Err(AuthError::Replay);
        }
        node.last_ts_ms = ts_ms;
        let out = node.clone();
        // Best effort: failing to persist the mark must not drop a beat, but
        // the in-memory mark still stops replays until a restart.
        let _ = self.save();
        Ok(out)
    }

    /// The hub's transport key for listening nodes as `(seed, public)`, made on
    /// first use.
    pub fn hub_node_key(&mut self) -> Result<(String, String), String> {
        if self.data.hub_node_seed.is_empty() {
            self.data.hub_node_seed = generate_hub_seed();
            self.save()?;
        }
        let public = hub_public(&self.data.hub_node_seed)?;
        Ok((self.data.hub_node_seed.clone(), public))
    }

    /// Active nodes the hub has to dial.
    pub fn listening(&self) -> Vec<NodeRecord> {
        self.data
            .nodes
            .iter()
            .filter(|n| n.listen.is_some() && n.revoked_at.is_none())
            .cloned()
            .collect()
    }

    /// Notes that the hub polled `id` just now.
    pub fn mark_polled(&mut self, id: &str, now_iso: &str) {
        if let Some(n) = self.data.nodes.iter_mut().find(|n| n.id == id) {
            n.last_polled = Some(now_iso.to_string());
            let _ = self.save();
        }
    }

    pub fn list(&self) -> Vec<NodeRecord> {
        self.data.nodes.clone()
    }

    pub fn get(&self, id: &str) -> Option<NodeRecord> {
        self.data.nodes.iter().find(|n| n.id == id).cloned()
    }

    /// Finds an active node by name or id.
    pub fn find(&self, name_or_id: &str) -> Option<NodeRecord> {
        self.data
            .nodes
            .iter()
            .find(|n| n.revoked_at.is_none() && (n.id == name_or_id || n.name == name_or_id))
            .cloned()
    }

    pub fn revoke(&mut self, id: &str, now_iso: &str) -> Result<NodeRecord, String> {
        let n = self
            .data
            .nodes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or("No such node")?;
        if n.revoked_at.is_none() {
            n.revoked_at = Some(now_iso.to_string());
        }
        let out = n.clone();
        self.save()?;
        Ok(out)
    }

    /// Replaces a node's observed state from a beat. `desired` is what the hub
    /// would write for each target id (`Ok(sha)`), or why it will not (`Err`).
    pub fn record_beat(
        &mut self,
        id: &str,
        beat: &Beat,
        desired: &dyn Fn(&TargetReport) -> Result<String, String>,
        now_iso: &str,
    ) -> Result<(), String> {
        let now_secs = unix_now();
        let approvals: Vec<ApprovalRecord> = self.data.approvals.clone();
        let node = self
            .data
            .nodes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or("No such node")?;
        if beat.targets.len() > MAX_TARGETS {
            return Err(format!("at most {MAX_TARGETS} targets"));
        }
        let accepted: Vec<(String, String)> = node
            .targets
            .iter()
            .filter_map(|t| t.accepted_sha.clone().map(|a| (t.id.clone(), a)))
            .collect();
        let requires_approval = matches!(node.approval.as_str(), "required" | "device");
        let mut out = Vec::new();
        for r in &beat.targets {
            if !valid_id(&r.id) || !valid_exporter(&r.exporter) {
                continue;
            }
            let accepted_sha = accepted
                .iter()
                .find(|(i, _)| i == &r.id)
                .map(|(_, a)| a.clone());
            let (desired_sha, refusal) = if r.mode == "push" {
                if !node.projects.iter().any(|p| p == &r.project) {
                    (
                        None,
                        Some(format!(
                            "node '{}' was not enrolled for project '{}'",
                            node.name, r.project
                        )),
                    )
                } else {
                    match desired(r) {
                        Ok(s) => (Some(s), None),
                        Err(e) if e == LOCKED => (None, None),
                        Err(e) => (None, Some(e)),
                    }
                }
            } else {
                (None, None)
            };
            let mut status =
                derive_status(r, desired_sha.as_deref(), accepted_sha.as_deref(), &refusal);
            // A push that is ready to go is held for a human when the node needs one.
            if status == "pending" && requires_approval {
                if let Some(d) = desired_sha.as_deref() {
                    status = approval_status(&approvals, id, &r.id, d, now_secs).into();
                }
            }
            out.push(TargetStatus {
                id: r.id.clone(),
                project: r.project.clone(),
                exporter: r.exporter.clone(),
                mode: r.mode.clone(),
                apply: r.apply,
                reported_sha: r.sha256.clone(),
                desired_sha,
                accepted_sha,
                state: r.state.clone(),
                error: r.error.clone(),
                status,
                refusal,
            });
        }
        node.targets = out;
        node.host = Some(beat.host.clone());
        node.last_seen = Some(now_iso.to_string());
        // An approved push whose bytes the node now reports has done its job; one
        // nobody acted on in time, or a request nobody answered, lapses.
        for a in self.data.approvals.iter_mut().filter(|a| a.node_id == id) {
            let applied = beat
                .targets
                .iter()
                .any(|r| r.id == a.target && r.sha256.as_deref() == Some(a.sha256.as_str()));
            match a.status.as_str() {
                "approved" if applied => a.status = "consumed".into(),
                "approved" if now_secs >= a.decided_secs.unwrap_or(0) + APPROVAL_TTL_SECS => {
                    a.status = "expired".into()
                }
                "pending" if now_secs >= a.requested_secs + PENDING_TTL_SECS => {
                    a.status = "expired".into()
                }
                _ => {}
            }
        }
        self.save()
    }

    /// Records the hash a human accepted into the vault for a pull target.
    pub fn accept(&mut self, id: &str, target: &str) -> Result<String, String> {
        let node = self
            .data
            .nodes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or("No such node")?;
        let t = node
            .targets
            .iter_mut()
            .find(|t| t.id == target)
            .ok_or("No such target on this node")?;
        if t.mode != "pull" {
            return Err("Only a pull target has something to accept".into());
        }
        let sha = t
            .reported_sha
            .clone()
            .ok_or("The file does not exist on the node, so there is nothing to accept")?;
        t.accepted_sha = Some(sha.clone());
        t.status = "in_sync".into();
        self.save()?;
        Ok(sha)
    }
}

/// The one place a target's status word is decided.
pub fn derive_status(
    r: &TargetReport,
    desired: Option<&str>,
    accepted: Option<&str>,
    refusal: &Option<String>,
) -> String {
    if r.mode == "pull" {
        return match (r.sha256.as_deref(), accepted) {
            (None, _) => "missing",
            (Some(_), None) => "unreviewed",
            (Some(a), Some(b)) if a == b => "in_sync",
            _ => "changed",
        }
        .into();
    }
    if refusal.is_some() {
        return "refused".into();
    }
    match (r.sha256.as_deref(), desired) {
        (_, None) => "unknown",
        (None, Some(_)) => {
            if r.apply {
                "pending"
            } else {
                "missing"
            }
        }
        (Some(a), Some(d)) if a == d => "in_sync",
        (Some(_), Some(_)) => {
            if r.apply {
                "pending"
            } else {
                "drift"
            }
        }
    }
    .into()
}

// ── Approval (Phase 37, ADR-0143) ─────────────────────────────────────────────

/// How long an approved push stays valid, and so how long its signed token does.
pub const APPROVAL_TTL_SECS: i64 = 3600;
/// How long a request waits for a human before it lapses.
pub const PENDING_TTL_SECS: i64 = 7 * 86_400;

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// A request for a human to say yes to these exact bytes for this node target.
/// Holds hashes and snapshot numbers, never content: the content is in the
/// config history, where the human reads it as a diff.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApprovalRecord {
    pub id: String,
    pub node_id: String,
    pub target: String,
    pub project: String,
    pub exporter: String,
    /// SHA-256 of the proposed file. The approval is for this and nothing else.
    pub sha256: String,
    /// What the node reported having when the request was made.
    pub from_sha: Option<String>,
    /// History snapshot of the file the node has (when known) and of the proposal.
    pub from_seq: Option<i64>,
    pub to_seq: Option<i64>,
    pub requested_at: String,
    pub requested_secs: i64,
    /// `pending`, `approved`, `rejected`, `consumed`, `expired`.
    pub status: String,
    pub decided_at: Option<String>,
    pub decided_secs: Option<i64>,
    pub decided_by: Option<String>,
    /// Set when the yes was signed on the owner's own device (Phase 37.1); the
    /// hub then sends exactly this and never signs an approval itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedApproval>,
}

/// A device whose signature counts as the owner's approval (Phase 37.1, ADR-0147).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Approver {
    pub pubkey: String,
    pub fingerprint: String,
    pub label: String,
    pub added: String,
}

/// A held push, as told to the node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PendingNote {
    pub target: String,
    pub sha256: String,
    pub status: String,
    pub approval_id: String,
}

/// What the hub signs when a human approves. Canonical JSON is signed as text,
/// so there is nothing to re-serialise on the verifying side.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApprovalToken {
    pub v: u8,
    pub node_id: String,
    pub target: String,
    pub sha256: String,
    pub approval_id: String,
    pub approved_by: String,
    pub approved_at: String,
    pub expires_secs: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignedApproval {
    /// The token as JSON text; the signature covers exactly these bytes.
    pub token: String,
    pub sig: String,
}

fn approval_input(token_json: &str) -> Vec<u8> {
    format!("envv-approval-v1\n{token_json}").into_bytes()
}

/// The public key for a hub's approval-signing seed.
pub fn hub_public(seed_hex: &str) -> Result<String, String> {
    let seed: [u8; 32] = hex::decode(seed_hex)
        .map_err(|_| "hub key is not hex".to_string())?
        .try_into()
        .map_err(|_| "hub key must be 32 bytes".to_string())?;
    Ok(hex::encode(
        SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    ))
}

/// A fresh hub approval seed, hex.
pub fn generate_hub_seed() -> String {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    hex::encode(seed)
}

/// The hub's approval-signing seed, created on first use. It lives in the vault's
/// own encrypted `vault_meta` (as the unique-ID registry's secrets do), so a
/// copy of `nodes.json` is not enough to forge an approval.
pub fn hub_seed(conn: &rusqlite::Connection) -> Result<String, String> {
    use rusqlite::OptionalExtension;
    let have: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'node_hub_seed'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(s) = have {
        return Ok(s);
    }
    let seed = generate_hub_seed();
    conn.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('node_hub_seed', ?1)",
        [&seed],
    )
    .map_err(|e| e.to_string())?;
    // Two first uses can race; whichever insert won is the key.
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'node_hub_seed'",
        [],
        |r| r.get(0),
    )
    .map_err(|e| e.to_string())
}

pub fn sign_approval(seed_hex: &str, token: &ApprovalToken) -> Result<SignedApproval, String> {
    let seed: [u8; 32] = hex::decode(seed_hex)
        .map_err(|_| "hub key is not hex".to_string())?
        .try_into()
        .map_err(|_| "hub key must be 32 bytes".to_string())?;
    let json = serde_json::to_string(token).map_err(|e| e.to_string())?;
    let sig = SigningKey::from_bytes(&seed).sign(&approval_input(&json));
    Ok(SignedApproval {
        token: json,
        sig: hex::encode(sig.to_bytes()),
    })
}

/// The owner device's approval seed in `dir/approver.key`, made on first use
/// (0600). One file per machine, shared by the CLI and the desktop app.
pub fn approver_seed(dir: &Path) -> Result<String, String> {
    let path = dir.join("approver.key");
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim().to_string();
        hub_public(&t).map_err(|e| format!("{}: {e}", path.display()))?;
        return Ok(t);
    }
    let seed = generate_hub_seed();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    // Written through the same private-file path as the registry.
    let tmp = path.with_extension("key.tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let _ = std::fs::remove_file(&tmp);
        let mut f = o.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(seed.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    // A second process may have won the race; keep whichever landed first.
    if path.exists() {
        let _ = std::fs::remove_file(&tmp);
        return approver_seed(dir);
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(seed)
}

/// Where the CLI keeps the device key: the directory the desktop app uses too.
pub fn default_approver_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("io.envvault"))
}

/// Signs an approval on the owner's device for exactly one request. The lifetime
/// is the hub's own ([`APPROVAL_TTL_SECS`]); the nonce is fresh.
pub fn sign_device_approval(
    seed_hex: &str,
    node_id: &str,
    target: &str,
    sha256: &str,
    approval_id: &str,
    now_secs: i64,
    now_iso: &str,
) -> Result<SignedApproval, String> {
    let fp = key_fingerprint(&hub_public(seed_hex)?)?;
    sign_approval(
        seed_hex,
        &ApprovalToken {
            v: 1,
            node_id: node_id.into(),
            target: target.into(),
            sha256: sha256.into(),
            approval_id: approval_id.into(),
            approved_by: format!("device:{}", &fp[..12]),
            approved_at: now_iso.into(),
            expires_secs: now_secs + APPROVAL_TTL_SECS,
            nonce: crate::new_uuid(),
        },
    )
}

/// Checks a token the way a node does before it writes: the signature is the
/// hub's, it names this node, this target and exactly this hash, and it has not
/// expired. Returns the token so the caller can remember its nonce.
pub fn verify_approval(
    hub_public_hex: &str,
    signed: &SignedApproval,
    node_id: &str,
    target: &str,
    sha256: &str,
    now_secs: i64,
) -> Result<ApprovalToken, String> {
    let pk: [u8; 32] = hex::decode(hub_public_hex)
        .map_err(|_| "hub key is not hex".to_string())?
        .try_into()
        .map_err(|_| "hub key must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "hub key is not a valid Ed25519 key")?;
    let sig: [u8; 64] = hex::decode(&signed.sig)
        .map_err(|_| "approval signature is not hex".to_string())?
        .try_into()
        .map_err(|_| "approval signature has the wrong length".to_string())?;
    vk.verify(&approval_input(&signed.token), &Signature::from_bytes(&sig))
        .map_err(|_| "approval signature does not verify")?;
    let t: ApprovalToken =
        serde_json::from_str(&signed.token).map_err(|e| format!("approval is unreadable: {e}"))?;
    if t.v != 1 {
        return Err("unknown approval version".into());
    }
    if t.node_id != node_id {
        return Err("approval is for a different node".into());
    }
    if t.target != target {
        return Err("approval is for a different target".into());
    }
    if t.sha256 != sha256 {
        return Err("approval is for different bytes than the ones sent".into());
    }
    if now_secs >= t.expires_secs {
        return Err("approval has expired".into());
    }
    Ok(t)
}

/// The status word for a push that is ready but may be held.
fn approval_status(
    approvals: &[ApprovalRecord],
    node_id: &str,
    target: &str,
    sha: &str,
    now_secs: i64,
) -> &'static str {
    match latest_approval(approvals, node_id, target, sha) {
        Some(a)
            if a.status == "approved"
                && now_secs < a.decided_secs.unwrap_or(0) + APPROVAL_TTL_SECS =>
        {
            "pending"
        }
        Some(a) if a.status == "rejected" => "rejected",
        _ => "awaiting_approval",
    }
}

fn latest_approval<'a>(
    approvals: &'a [ApprovalRecord],
    node_id: &str,
    target: &str,
    sha: &str,
) -> Option<&'a ApprovalRecord> {
    approvals
        .iter()
        .rev()
        .find(|a| a.node_id == node_id && a.target == target && a.sha256 == sha)
}

impl NodeStore {
    /// Sets whether every push to a node is held for a human.
    pub fn set_approval_policy(&mut self, id: &str, policy: &str) -> Result<NodeRecord, String> {
        if !matches!(policy, "required" | "none" | "device") {
            return Err("approval must be \"required\", \"device\" or \"none\"".into());
        }
        if policy == "device" && self.data.approvers.is_empty() {
            return Err(
                "Register an approver device first (`unv node approver register`); \
                 otherwise nothing could ever approve this node's pushes."
                    .into(),
            );
        }
        let n = self
            .data
            .nodes
            .iter_mut()
            .find(|n| n.id == id && n.revoked_at.is_none())
            .ok_or("No such node")?;
        n.approval = if policy == "none" {
            String::new()
        } else {
            policy.to_string()
        };
        let out = n.clone();
        self.save()?;
        Ok(out)
    }

    /// The approval for exactly these bytes, if there is one and it can still be
    /// used: approved, within its lifetime, for an active node.
    pub fn usable_approval(
        &self,
        node_id: &str,
        target: &str,
        sha: &str,
        now_secs: i64,
    ) -> Option<ApprovalRecord> {
        let node_ok = self
            .data
            .nodes
            .iter()
            .any(|n| n.id == node_id && n.revoked_at.is_none());
        latest_approval(&self.data.approvals, node_id, target, sha)
            .filter(|a| {
                node_ok
                    && a.status == "approved"
                    && now_secs < a.decided_secs.unwrap_or(0) + APPROVAL_TTL_SECS
            })
            .cloned()
    }

    /// The newest request for these bytes in any state.
    pub fn approval_for(&self, node_id: &str, target: &str, sha: &str) -> Option<ApprovalRecord> {
        latest_approval(&self.data.approvals, node_id, target, sha).cloned()
    }

    /// Opens a request for a human, unless one for the same bytes is already
    /// open, decided, or spent. A consumed or expired request for the same bytes
    /// (a revert) opens a fresh one: an old yes does not cover a later push.
    #[allow(clippy::too_many_arguments)]
    pub fn request_approval(
        &mut self,
        node_id: &str,
        target: &TargetReport,
        sha: &str,
        from_seq: Option<i64>,
        to_seq: Option<i64>,
        now_secs: i64,
        now_iso: &str,
    ) -> Result<ApprovalRecord, String> {
        if let Some(a) = latest_approval(&self.data.approvals, node_id, &target.id, sha) {
            if matches!(a.status.as_str(), "pending" | "approved" | "rejected") {
                return Ok(a.clone());
            }
        }
        // Bound the table: spent requests are history the audit chain keeps.
        self.data.approvals.retain(|a| {
            matches!(a.status.as_str(), "pending" | "approved")
                || now_secs - a.requested_secs < 7 * 86_400
        });
        let rec = ApprovalRecord {
            id: crate::new_uuid(),
            node_id: node_id.to_string(),
            target: target.id.clone(),
            project: target.project.clone(),
            exporter: target.exporter.clone(),
            sha256: sha.to_string(),
            from_sha: target.sha256.clone(),
            from_seq,
            to_seq,
            requested_at: now_iso.to_string(),
            requested_secs: now_secs,
            status: "pending".into(),
            decided_at: None,
            decided_secs: None,
            decided_by: None,
            signed: None,
        };
        self.data.approvals.push(rec.clone());
        self.save()?;
        Ok(rec)
    }

    /// A human's answer. Only a pending request can be decided: an approval is
    /// never revived, and a decision on stale bytes is a decision on a request
    /// the hub no longer asks for.
    pub fn decide(
        &mut self,
        approval_id: &str,
        approve: bool,
        by: &str,
        now_secs: i64,
        now_iso: &str,
    ) -> Result<ApprovalRecord, String> {
        let a = self
            .data
            .approvals
            .iter_mut()
            .find(|a| a.id == approval_id)
            .ok_or("No such approval request")?;
        if a.status != "pending" {
            return Err(format!("That request is already {}", a.status));
        }
        if now_secs >= a.requested_secs + PENDING_TTL_SECS {
            a.status = "expired".into();
            let _ = self.save();
            return Err("That request has expired; the next beat opens a new one".into());
        }
        a.status = if approve { "approved" } else { "rejected" }.into();
        a.decided_at = Some(now_iso.to_string());
        a.decided_secs = Some(now_secs);
        a.decided_by = Some(by.to_string());
        let out = a.clone();
        self.save()?;
        Ok(out)
    }

    /// Registers a device whose signature counts as the owner's approval.
    pub fn add_approver(
        &mut self,
        pubkey_hex: &str,
        label: &str,
        now_iso: &str,
    ) -> Result<Approver, String> {
        let raw: [u8; 32] = hex::decode(pubkey_hex)
            .map_err(|_| "public key is not hex".to_string())?
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        VerifyingKey::from_bytes(&raw).map_err(|_| "public key is not a valid Ed25519 key")?;
        let label = label.trim();
        if label.is_empty() || label.len() > 64 || label.chars().any(char::is_control) {
            return Err("give the device a short label (up to 64 characters)".into());
        }
        let pubkey = pubkey_hex.to_ascii_lowercase();
        if let Some(a) = self.data.approvers.iter().find(|a| a.pubkey == pubkey) {
            return Ok(a.clone());
        }
        if self.data.approvers.len() >= 16 {
            return Err("at most 16 approver devices".into());
        }
        let a = Approver {
            fingerprint: key_fingerprint(&pubkey)?,
            pubkey,
            label: label.to_string(),
            added: now_iso.to_string(),
        };
        self.data.approvers.push(a.clone());
        self.save()?;
        Ok(a)
    }

    /// Removes a device by (a prefix of at least 8 characters of) its fingerprint.
    /// Nodes set to `device` approval lose their only approver if this was the
    /// last one: they fall back to `required`, so nothing is left unapprovable and
    /// nothing silently becomes approvable by the hub alone.
    pub fn remove_approver(&mut self, fp_prefix: &str) -> Result<Approver, String> {
        if fp_prefix.len() < 8 {
            return Err("name at least 8 characters of the fingerprint".into());
        }
        let hits: Vec<usize> = self
            .data
            .approvers
            .iter()
            .enumerate()
            .filter(|(_, a)| a.fingerprint.starts_with(fp_prefix))
            .map(|(i, _)| i)
            .collect();
        let [i] = hits[..] else {
            return Err(if hits.is_empty() {
                "No such approver".into()
            } else {
                "That prefix fits more than one approver".into()
            });
        };
        let gone = self.data.approvers.remove(i);
        if self.data.approvers.is_empty() {
            for n in self
                .data
                .nodes
                .iter_mut()
                .filter(|n| n.approval == "device")
            {
                n.approval = "required".into();
            }
        }
        self.save()?;
        Ok(gone)
    }

    pub fn approvers(&self) -> Vec<Approver> {
        self.data.approvers.clone()
    }

    /// A human's yes, signed on their own device. The hub holds no key that could
    /// have made it: it checks the signature against the registered devices, that
    /// the token names exactly this request (node, target, bytes, request id), and
    /// that its lifetime is no longer than the hub's own.
    pub fn decide_signed(
        &mut self,
        approval_id: &str,
        signed: SignedApproval,
        now_secs: i64,
        now_iso: &str,
    ) -> Result<ApprovalRecord, String> {
        let keys: Vec<(String, String)> = self
            .data
            .approvers
            .iter()
            .map(|a| (a.pubkey.clone(), a.fingerprint.clone()))
            .collect();
        let rec = self
            .data
            .approvals
            .iter_mut()
            .find(|a| a.id == approval_id)
            .ok_or("No such approval request")?;
        if rec.status != "pending" {
            return Err(format!("That request is already {}", rec.status));
        }
        if now_secs >= rec.requested_secs + PENDING_TTL_SECS {
            rec.status = "expired".into();
            let _ = self.save();
            return Err("That request has expired; the next beat opens a new one".into());
        }
        let mut by = None;
        let mut last_err = "no approver device is registered".to_string();
        for (pk, fp) in &keys {
            match verify_approval(
                pk,
                &signed,
                &rec.node_id,
                &rec.target,
                &rec.sha256,
                now_secs,
            ) {
                Ok(t) => {
                    if t.approval_id != rec.id {
                        last_err = "approval is for a different request".into();
                        continue;
                    }
                    if t.expires_secs > now_secs + APPROVAL_TTL_SECS + 60 {
                        last_err = "approval lasts longer than the hub allows".into();
                        continue;
                    }
                    if t.nonce.is_empty() {
                        last_err = "approval has no nonce".into();
                        continue;
                    }
                    by = Some(format!("device:{}", &fp[..12]));
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        let Some(by) = by else {
            return Err(format!("Not accepted: {last_err}"));
        };
        rec.status = "approved".into();
        rec.decided_at = Some(now_iso.to_string());
        rec.decided_secs = Some(now_secs);
        rec.decided_by = Some(by);
        rec.signed = Some(signed);
        let out = rec.clone();
        self.save()?;
        Ok(out)
    }

    /// Requests, newest first; for one node or all.
    pub fn approvals(&self, node_id: Option<&str>) -> Vec<ApprovalRecord> {
        let mut v: Vec<ApprovalRecord> = self
            .data
            .approvals
            .iter()
            .filter(|a| node_id.is_none_or(|n| a.node_id == n))
            .cloned()
            .collect();
        v.reverse();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("envv-nodes-{tag}-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn enrolled() -> (NodeStore, NodeRecord, String, PathBuf) {
        let dir = scratch("store");
        let mut s = NodeStore::open(&dir.join("nodes.json")).unwrap();
        let (seed, public) = generate_identity();
        let (tok, _) = s
            .mint_token("vps-01", vec!["edge".into()], 900, 1_000)
            .unwrap();
        let n = s
            .enroll(&tok, &public, None, 1_001, "2026-10-08T00:00:00Z")
            .unwrap();
        (s, n, seed, dir)
    }

    fn report(mode: &str, apply: bool, sha: Option<&str>) -> TargetReport {
        TargetReport {
            id: "nginx-main".into(),
            project: "edge".into(),
            exporter: "nginx".into(),
            mode: mode.into(),
            apply,
            sha256: sha.map(String::from),
            state: "ok".into(),
            error: None,
        }
    }

    #[test]
    fn a_signature_covers_method_path_time_and_body() {
        let (seed, public) = generate_identity();
        let sig = sign_request(&seed, "POST", "/api/nodes/beat", 5, b"{}").unwrap();
        assert!(verify_request(
            &public,
            "post",
            "/api/nodes/beat",
            5,
            b"{}",
            &sig
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/api/nodes/upload",
            5,
            b"{}",
            &sig
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/api/nodes/beat",
            6,
            b"{}",
            &sig
        ));
        assert!(!verify_request(
            &public,
            "POST",
            "/api/nodes/beat",
            5,
            b"{ }",
            &sig
        ));
        let (_, other) = generate_identity();
        assert!(!verify_request(
            &other,
            "POST",
            "/api/nodes/beat",
            5,
            b"{}",
            &sig
        ));
        assert!(!verify_request("zz", "POST", "/", 5, b"", "00"));
    }

    #[test]
    fn a_token_enrolls_exactly_one_node_and_only_once() {
        let dir = scratch("once");
        let mut s = NodeStore::open(&dir.join("nodes.json")).unwrap();
        let (tok, _) = s.mint_token("a", vec!["p".into()], 900, 100).unwrap();
        let (_, pk) = generate_identity();
        s.enroll(&tok, &pk, None, 101, "t").unwrap();
        let (_, pk2) = generate_identity();
        let again = s.enroll(&tok, &pk2, None, 102, "t").unwrap_err();
        assert_eq!(again, "Invalid or expired enrollment token");
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn an_expired_or_unknown_token_gets_the_same_answer() {
        let dir = scratch("exp");
        let mut s = NodeStore::open(&dir.join("nodes.json")).unwrap();
        let (tok, exp) = s.mint_token("a", vec!["p".into()], 60, 100).unwrap();
        let (_, pk) = generate_identity();
        let late = s.enroll(&tok, &pk, None, exp, "t").unwrap_err();
        let unknown = s.enroll("envn_nope", &pk, None, 101, "t").unwrap_err();
        assert_eq!(late, unknown);
    }

    #[test]
    fn the_token_is_stored_as_a_hash() {
        let dir = scratch("hash");
        let mut s = NodeStore::open(&dir.join("nodes.json")).unwrap();
        let (tok, _) = s.mint_token("a", vec!["p".into()], 900, 100).unwrap();
        let on_disk = std::fs::read_to_string(dir.join("nodes.json")).unwrap();
        assert!(
            !on_disk.contains(&tok),
            "plaintext token reached nodes.json"
        );
        assert!(on_disk.contains(&token_hash(&tok)));
    }

    #[test]
    fn a_key_that_is_not_a_curve_point_is_refused_and_does_not_spend_the_token() {
        let dir = scratch("badkey");
        let mut s = NodeStore::open(&dir.join("nodes.json")).unwrap();
        let (tok, _) = s.mint_token("a", vec!["p".into()], 900, 100).unwrap();
        // About half of all 32-byte strings do not decompress to a point.
        let bad = (0u8..=255)
            .map(|b| hex::encode([b; 32]))
            .find(|k| {
                VerifyingKey::from_bytes(&hex::decode(k).unwrap().try_into().unwrap()).is_err()
            })
            .expect("some repeated byte is not a point");
        assert!(s
            .enroll(&tok, &bad, None, 101, "t")
            .unwrap_err()
            .contains("valid Ed25519"));
        let (_, ok) = generate_identity();
        assert!(
            s.enroll(&tok, &ok, None, 102, "t").is_ok(),
            "a refused key spent the token"
        );
    }

    #[test]
    fn authentication_refuses_replay_skew_revocation_and_forgery() {
        let (mut s, n, seed, _d) = enrolled();
        let now = 1_700_000_000_000i64;
        let sig = |ts: i64| sign_request(&seed, "POST", "/api/nodes/beat", ts, b"x").unwrap();
        let auth = |s: &mut NodeStore, ts: i64, sg: &str| {
            s.authenticate(&n.id, "POST", "/api/nodes/beat", ts, b"x", sg, now)
        };
        assert!(auth(&mut s, now, &sig(now)).is_ok());
        // The same request again is a replay, not a second beat.
        assert_eq!(auth(&mut s, now, &sig(now)).unwrap_err(), AuthError::Replay);
        assert_eq!(
            auth(&mut s, now - 1, &sig(now - 1)).unwrap_err(),
            AuthError::Replay
        );
        assert!(auth(&mut s, now + 1, &sig(now + 1)).is_ok());
        let far = now + 61_000;
        assert_eq!(auth(&mut s, far, &sig(far)).unwrap_err(), AuthError::Skew);
        assert_eq!(
            auth(&mut s, now + 2, "00").unwrap_err(),
            AuthError::BadSignature
        );
        s.revoke(&n.id, "t").unwrap();
        assert_eq!(
            auth(&mut s, now + 3, &sig(now + 3)).unwrap_err(),
            AuthError::Revoked
        );
    }

    #[test]
    fn the_replay_mark_survives_a_restart() {
        let (mut s, n, seed, dir) = enrolled();
        let now = 1_700_000_000_000i64;
        let sig = sign_request(&seed, "POST", "/p", now, b"").unwrap();
        s.authenticate(&n.id, "POST", "/p", now, b"", &sig, now)
            .unwrap();
        let mut reopened = NodeStore::open(&dir.join("nodes.json")).unwrap();
        assert_eq!(
            reopened
                .authenticate(&n.id, "POST", "/p", now, b"", &sig, now)
                .unwrap_err(),
            AuthError::Replay
        );
    }

    #[test]
    fn a_corrupt_registry_is_an_error_not_an_empty_one() {
        let dir = scratch("corrupt");
        std::fs::write(dir.join("nodes.json"), "{ not json").unwrap();
        assert!(NodeStore::open(&dir.join("nodes.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_registry_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_s, _n, _seed, dir) = enrolled();
        let mode = std::fs::metadata(dir.join("nodes.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn status_words() {
        let none = None;
        let d = Some("aa");
        assert_eq!(
            derive_status(&report("push", false, Some("aa")), d, None, &none),
            "in_sync"
        );
        assert_eq!(
            derive_status(&report("push", false, Some("bb")), d, None, &none),
            "drift"
        );
        assert_eq!(
            derive_status(&report("push", true, Some("bb")), d, None, &none),
            "pending"
        );
        assert_eq!(
            derive_status(&report("push", false, None), d, None, &none),
            "missing"
        );
        assert_eq!(
            derive_status(&report("push", false, Some("aa")), None, None, &none),
            "unknown"
        );
        assert_eq!(
            derive_status(
                &report("push", true, Some("aa")),
                d,
                None,
                &Some("no".into())
            ),
            "refused"
        );
        assert_eq!(
            derive_status(&report("pull", false, Some("aa")), None, None, &none),
            "unreviewed"
        );
        assert_eq!(
            derive_status(&report("pull", false, Some("aa")), None, Some("aa"), &none),
            "in_sync"
        );
        assert_eq!(
            derive_status(&report("pull", false, Some("bb")), None, Some("aa"), &none),
            "changed"
        );
        assert_eq!(
            derive_status(&report("pull", false, None), None, Some("aa"), &none),
            "missing"
        );
    }

    #[test]
    fn a_node_cannot_be_sent_a_project_it_was_not_enrolled_for() {
        let (mut s, n, _seed, _d) = enrolled();
        let mut r = report("push", true, Some("bb"));
        r.project = "payroll".into();
        let beat = Beat {
            targets: vec![r],
            ..Default::default()
        };
        s.record_beat(&n.id, &beat, &|_| Ok("aa".into()), "t")
            .unwrap();
        let t = &s.get(&n.id).unwrap().targets[0];
        assert_eq!(t.status, "refused");
        assert!(t.desired_sha.is_none());
    }

    #[test]
    fn accepting_a_pull_target_records_its_current_hash() {
        let (mut s, n, _seed, _d) = enrolled();
        let beat = Beat {
            targets: vec![report("pull", false, Some("cc"))],
            ..Default::default()
        };
        s.record_beat(&n.id, &beat, &|_| Err("x".into()), "t")
            .unwrap();
        assert_eq!(s.get(&n.id).unwrap().targets[0].status, "unreviewed");
        s.accept(&n.id, "nginx-main").unwrap();
        // The next beat still sees the accepted hash.
        s.record_beat(&n.id, &beat, &|_| Err("x".into()), "t")
            .unwrap();
        assert_eq!(s.get(&n.id).unwrap().targets[0].status, "in_sync");
    }

    #[test]
    fn config_parses_and_every_mistake_is_named() {
        let ok = r#"
interval_secs = 30
[[target]]
id = "nginx-main"
path = "/etc/nginx/sites-enabled/x.conf"
project = "edge"
exporter = "nginx"
apply = true
validate = "nginx -t"
reload = "systemctl reload nginx"
"#;
        let c = NodeConfig::parse(ok).unwrap();
        assert_eq!(c.targets[0].mode, "push");
        let bad = |t: &str| NodeConfig::parse(t).unwrap_err();
        let base = |extra: &str| {
            format!(
                "[[target]]\nid=\"a\"\npath=\"/etc/a\"\nproject=\"p\"\nexporter=\"nginx\"\n{extra}"
            )
        };
        assert!(bad(&base("aply = true")).contains("unknown field"));
        assert!(bad(&base("mode = \"sideways\"")).contains("mode must be"));
        assert!(bad(&base("mode = \"pull\"\napply = true")).contains("only read"));
        assert!(bad(&base("mode = \"pull\"\nreload = \"x\"")).contains("only read"));
        assert!(bad(&base("reload = \"\"")).contains("reload"));
        assert!(bad(&base("").replace("/etc/a", "etc/a")).contains("absolute"));
        assert!(bad(&base("").replace("nginx", "emacs")).contains("unknown exporter"));
        assert!(bad(&base("").replace("id=\"a\"", "id=\"../a\"")).contains("id"));
        assert!(bad(&format!("{}\n{}", base(""), base(""))).contains("twice"));
        assert!(bad("interval_secs = 1").contains("interval_secs"));
    }
    // ── Approval (Phase 37) ───────────────────────────────────────────────────

    fn token(node: &str, target: &str, sha: &str, exp: i64) -> ApprovalToken {
        ApprovalToken {
            v: 1,
            node_id: node.into(),
            target: target.into(),
            sha256: sha.into(),
            approval_id: "a1".into(),
            approved_by: "owner".into(),
            approved_at: "t".into(),
            expires_secs: exp,
            nonce: "n1".into(),
        }
    }

    #[test]
    fn an_approval_verifies_only_for_the_node_target_and_bytes_it_names() {
        let seed = generate_hub_seed();
        let public = hub_public(&seed).unwrap();
        let signed = sign_approval(&seed, &token("n1", "nginx", "abc", 2_000)).unwrap();
        assert!(verify_approval(&public, &signed, "n1", "nginx", "abc", 1_000).is_ok());
        let err = |node, target, sha, now| {
            verify_approval(&public, &signed, node, target, sha, now).unwrap_err()
        };
        assert!(err("other", "nginx", "abc", 1_000).contains("different node"));
        assert!(err("n1", "wg", "abc", 1_000).contains("different target"));
        assert!(err("n1", "nginx", "abd", 1_000).contains("different bytes"));
        assert!(err("n1", "nginx", "abc", 2_000).contains("expired"));
        // Edited token text, another hub's key, a mangled signature.
        let mut forged = signed.clone();
        forged.token = forged.token.replace("\"abc\"", "\"abd\"");
        assert!(
            verify_approval(&public, &forged, "n1", "nginx", "abd", 1_000)
                .unwrap_err()
                .contains("does not verify")
        );
        let other = hub_public(&generate_hub_seed()).unwrap();
        assert!(verify_approval(&other, &signed, "n1", "nginx", "abc", 1_000).is_err());
        let mut bad = signed.clone();
        bad.sig = "00".into();
        assert!(verify_approval(&public, &bad, "n1", "nginx", "abc", 1_000).is_err());
    }

    fn request(s: &mut NodeStore, node: &str, sha: &str, now: i64) -> ApprovalRecord {
        s.request_approval(
            node,
            &report("push", true, Some("old")),
            sha,
            Some(1),
            Some(2),
            now,
            "t",
        )
        .unwrap()
    }

    #[test]
    fn a_request_is_opened_once_per_set_of_bytes_and_decided_once() {
        let (mut s, n, _seed, _d) = enrolled();
        let a = request(&mut s, &n.id, "new", 1_000);
        assert_eq!(a.status, "pending");
        assert_eq!(
            request(&mut s, &n.id, "new", 1_001).id,
            a.id,
            "asking again must not open a second request"
        );
        assert_ne!(request(&mut s, &n.id, "other", 1_002).id, a.id);
        assert!(
            s.usable_approval(&n.id, "nginx-main", "new", 1_003)
                .is_none(),
            "pending is not approved"
        );
        let done = s.decide(&a.id, true, "owner", 1_010, "t").unwrap();
        assert_eq!(
            (done.status.as_str(), done.decided_by.as_deref()),
            ("approved", Some("owner"))
        );
        assert!(s
            .decide(&a.id, false, "owner", 1_011, "t")
            .unwrap_err()
            .contains("already approved"));
        assert!(s
            .usable_approval(&n.id, "nginx-main", "new", 1_020)
            .is_some());
        // An approval is for those bytes only.
        assert!(s
            .usable_approval(&n.id, "nginx-main", "other", 1_020)
            .is_none());
        assert!(s.usable_approval(&n.id, "wg", "new", 1_020).is_none());
    }

    #[test]
    fn an_approval_lapses_and_a_revoked_node_cannot_use_one() {
        let (mut s, n, _seed, _d) = enrolled();
        let a = request(&mut s, &n.id, "new", 1_000);
        s.decide(&a.id, true, "owner", 1_000, "t").unwrap();
        assert!(s
            .usable_approval(&n.id, "nginx-main", "new", 1_000 + APPROVAL_TTL_SECS - 1)
            .is_some());
        assert!(s
            .usable_approval(&n.id, "nginx-main", "new", 1_000 + APPROVAL_TTL_SECS)
            .is_none());
        s.revoke(&n.id, "t").unwrap();
        assert!(s
            .usable_approval(&n.id, "nginx-main", "new", 1_001)
            .is_none());
    }

    #[test]
    fn a_rejected_request_stays_rejected_for_those_bytes_and_an_old_request_cannot_be_decided() {
        let (mut s, n, _seed, _d) = enrolled();
        let a = request(&mut s, &n.id, "new", 1_000);
        s.decide(&a.id, false, "owner", 1_001, "t").unwrap();
        assert_eq!(
            request(&mut s, &n.id, "new", 1_002).status,
            "rejected",
            "asking again must not reopen it"
        );
        let b = request(&mut s, &n.id, "newer", 2_000);
        let late = 2_000 + PENDING_TTL_SECS;
        assert!(s
            .decide(&b.id, true, "owner", late, "t")
            .unwrap_err()
            .contains("expired"));
        assert!(s
            .decide("nope", true, "owner", 1, "t")
            .unwrap_err()
            .contains("No such"));
    }

    #[test]
    fn a_spent_request_for_the_same_bytes_does_not_cover_a_later_push() {
        let (mut s, n, _seed, _d) = enrolled();
        let a = request(&mut s, &n.id, "v1", 1_000);
        s.decide(&a.id, true, "owner", 1_001, "t").unwrap();
        // The node reports having the approved bytes: the approval is consumed.
        let beat = Beat {
            targets: vec![report("push", true, Some("v1"))],
            ..Default::default()
        };
        s.record_beat(&n.id, &beat, &|_| Ok("v1".into()), "t")
            .unwrap();
        assert_eq!(
            s.approval_for(&n.id, "nginx-main", "v1").unwrap().status,
            "consumed"
        );
        assert!(s
            .usable_approval(&n.id, "nginx-main", "v1", 1_002)
            .is_none());
        // The same bytes wanted again later (a revert) need a new yes.
        let again = request(&mut s, &n.id, "v1", 5_000);
        assert_ne!(again.id, a.id);
        assert_eq!(again.status, "pending");
    }

    #[test]
    fn status_follows_the_policy_and_the_decision() {
        let (mut s, n, _seed, _d) = enrolled();
        let beat = Beat {
            targets: vec![report("push", true, Some("old"))],
            ..Default::default()
        };
        let status = |s: &NodeStore| s.get(&n.id).unwrap().targets[0].status.clone();
        // No policy: ready to go.
        s.record_beat(&n.id, &beat, &|_| Ok("new".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "pending");
        // Policy required, nothing asked yet: held.
        s.set_approval_policy(&n.id, "required").unwrap();
        s.record_beat(&n.id, &beat, &|_| Ok("new".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "awaiting_approval");
        let now = unix_now();
        let a = s
            .request_approval(&n.id, &beat.targets[0], "new", None, None, now, "t")
            .unwrap();
        s.record_beat(&n.id, &beat, &|_| Ok("new".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "awaiting_approval");
        s.decide(&a.id, true, "owner", now, "t").unwrap();
        s.record_beat(&n.id, &beat, &|_| Ok("new".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "pending", "approved: the hub will push it");
        // The vault moved on: the old yes does not cover the new bytes.
        s.record_beat(&n.id, &beat, &|_| Ok("newer".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "awaiting_approval");
        // A rejection is shown as one.
        let b = s
            .request_approval(&n.id, &beat.targets[0], "newer", None, None, now, "t")
            .unwrap();
        s.decide(&b.id, false, "owner", now, "t").unwrap();
        s.record_beat(&n.id, &beat, &|_| Ok("newer".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "rejected");
        // Policy off again.
        s.set_approval_policy(&n.id, "none").unwrap();
        s.record_beat(&n.id, &beat, &|_| Ok("newer".into()), "t")
            .unwrap();
        assert_eq!(status(&s), "pending");
        assert!(s.set_approval_policy(&n.id, "sometimes").is_err());
    }

    #[test]
    fn a_pull_target_cannot_require_approval() {
        let t = "[[target]]\nid=\"a\"\npath=\"/etc/a\"\nproject=\"p\"\nexporter=\"nginx\"\nmode=\"pull\"\nrequire_approval=true\n";
        assert!(NodeConfig::parse(t).unwrap_err().contains("only read"));
        let ok = "[[target]]\nid=\"a\"\npath=\"/etc/a\"\nproject=\"p\"\nexporter=\"nginx\"\napply=true\nrequire_approval=true\n";
        assert!(NodeConfig::parse(ok).unwrap().targets[0].require_approval);
    }

    fn listen(endpoint: &str) -> ListenInfo {
        ListenInfo {
            endpoint: endpoint.into(),
            cert_sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn a_listening_address_is_a_bare_https_origin() {
        for ok in [
            "https://node.example",
            "https://10.0.0.5:9443",
            "https://[::1]:9443/",
            "https://n-1.lan",
        ] {
            assert!(listen(ok).validate().is_ok(), "{ok}");
        }
        for bad in [
            "http://node.example",
            "https://user@node.example",
            "https://node.example/path",
            "https://node.example?x=1",
            "https://node.example#f",
            "https://",
            "ftp://node.example",
            "",
        ] {
            assert!(listen(bad).validate().is_err(), "{bad}");
        }
        let mut l = listen("https://n.example");
        l.cert_sha256 = "xyz".into();
        assert!(l.validate().is_err());
        assert_eq!(listen("https://n.example/").base(), "https://n.example");
    }

    #[test]
    fn a_node_signature_is_not_a_hub_signature_and_the_reverse() {
        let (node_seed, node_pub) = generate_identity();
        let hub_seed = generate_hub_seed();
        let hub_pub = hub_public(&hub_seed).unwrap();
        let body = b"{}";
        let n = sign_request(&node_seed, "POST", "/p", 5, body).unwrap();
        let h = sign_hub_request(&hub_seed, "POST", "/p", 5, body).unwrap();
        assert!(verify_request(&node_pub, "POST", "/p", 5, body, &n));
        assert!(verify_hub_request(&hub_pub, "POST", "/p", 5, body, &h));
        // Same input, other direction: refused. Without the domain line a node
        // could replay what the hub told it, or the reverse.
        assert!(!verify_hub_request(&node_pub, "POST", "/p", 5, body, &n));
        assert!(!verify_request(&hub_pub, "POST", "/p", 5, body, &h));
        // And a hub signature is bound to its path, time and body.
        assert!(!verify_hub_request(&hub_pub, "POST", "/other", 5, body, &h));
        assert!(!verify_hub_request(&hub_pub, "POST", "/p", 6, body, &h));
        assert!(!verify_hub_request(&hub_pub, "POST", "/p", 5, b"{ }", &h));
    }

    #[test]
    fn enrollment_records_where_a_listening_node_is_and_refuses_a_bad_address() {
        let dir = scratch("listen");
        let path = dir.join("nodes.json");
        let mut s = NodeStore::open(&path).unwrap();
        let (_, pk) = generate_identity();
        let (tok, _) = s.mint_token("edge", vec!["web".into()], 900, 100).unwrap();
        let bad = s
            .enroll(&tok, &pk, Some(listen("http://plain.example")), 101, "t")
            .unwrap_err();
        assert!(bad.contains("https"), "{bad}");
        // A refused address does not spend the token.
        let n = s
            .enroll(
                &tok,
                &pk,
                Some(listen("https://edge.example:9443")),
                102,
                "t",
            )
            .unwrap();
        assert_eq!(
            n.listen.as_ref().unwrap().base(),
            "https://edge.example:9443"
        );
        assert_eq!(s.listening().len(), 1);
        // A dialling node is not in the list the hub dials.
        let (_, pk2) = generate_identity();
        let (tok2, _) = s
            .mint_token("dialer", vec!["web".into()], 900, 100)
            .unwrap();
        s.enroll(&tok2, &pk2, None, 103, "t").unwrap();
        assert_eq!(s.listening().len(), 1);
        s.revoke(&n.id, "t").unwrap();
        assert!(s.listening().is_empty(), "a revoked node is not dialled");
        // Survives a reopen.
        let again = NodeStore::open(&path).unwrap();
        assert!(again.get(&n.id).unwrap().listen.is_some());
    }

    #[test]
    fn the_hub_transport_key_is_made_once_and_kept() {
        let dir = scratch("hubkey");
        let path = dir.join("nodes.json");
        let mut s = NodeStore::open(&path).unwrap();
        let (seed, public) = s.hub_node_key().unwrap();
        assert_eq!(hub_public(&seed).unwrap(), public);
        assert_eq!(s.hub_node_key().unwrap().0, seed);
        let mut reopened = NodeStore::open(&path).unwrap();
        assert_eq!(reopened.hub_node_key().unwrap(), (seed, public));
    }

    fn device() -> (String, String) {
        let seed = generate_hub_seed();
        let public = hub_public(&seed).unwrap();
        (seed, public)
    }

    #[test]
    fn device_approval_is_accepted_only_for_the_request_it_names_and_only_from_a_registered_device()
    {
        let (mut s, n, _seed, _dir) = enrolled();
        let (dev_seed, dev_pub) = device();
        // `device` is not a policy until a device exists.
        assert!(s.set_approval_policy(&n.id, "device").is_err());
        s.add_approver(&dev_pub, "laptop", "t").unwrap();
        s.set_approval_policy(&n.id, "device").unwrap();

        let rec = s
            .request_approval(
                &n.id,
                &report("push", true, Some("old")),
                "newsha",
                None,
                None,
                2_000,
                "t",
            )
            .unwrap();
        let sign = |seed: &str, node: &str, target: &str, sha: &str, id: &str, now: i64| {
            sign_device_approval(seed, node, target, sha, id, now, "t").unwrap()
        };
        // Not registered: refused.
        let (other_seed, _) = device();
        let bad = sign(&other_seed, &n.id, "nginx-main", "newsha", &rec.id, 2_010);
        assert!(s
            .decide_signed(&rec.id, bad, 2_010, "t")
            .unwrap_err()
            .contains("Not accepted"));
        // Registered, but for other bytes / target / node / request: refused.
        for (node, target, sha, id) in [
            (n.id.as_str(), "nginx-main", "othersha", rec.id.as_str()),
            (n.id.as_str(), "other", "newsha", rec.id.as_str()),
            ("someone", "nginx-main", "newsha", rec.id.as_str()),
            (n.id.as_str(), "nginx-main", "newsha", "another-request"),
        ] {
            let t = sign(&dev_seed, node, target, sha, id, 2_010);
            assert!(
                s.decide_signed(&rec.id, t, 2_010, "t").is_err(),
                "{node} {target} {sha} {id}"
            );
        }
        // A lifetime longer than the hub's own is refused.
        let long = sign_approval(
            &dev_seed,
            &ApprovalToken {
                v: 1,
                node_id: n.id.clone(),
                target: "nginx-main".into(),
                sha256: "newsha".into(),
                approval_id: rec.id.clone(),
                approved_by: "x".into(),
                approved_at: "t".into(),
                expires_secs: 2_010 + APPROVAL_TTL_SECS * 10,
                nonce: "n".into(),
            },
        )
        .unwrap();
        assert!(s
            .decide_signed(&rec.id, long, 2_010, "t")
            .unwrap_err()
            .contains("longer"));
        // The right one is accepted, recorded, and cannot be decided twice.
        let good = sign(&dev_seed, &n.id, "nginx-main", "newsha", &rec.id, 2_010);
        let a = s.decide_signed(&rec.id, good.clone(), 2_010, "t").unwrap();
        assert_eq!(a.status, "approved");
        assert!(a.decided_by.as_deref().unwrap().starts_with("device:"));
        assert_eq!(a.signed, Some(good.clone()));
        assert!(s
            .decide_signed(&rec.id, good, 2_011, "t")
            .unwrap_err()
            .contains("already"));
        assert!(s
            .usable_approval(&n.id, "nginx-main", "newsha", 2_020)
            .is_some());
    }

    #[test]
    fn removing_the_last_approver_returns_device_nodes_to_hub_approval() {
        let (mut s, n, _seed, _dir) = enrolled();
        let (_, p1) = device();
        let a = s.add_approver(&p1, "laptop", "t").unwrap();
        assert_eq!(
            s.add_approver(&p1, "again", "t").unwrap(),
            a,
            "adding twice is one device"
        );
        s.set_approval_policy(&n.id, "device").unwrap();
        assert!(
            s.remove_approver("abc").is_err(),
            "a short prefix is a guess"
        );
        s.remove_approver(&a.fingerprint[..10]).unwrap();
        assert_eq!(s.get(&n.id).unwrap().approval, "required");
        assert!(s.approvers().is_empty());
        assert!(s.add_approver("zz", "x", "t").is_err());
        assert!(s.add_approver(&p1, "", "t").is_err());
    }

    #[test]
    fn the_device_seed_is_made_once_private_and_stable() {
        let dir = scratch("approver");
        let a = approver_seed(&dir).unwrap();
        assert_eq!(approver_seed(&dir).unwrap(), a);
        assert_eq!(hub_public(&a).unwrap().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.join("approver.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o077, 0, "the key is readable by others: {m:o}");
        }
        std::fs::write(dir.join("approver.key"), "not a key").unwrap();
        assert!(
            approver_seed(&dir).is_err(),
            "a damaged key is an error, not a new identity"
        );
    }

    #[test]
    fn a_node_config_names_its_approver_as_a_real_public_key_or_not_at_all() {
        let (_, p) = device();
        assert!(NodeConfig::parse(&format!("approver = \"{p}\"")).is_ok());
        assert!(NodeConfig::parse("approver = \"zz\"").is_err());
        assert!(NodeConfig::parse("").unwrap().approver.is_none());
    }
}
