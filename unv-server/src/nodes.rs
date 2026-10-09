//! Phase 34 — the hub half of Nodes (ADR-0140).
//!
//! Opt-in: every route here answers 404 unless the server was started with
//! `--nodes`, so a deployment that never asked for the feature has no extra
//! unauthenticated surface.
//!
//! Two kinds of caller:
//!
//! - **The owner** (a bearer session) mints enrollment tokens, lists and
//!   revokes nodes, asks for a pull target's file, and accepts it.
//! - **A node** is never a session. It proves itself on every request with an
//!   Ed25519 signature over method, path, timestamp and body hash, checked
//!   against the key it registered at enrollment. It holds no vault key and no
//!   token that reads the vault.
//!
//! The hub renders on demand and never writes rendered content anywhere. A
//! pull target's file passes through memory for at most [`HOLD`] and is handed
//! to the owner exactly once.

use super::*;
use axum::body::Bytes;
use base64::Engine;
use vault_core::nodes::{
    Action, ApplyResult, Beat, BeatReply, NodeRecord, NodeStore, TargetReport, LOCKED,
};

/// How long a requested upload, or an uploaded file nobody collected, lives.
const HOLD: Duration = Duration::from_secs(120);
/// The most a node may upload for one pull target.
const MAX_UPLOAD: usize = 1024 * 1024;
/// The longest the hub holds a beat open waiting for something to do.
const MAX_WAIT_SECS: u32 = 25;
/// Pushes per beat. A node catches up over several beats; one huge reply is
/// the thing a slow link and a short timeout turn into a retry loop.
const MAX_PUSHES: usize = 16;

fn disabled() -> axum::response::Response {
    err_json(
        StatusCode::NOT_FOUND,
        "Nodes are not enabled on this server (--nodes).",
    )
    .into_response()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Runs `f` on the registry, opening it on first use.
fn with_store<R>(state: &AppState, f: impl FnOnce(&mut NodeStore) -> R) -> Result<R, String> {
    let mut g = state.nodes.lock().unwrap();
    if g.is_none() {
        *g = Some(NodeStore::open(&state.nodes_path)?);
    }
    Ok(f(g.as_mut().expect("opened above")))
}

fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn audit(
    state: &AppState,
    key: &VaultKey,
    action: &str,
    who: &str,
    details: serde_json::Value,
    actor: &str,
) {
    if let Ok(conn) = open_db(&state.db_path, key) {
        let _ =
            vault_core::record_event(&conn, action, who, Some(&details.to_string()), Some(actor));
    }
}

// ── Owner routes ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct MintRequest {
    name: String,
    projects: Vec<String>,
    ttl_secs: Option<i64>,
}

pub(crate) async fn mint_token(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<MintRequest>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    let ttl = req.ttl_secs.unwrap_or(vault_core::nodes::ENROLL_TTL_SECS);
    let name = req.name.clone();
    let projects = req.projects.clone();
    match with_store(&state, |s| s.mint_token(&name, projects, ttl, now_secs())) {
        Ok(Ok((token, expires))) => {
            audit(
                &state,
                &session.vault_key,
                "node.token",
                &req.name,
                serde_json::json!({ "projects": req.projects, "expires_at": expires }),
                "owner",
            );
            // The one time the plaintext exists outside the node that will use it.
            Json(serde_json::json!({ "token": token, "expires_at": expires, "name": req.name }))
                .into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

fn public_view(n: &NodeRecord) -> serde_json::Value {
    // The public key itself is not needed by any caller; its fingerprint is
    // what a human compares.
    let mut v = serde_json::to_value(n).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("pubkey");
        o.remove("last_ts_ms");
    }
    v
}

pub(crate) async fn list_nodes(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    // Phase 35: say which snapshot of the history a reported file came from, so
    // a drifted target reads "still what was rendered on 3 October".
    let conn = open_db(&state.db_path, &session.vault_key).ok();
    match with_store(&state, |s| {
        s.list()
            .into_iter()
            .map(|n| {
                let a = s.approvals(Some(&n.id));
                (n, a)
            })
            .collect::<Vec<_>>()
    }) {
        Ok(list) => Json(serde_json::json!({
            "nodes": list.iter().map(|(n, approvals)| {
                let mut v = public_view(n);
                // What is waiting for a human, and what recently was decided.
                v["approvals"] = serde_json::json!(approvals.iter().take(20).collect::<Vec<_>>());
                if let (Some(conn), Some(ts)) = (&conn, v["targets"].as_array_mut()) {
                    for t in ts {
                        let sha = t["reported_sha"].as_str().map(String::from);
                        if let Some(s) = sha.and_then(|h| crate::history::snapshot_for_hash(conn, &h)) {
                            t["snapshot"] = s;
                        }
                    }
                }
                v
            }).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

#[derive(Deserialize)]
pub(crate) struct PolicyRequest {
    approval: String,
}

/// Holds every push to a node for a human (`required`), or stops doing so (`none`).
pub(crate) async fn set_policy(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PolicyRequest>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    match with_store(&state, |s| s.set_approval_policy(&id, &req.approval)) {
        Ok(Ok(n)) => {
            audit(
                &state,
                &session.vault_key,
                "node.policy",
                &n.name,
                serde_json::json!({ "node": n.id, "approval": req.approval }),
                "owner",
            );
            state.nodes_wake.notify_waiters();
            Json(serde_json::json!({ "name": n.name, "approval": req.approval })).into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// A human's answer to a held push: `approve` or `reject`. Owner only. The
/// approval is for the bytes the request names; if the vault has moved on the
/// hub has already opened a new request for the new bytes and this one is stale.
pub(crate) async fn decide_approval(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((aid, verb)): Path<(String, String)>,
    body: Bytes,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    let approve = match verb.as_str() {
        "approve" => true,
        "reject" => false,
        _ => return err_json(StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    // A yes signed on the owner's device (Phase 37.1) arrives as `{"signed": …}`.
    #[derive(Deserialize, Default)]
    struct Decision {
        #[serde(default)]
        signed: Option<vault_core::nodes::SignedApproval>,
    }
    let decision: Decision = if body.is_empty() {
        Decision::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(d) => d,
            Err(e) => {
                return err_json(StatusCode::BAD_REQUEST, &format!("Bad decision: {e}"))
                    .into_response()
            }
        }
    };
    // A node set to `device` is approved by a device or not at all: the hub's own
    // click does not count, so a hub someone else controls cannot approve itself.
    if approve && decision.signed.is_none() {
        let device_only = with_store(&state, |s| {
            s.approvals(None)
                .into_iter()
                .find(|a| a.id == aid)
                .and_then(|a| s.get(&a.node_id))
                .is_some_and(|n| n.approval == "device")
        })
        .unwrap_or(false);
        if device_only {
            return err_json(
                StatusCode::CONFLICT,
                "This node's pushes are approved on your own device: sign the approval there (unv node approve, or the app).",
            )
            .into_response();
        }
    }
    let r = with_store(&state, |s| match (approve, decision.signed.clone()) {
        (true, Some(signed)) => s.decide_signed(&aid, signed, now_secs(), &vault_core::iso_now()),
        _ => s.decide(&aid, approve, "owner", now_secs(), &vault_core::iso_now()),
    });
    match r {
        Ok(Ok(a)) => {
            audit(
                &state,
                &session.vault_key,
                if approve {
                    "node.approve"
                } else {
                    "node.reject"
                },
                &a.node_id,
                serde_json::json!({
                    "approval": a.id, "target": a.target, "sha256": a.sha256, "from_sha": a.from_sha,
                }),
                "owner",
            );
            // A beat held open for exactly this should go out now.
            state.nodes_wake.notify_waiters();
            Json(a).into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::CONFLICT, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── Approver devices (Phase 37.1, ADR-0147) ───────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct ApproverRequest {
    pubkey: String,
    label: String,
}

/// Registered approver devices. Owner only.
pub(crate) async fn list_approvers(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    match with_store(&state, |s| s.approvers()) {
        Ok(a) => Json(serde_json::json!({ "approvers": a })).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Registers a device whose signature counts as the owner's approval.
pub(crate) async fn add_approver(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ApproverRequest>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    match with_store(&state, |s| {
        s.add_approver(&req.pubkey, &req.label, &vault_core::iso_now())
    }) {
        Ok(Ok(a)) => {
            audit(
                &state,
                &session.vault_key,
                "node.approver.add",
                &a.label,
                serde_json::json!({ "fingerprint": a.fingerprint }),
                "owner",
            );
            Json(a).into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

pub(crate) async fn remove_approver(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(fp): Path<String>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    match with_store(&state, |s| s.remove_approver(&fp)) {
        Ok(Ok(a)) => {
            audit(
                &state,
                &session.vault_key,
                "node.approver.remove",
                &a.label,
                serde_json::json!({ "fingerprint": a.fingerprint }),
                "owner",
            );
            state.nodes_wake.notify_waiters();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::NOT_FOUND, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

pub(crate) async fn revoke_node(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    match with_store(&state, |s| s.revoke(&id, &vault_core::iso_now())) {
        Ok(Ok(n)) => {
            state
                .node_wants
                .lock()
                .unwrap()
                .retain(|(i, _), _| i != &id);
            state
                .node_uploads
                .lock()
                .unwrap()
                .retain(|(i, _), _| i != &id);
            audit(
                &state,
                &session.vault_key,
                "node.revoke",
                &n.name,
                serde_json::json!({ "node": n.id }),
                "owner",
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::NOT_FOUND, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

#[derive(Deserialize)]
pub(crate) struct TargetRequest {
    target: String,
}

pub(crate) async fn request_pull(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TargetRequest>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    let node = match with_store(&state, |s| s.get(&id)) {
        Ok(Some(n)) if n.revoked_at.is_none() => n,
        Ok(_) => return err_json(StatusCode::NOT_FOUND, "No such node").into_response(),
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    };
    if !node
        .targets
        .iter()
        .any(|t| t.id == req.target && t.mode == "pull")
    {
        return err_json(
            StatusCode::BAD_REQUEST,
            "That is not a pull target on this node (or the node has not reported it yet)",
        )
        .into_response();
    }
    state
        .node_wants
        .lock()
        .unwrap()
        .insert((id, req.target), Instant::now());
    state.nodes_wake.notify_waiters();
    StatusCode::ACCEPTED.into_response()
}

pub(crate) async fn fetch_content(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((id, target)): Path<(String, String)>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    let key = (id.clone(), target.clone());
    let taken = {
        let mut up = state.node_uploads.lock().unwrap();
        up.retain(|_, (t, _)| t.elapsed() < HOLD);
        up.remove(&key)
    };
    if let Some((_, bytes)) = taken {
        let sha = vault_core::nodes_apply::sha256_hex(&bytes);
        audit(
            &state,
            &session.vault_key,
            "node.pull",
            &id,
            serde_json::json!({ "target": target, "sha256": sha }),
            "owner",
        );
        return Json(serde_json::json!({
            "sha256": sha,
            "content_b64": base64::engine::general_purpose::STANDARD.encode(&bytes)
        }))
        .into_response();
    }
    let waiting = {
        let mut w = state.node_wants.lock().unwrap();
        w.retain(|_, t| t.elapsed() < HOLD);
        w.contains_key(&key)
    };
    if waiting {
        StatusCode::NO_CONTENT.into_response()
    } else {
        err_json(
            StatusCode::NOT_FOUND,
            "No pull was requested for that target, or it expired",
        )
        .into_response()
    }
}

pub(crate) async fn accept_pull(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TargetRequest>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    match with_store(&state, |s| s.accept(&id, &req.target)) {
        Ok(Ok(sha)) => {
            audit(
                &state,
                &session.vault_key,
                "node.accept",
                &id,
                serde_json::json!({ "target": req.target, "sha256": sha }),
                "owner",
            );
            Json(serde_json::json!({ "sha256": sha })).into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

// ── Node routes ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct EnrollRequest {
    token: String,
    pubkey: String,
    /// Present for a node that listens and is dialled (Phase 34.1).
    #[serde(default)]
    listen: Option<vault_core::nodes::ListenInfo>,
}

pub(crate) async fn enroll(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let rl = format!("node-enroll:{}", addr.ip());
    if let Some(retry) = rate_retry_after(&mut state.rate_limiter.lock().unwrap(), &rl) {
        return err_json_retry(StatusCode::TOO_MANY_REQUESTS, "Too many requests", retry);
    }
    let r = with_store(&state, |s| {
        s.enroll(
            &req.token,
            &req.pubkey,
            req.listen.clone(),
            now_secs(),
            &vault_core::iso_now(),
        )
    });
    match r {
        Ok(Ok(n)) => {
            if let Some(key) = owner_vault_key(&state) {
                audit(
                    &state,
                    &key,
                    "node.enroll",
                    &n.name,
                    serde_json::json!({ "node": n.id, "fingerprint": n.fingerprint, "projects": n.projects }),
                    &format!("node:{}", n.name),
                );
            }
            // A listening node verifies everything the hub sends under this key,
            // so it is handed over here, on the token-authenticated channel.
            let hub_node_pubkey = with_store(&state, |s| s.hub_node_key().map(|k| k.1))
                .ok()
                .and_then(Result::ok);
            Json(serde_json::json!({
                "node_id": n.id,
                "name": n.name,
                "projects": n.projects,
                "node_fingerprint": n.fingerprint,
                "hub_fingerprint": state.cert_fingerprint,
                "hub_node_pubkey": hub_node_pubkey,
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &rl);
            err_json(StatusCode::UNAUTHORIZED, &e).into_response()
        }
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response(),
    }
}

/// Verifies the three headers and the signature, or builds the refusal.
fn authenticate(
    state: &AppState,
    addr: &SocketAddr,
    headers: &HeaderMap,
    path: &str,
    body: &[u8],
) -> Result<NodeRecord, axum::response::Response> {
    let rl = format!("node-auth:{}", addr.ip());
    if let Some(retry) = rate_retry_after(&mut state.rate_limiter.lock().unwrap(), &rl) {
        return Err(err_json_retry(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            retry,
        ));
    }
    let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    let fail = || {
        record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &rl);
        err_json(StatusCode::UNAUTHORIZED, "Node authentication failed").into_response()
    };
    let (Some(id), Some(ts), Some(sig)) = (get("x-node-id"), get("x-node-ts"), get("x-node-sig"))
    else {
        return Err(fail());
    };
    let Ok(ts) = ts.parse::<i64>() else {
        return Err(fail());
    };
    match with_store(state, |s| {
        s.authenticate(id, "POST", path, ts, body, sig, now_ms())
    }) {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(e)) => {
            record_auth_failure(&mut state.rate_limiter.lock().unwrap(), &rl);
            Err(err_json(StatusCode::UNAUTHORIZED, e.message()).into_response())
        }
        Err(e) => Err(err_json(StatusCode::INTERNAL_SERVER_ERROR, &e).into_response()),
    }
}

/// What the hub would write for each target of this node, or why it will not.
struct Plan {
    /// target id -> rendered bytes, for the targets it will render.
    rendered: HashMap<String, Result<Vec<u8>, String>>,
}

fn plan(vault: Option<&serde_json::Value>, node: &NodeRecord, targets: &[TargetReport]) -> Plan {
    let mut rendered = HashMap::new();
    let Some(vault) = vault else {
        for t in targets.iter().filter(|t| t.mode == "push") {
            rendered.insert(t.id.clone(), Err(LOCKED.to_string()));
        }
        return Plan { rendered };
    };
    let names = unv_cli::check_cmd::vault_names(vault);
    let mut cache: HashMap<(String, String), Result<Vec<u8>, String>> = HashMap::new();
    for t in targets.iter().filter(|t| t.mode == "push") {
        if !node.projects.iter().any(|p| p == &t.project) {
            continue; // record_beat words this refusal itself
        }
        let r = cache
            .entry((t.project.clone(), t.exporter.clone()))
            .or_insert_with(|| render_gated(vault, &names, &t.project, &t.exporter))
            .clone();
        rendered.insert(t.id.clone(), r);
    }
    Plan { rendered }
}

/// Renders one project for a node, after the config compiler has looked at it.
///
/// The compiler's error findings are exactly "the generated config is wrong",
/// and a node is about to write that config to a live host. A warning does not
/// stop a push; it is something a human can read in `unv check`.
fn render_gated(
    vault: &serde_json::Value,
    names: &[String],
    project: &str,
    exporter: &str,
) -> Result<Vec<u8>, String> {
    let list = unv_cli::data::projects(vault);
    let idx = unv_cli::data::find_project_index(vault, project).map_err(|e| e.to_string())?;
    let errors = vault_core::config_check::gate(&list[idx], names);
    if let Some(f) = errors.first() {
        return Err(format!(
            "config check: {} ({} error{} in project '{project}')",
            f.message,
            errors.len(),
            if errors.len() == 1 { "" } else { "s" }
        ));
    }
    unv_cli::chunks::render_project(vault, project, exporter)
        .map(String::into_bytes)
        .map_err(|e| e.to_string())
}

fn record_results(state: &AppState, key: &VaultKey, node: &NodeRecord, results: &[ApplyResult]) {
    for r in results.iter().take(64) {
        audit(
            state,
            key,
            "node.apply",
            &node.name,
            serde_json::json!({
                "node": node.id,
                "target": short(&r.target, 63),
                "at": short(&r.at, 40),
                "sha256": short(&r.sha256, 64),
                "ok": r.ok,
                "error": r.error.as_deref().map(|e| short(e, 400)),
            }),
            &format!("node:{}", node.name),
        );
    }
}

/// One pass of beat handling: audit, plan, record, and decide the actions.
fn process(state: &AppState, node: &NodeRecord, beat: &Beat, first: bool) -> BeatReply {
    let key = owner_vault_key(state);
    let mut reply = BeatReply {
        interval_secs: 60,
        hub_locked: key.is_none(),
        results_ack: false,
        actions: Vec::new(),
        pending: Vec::new(),
        hub_pubkey: None,
    };

    let conn = key.as_ref().and_then(|k| open_db(&state.db_path, k).ok());
    // The hub's approval-signing key lives in the vault's own (encrypted) meta
    // table, so it exists only while the vault is open, like the push it signs.
    let hub_seed = conn
        .as_ref()
        .and_then(|c| vault_core::nodes::hub_seed(c).ok());
    reply.hub_pubkey = hub_seed
        .as_deref()
        .and_then(|s| vault_core::nodes::hub_public(s).ok());
    // Read the policy now, not from the clone taken when the request arrived: a
    // held beat that is woken by an approval must see what the owner set.
    let requires_approval = with_store(state, |s| s.get(&node.id))
        .ok()
        .flatten()
        .is_some_and(|n| matches!(n.approval.as_str(), "required" | "device"));
    let vault = conn.as_ref().and_then(|c| load_vault(c).ok().flatten());
    if let Some(k) = &key {
        if first {
            record_results(state, k, node, &beat.results);
        }
        reply.results_ack = true;
    }

    let plan = plan(vault.as_ref(), node, &beat.targets);
    let desired = |t: &TargetReport| -> Result<String, String> {
        match plan.rendered.get(&t.id) {
            Some(Ok(b)) => Ok(vault_core::nodes_apply::sha256_hex(b)),
            Some(Err(e)) => Err(e.clone()),
            None => Err(LOCKED.to_string()),
        }
    };
    // A node that needs a human gets a request for each set of bytes it is about
    // to be sent, with the proposal recorded in the history so the human reads it
    // as a diff. The request exists before the status is computed, so the very
    // beat that notices a change already shows it as awaiting approval.
    if requires_approval {
        if let (Some(c), Some(v)) = (&conn, &vault) {
            for t in beat.targets.iter().filter(|t| t.mode == "push" && t.apply) {
                let Some(Ok(bytes)) = plan.rendered.get(&t.id) else {
                    continue;
                };
                let sha = vault_core::nodes_apply::sha256_hex(bytes);
                if t.sha256.as_deref() == Some(sha.as_str()) {
                    continue;
                }
                let known = with_store(state, |s| s.approval_for(&node.id, &t.id, &sha))
                    .ok()
                    .flatten()
                    .is_some_and(|a| {
                        matches!(a.status.as_str(), "pending" | "approved" | "rejected")
                    });
                if known {
                    continue;
                }
                let actor = format!("node:{}", node.name);
                let to_seq = unv_cli::history::snapshot_stream(
                    c,
                    v,
                    &t.project,
                    &t.exporter,
                    &format!("proposed:{}", node.name),
                    Some(&actor),
                )
                .ok()
                .flatten()
                .or_else(|| {
                    vault_core::config_history::find_by_sha(c, &sha, 1)
                        .ok()
                        .and_then(|m| m.first().map(|x| x.seq))
                });
                let from_seq = t.sha256.as_deref().and_then(|h| {
                    vault_core::config_history::find_by_sha(c, h, 1)
                        .ok()
                        .and_then(|m| m.first().map(|x| x.seq))
                });
                let made = with_store(state, |s| {
                    s.request_approval(
                        &node.id,
                        t,
                        &sha,
                        from_seq,
                        to_seq,
                        now_secs(),
                        &vault_core::iso_now(),
                    )
                });
                if let Ok(Ok(rec)) = made {
                    if first {
                        if let Some(k) = &key {
                            audit(
                                state,
                                k,
                                "node.approval.request",
                                &node.name,
                                serde_json::json!({
                                    "approval": rec.id, "target": t.id,
                                    "sha256": sha, "from_sha": rec.from_sha,
                                }),
                                &actor,
                            );
                        }
                    }
                }
            }
        }
    }
    let rec = with_store(state, |s| {
        s.record_beat(&node.id, beat, &desired, &vault_core::iso_now())
    });
    if !matches!(rec, Ok(Ok(()))) {
        return reply;
    }

    for t in &beat.targets {
        if reply.actions.len() >= MAX_PUSHES {
            break;
        }
        if t.mode == "push" && t.apply {
            if let Some(Ok(bytes)) = plan.rendered.get(&t.id) {
                let sha = vault_core::nodes_apply::sha256_hex(bytes);
                if t.sha256.as_deref() != Some(sha.as_str()) {
                    // What is about to leave this hub is recorded first, so the
                    // history (and blast radius with it) accounts for every file a
                    // host was ever sent. A no-op when a save already recorded it.
                    if let (Some(c), Some(v)) = (&conn, &vault) {
                        let _ = unv_cli::history::snapshot_stream(
                            c,
                            v,
                            &t.project,
                            &t.exporter,
                            &format!("push:{}", node.name),
                            Some(&format!("node:{}", node.name)),
                        );
                    }
                    // A node that needs a human is sent nothing until there is a yes
                    // for exactly these bytes, and then it is sent that yes, signed.
                    let approval = if requires_approval {
                        let usable = with_store(state, |s| {
                            s.usable_approval(&node.id, &t.id, &sha, now_secs())
                        })
                        .ok()
                        .flatten();
                        let Some(a) = usable else {
                            let rec = with_store(state, |s| s.approval_for(&node.id, &t.id, &sha))
                                .ok()
                                .flatten();
                            reply.pending.push(vault_core::nodes::PendingNote {
                                target: t.id.clone(),
                                sha256: sha.clone(),
                                status: rec
                                    .as_ref()
                                    .map_or("awaiting_approval", |r| r.status.as_str())
                                    .to_string(),
                                approval_id: rec.map(|r| r.id).unwrap_or_default(),
                            });
                            continue;
                        };
                        // Signed on the owner's device: the hub sends exactly that and
                        // holds no key that could have made it. A `device` node is
                        // never sent a hub-made approval, whatever the record says.
                        if let Some(signed) = a.signed.clone() {
                            reply.actions.push(Action::Push {
                                target: t.id.clone(),
                                sha256: sha,
                                content_b64: base64::engine::general_purpose::STANDARD
                                    .encode(bytes),
                                approval: Some(signed),
                            });
                            continue;
                        }
                        if node.approval == "device" {
                            continue;
                        }
                        let Some(seed) = &hub_seed else {
                            continue;
                        };
                        let token = vault_core::nodes::ApprovalToken {
                            v: 1,
                            node_id: node.id.clone(),
                            target: t.id.clone(),
                            sha256: sha.clone(),
                            approval_id: a.id.clone(),
                            approved_by: a.decided_by.clone().unwrap_or_default(),
                            approved_at: a.decided_at.clone().unwrap_or_default(),
                            expires_secs: a.decided_secs.unwrap_or(0)
                                + vault_core::nodes::APPROVAL_TTL_SECS,
                            nonce: vault_core::new_uuid(),
                        };
                        vault_core::nodes::sign_approval(seed, &token).ok()
                    } else {
                        None
                    };
                    reply.actions.push(Action::Push {
                        target: t.id.clone(),
                        sha256: sha,
                        content_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
                        approval,
                    });
                }
            }
        }
    }
    {
        let mut w = state.node_wants.lock().unwrap();
        w.retain(|_, at| at.elapsed() < HOLD);
        for t in beat.targets.iter().filter(|t| t.mode == "pull") {
            if w.contains_key(&(node.id.clone(), t.id.clone())) {
                reply.actions.push(Action::Upload {
                    target: t.id.clone(),
                });
            }
        }
    }
    reply
}

pub(crate) async fn beat(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let node = match authenticate(&state, &addr, &headers, "/api/nodes/beat", &body) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let beat: Beat = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return err_json(StatusCode::BAD_REQUEST, &format!("Bad beat: {e}")).into_response()
        }
    };

    // Registered before the first pass so a save landing between the pass and
    // the wait still wakes this request.
    let notified = state.nodes_wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    let mut reply = process(&state, &node, &beat, true);
    let wait = beat.wait_secs.min(MAX_WAIT_SECS);
    if reply.actions.is_empty() && wait > 0 {
        let _ = tokio::time::timeout(Duration::from_secs(u64::from(wait)), notified).await;
        let acked = reply.results_ack;
        reply = process(&state, &node, &beat, false);
        reply.results_ack = acked || reply.results_ack;
    }
    Json(reply).into_response()
}

// ── Dialling listening nodes (Phase 34.1, ADR-0145) ───────────────────────────

/// How often a listening node is polled when nothing wakes the hub earlier.
const POLL_EVERY: Duration = Duration::from_secs(30);

static LAST_HUB_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// A strictly increasing millisecond timestamp, even if the clock steps back.
fn next_hub_ts() -> i64 {
    use std::sync::atomic::Ordering;
    let now = now_ms();
    let mut prev = LAST_HUB_TS.load(Ordering::SeqCst);
    loop {
        let next = now.max(prev + 1);
        match LAST_HUB_TS.compare_exchange(prev, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(p) => prev = p,
        }
    }
}

/// One signed POST to a listening node.
fn dial(
    fingerprint: &str,
    seed: &str,
    base: &str,
    path: &str,
    body: &[u8],
) -> Result<unv_cli::tls::Dialed, String> {
    let ts = next_hub_ts();
    let sig = vault_core::nodes::sign_hub_request(seed, "POST", path, ts, body)?;
    unv_cli::tls::hub_post(fingerprint, base, path, ts, &sig, body)
}

/// Asks one listening node for its beat and answers it. Blocking: the pinned
/// client is `reqwest::blocking`, and `process` takes `std` locks.
fn poll_node(state: &AppState, node: &NodeRecord) -> Result<(), String> {
    let listen = node.listen.as_ref().ok_or("not a listening node")?;
    let (seed, _) = with_store(state, |s| s.hub_node_key())??;
    let (fp, base) = (listen.cert_sha256.as_str(), listen.base());

    let resp = dial(fp, &seed, base, "/node/v1/poll", b"")?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("the node answered {}", resp.status));
    }
    let (Some(id), Some(ts), Some(sig)) = (
        resp.headers.get("x-node-id"),
        resp.headers.get("x-node-ts"),
        resp.headers.get("x-node-sig"),
    ) else {
        return Err("the node's answer is not signed".into());
    };
    if id != &node.id {
        return Err("the answer is signed for a different node".into());
    }
    let ts: i64 = ts.parse().map_err(|_| "bad timestamp".to_string())?;
    // The same check, replay mark and clock rule as a beat that was dialled in.
    let node = with_store(state, |s| {
        s.authenticate(id, "POST", "/api/nodes/beat", ts, &resp.body, sig, now_ms())
    })?
    .map_err(|e| e.message().to_string())?;
    let beat: Beat = serde_json::from_slice(&resp.body).map_err(|e| format!("bad beat: {e}"))?;

    let reply = process(state, &node, &beat, true);
    let act = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
    let r = dial(fp, &seed, base, "/node/v1/act", &act)?;
    if !(200..300).contains(&r.status) {
        return Err(format!("the node refused the reply: {}", r.status));
    }
    let _ = with_store(state, |s| s.mark_polled(&node.id, &vault_core::iso_now()));
    Ok(())
}

/// Starts the task that dials listening nodes: every [`POLL_EVERY`], and at once
/// when the vault is saved or a decision is made. Does nothing unless Nodes are on.
/// Must be called from inside a Tokio runtime.
pub(crate) fn spawn_poller(state: AppState) {
    if !state.nodes_enabled {
        return;
    }
    tokio::spawn(async move {
        let mut last: std::collections::HashMap<String, Instant> = Default::default();
        loop {
            let woken = {
                let notified = state.nodes_wake.notified();
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(5)) => false,
                    () = notified => true,
                }
            };
            let nodes = with_store(&state, |s| s.listening()).unwrap_or_default();
            last.retain(|id, _| nodes.iter().any(|n| &n.id == id));
            for n in nodes {
                let due = last.get(&n.id).is_none_or(|t| t.elapsed() >= POLL_EVERY);
                if !(woken || due) {
                    continue;
                }
                last.insert(n.id.clone(), Instant::now());
                let st = state.clone();
                let node = n.clone();
                let r = tokio::task::spawn_blocking(move || poll_node(&st, &node)).await;
                match r {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!(node = %n.name, error = %e, "node poll failed"),
                    Err(e) => tracing::warn!(node = %n.name, error = %e, "node poll panicked"),
                }
            }
        }
    });
}

#[derive(Deserialize)]
struct UploadBody {
    target: String,
    content_b64: String,
}

pub(crate) async fn upload(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if !state.nodes_enabled {
        return disabled();
    }
    let node = match authenticate(&state, &addr, &headers, "/api/nodes/upload", &body) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let req: UploadBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return err_json(StatusCode::BAD_REQUEST, &format!("Bad upload: {e}")).into_response()
        }
    };
    let key = (node.id.clone(), req.target.clone());
    // Only content somebody asked for. An unsolicited upload would let a node
    // fill the hub's memory.
    if !state.node_wants.lock().unwrap().contains_key(&key) {
        return err_json(
            StatusCode::CONFLICT,
            "No pull was requested for that target",
        )
        .into_response();
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(req.content_b64.as_bytes())
    else {
        return err_json(StatusCode::BAD_REQUEST, "content_b64 is not base64").into_response();
    };
    if bytes.len() > MAX_UPLOAD {
        return err_json(
            StatusCode::PAYLOAD_TOO_LARGE,
            "File is over the 1 MiB pull limit",
        )
        .into_response();
    }
    state.node_wants.lock().unwrap().remove(&key);
    state
        .node_uploads
        .lock()
        .unwrap()
        .insert(key, (Instant::now(), bytes));
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt;
    use vault_core::nodes::{generate_identity, sign_request, HostInfo};

    fn scratch(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("unv-nodes-srv-{tag}-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const PASS: &str = "first-secret-value";

    fn vault_with(value: &str) -> serde_json::Value {
        serde_json::json!({
            "api_keys": [],
            "user_categories": [],
            "projects": [{
                "id": "edge", "name": "edge", "project_type": "generic",
                "chunks": [{
                    "id": "c1", "name": "app.env", "chunk_type": "env_file",
                    "fields": [{ "key": "TOKEN", "value": value }]
                }]
            }, {
                "id": "payroll", "name": "payroll", "project_type": "generic",
                "chunks": [{
                    "id": "c2", "name": "p.env", "chunk_type": "env_file",
                    "fields": [{ "key": "SALARY", "value": "do-not-send" }]
                }]
            }]
        })
    }

    struct Hub {
        state: AppState,
        owner: String,
        key: VaultKey,
    }

    fn hub(enabled: bool, unlocked: bool) -> Hub {
        let d = scratch("hub");
        let key = [7u8; 32];
        let mut s = AppState::new(
            d.join("vault.db"),
            d.join("vault.salt"),
            None,
            480,
            24,
            false,
        )
        .with_nodes(enabled, None);
        let conn = vault_core::open_db(&s.db_path, &key).unwrap();
        vault_core::init_schema(&conn).unwrap();
        vault_core::save_vault(&conn, vault_with(PASS), vault_core::SaveCtx::default()).unwrap();
        let owner = if unlocked {
            s.adopt_owner_key(key, "owner".into())
        } else {
            String::new()
        };
        s.nodes_path = d.join("nodes.json");
        Hub {
            state: s,
            owner,
            key,
        }
    }

    fn app(h: &Hub) -> axum::Router {
        build_router(h.state.clone(), 8743).layer(MockConnectInfo(
            "203.0.113.9:5000".parse::<SocketAddr>().unwrap(),
        ))
    }

    async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let r = app.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    fn owner_req(h: &Hub, method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", h.owner))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    struct Node {
        id: String,
        seed: String,
        last_ts: std::cell::Cell<i64>,
    }

    impl Node {
        fn signed(&self, path: &str, body: &[u8]) -> Request<Body> {
            let ts = now_ms().max(self.last_ts.get() + 1);
            self.last_ts.set(ts);
            self.signed_at(path, body, ts)
        }
        fn signed_at(&self, path: &str, body: &[u8], ts: i64) -> Request<Body> {
            let sig = sign_request(&self.seed, "POST", path, ts, body).unwrap();
            Request::builder()
                .method("POST")
                .uri(path)
                .header("x-node-id", &self.id)
                .header("x-node-ts", ts.to_string())
                .header("x-node-sig", sig)
                .header("content-type", "application/json")
                .body(Body::from(body.to_vec()))
                .unwrap()
        }
    }

    async fn enrolled(h: &Hub, app: &axum::Router, projects: &[&str]) -> Node {
        let (st, tok) = send(
            app,
            owner_req(
                h,
                "POST",
                "/api/nodes/tokens",
                serde_json::json!({ "name": "vps-01", "projects": projects }),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{tok}");
        let (seed, public) = generate_identity();
        let (st, e) = send(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/nodes/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "token": tok["token"], "pubkey": public }).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{e}");
        Node {
            id: e["node_id"].as_str().unwrap().into(),
            seed,
            last_ts: std::cell::Cell::new(0),
        }
    }

    fn target(
        id: &str,
        project: &str,
        mode: &str,
        apply: bool,
        sha: Option<String>,
    ) -> TargetReport {
        TargetReport {
            id: id.into(),
            project: project.into(),
            exporter: "env".into(),
            mode: mode.into(),
            apply,
            sha256: sha,
            state: "ok".into(),
            error: None,
        }
    }

    fn beat_body(targets: Vec<TargetReport>, results: Vec<ApplyResult>, wait: u32) -> Vec<u8> {
        serde_json::to_vec(&Beat {
            host: HostInfo {
                hostname: "vps".into(),
                ..Default::default()
            },
            targets,
            events: vec![],
            results,
            wait_secs: wait,
        })
        .unwrap()
    }

    async fn do_beat(
        app: &axum::Router,
        n: &Node,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        send(app, n.signed("/api/nodes/beat", &body)).await
    }

    fn rendered_sha(value: &str) -> String {
        let r = unv_cli::chunks::render_project(&vault_with(value), "edge", "env").unwrap();
        vault_core::nodes_apply::sha256_hex(r.as_bytes())
    }

    #[tokio::test]
    async fn every_node_route_is_404_unless_the_server_opted_in() {
        let h = hub(false, true);
        let a = app(&h);
        let (st, _) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        let (st, _) = send(
            &a,
            Request::builder()
                .method("POST")
                .uri("/api/nodes/enroll")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"token":"x","pubkey":"y"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        assert!(
            !h.state.nodes_path.exists(),
            "nodes.json was created for a hub that never asked"
        );
    }

    #[tokio::test]
    async fn only_the_owner_manages_nodes() {
        let h = hub(true, true);
        let a = app(&h);
        let no_auth = Request::builder()
            .method("GET")
            .uri("/api/nodes")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&a, no_auth).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_enrolled_node_with_apply_on_is_handed_the_rendered_file_and_its_hash() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let (st, reply) = do_beat(
            &a,
            &n,
            beat_body(
                vec![target("env-main", "edge", "push", true, None)],
                vec![],
                0,
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{reply}");
        let act = &reply["actions"][0];
        assert_eq!(act["kind"], "push");
        assert_eq!(act["target"], "env-main");
        assert_eq!(act["sha256"], rendered_sha(PASS));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(act["content_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(vault_core::nodes_apply::sha256_hex(&bytes), act["sha256"]);
        assert!(String::from_utf8(bytes).unwrap().contains(PASS));
    }

    #[tokio::test]
    async fn apply_off_means_the_hub_never_sends_content() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let (_, reply) = do_beat(
            &a,
            &n,
            beat_body(
                vec![target("env-main", "edge", "push", false, None)],
                vec![],
                0,
            ),
        )
        .await;
        assert_eq!(reply["actions"].as_array().unwrap().len(), 0);
        let (_, list) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        assert_eq!(list["nodes"][0]["targets"][0]["status"], "missing");
        assert!(!serde_json::to_string(&list).unwrap().contains(PASS));
    }

    #[tokio::test]
    async fn a_file_that_already_matches_is_in_sync_and_gets_no_push() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let (_, reply) = do_beat(
            &a,
            &n,
            beat_body(
                vec![target(
                    "env-main",
                    "edge",
                    "push",
                    true,
                    Some(rendered_sha(PASS)),
                )],
                vec![],
                0,
            ),
        )
        .await;
        assert!(reply["actions"].as_array().unwrap().is_empty());
        let (_, list) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        assert_eq!(list["nodes"][0]["targets"][0]["status"], "in_sync");
    }

    #[tokio::test]
    async fn a_node_is_never_sent_a_project_it_was_not_enrolled_for() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let (_, reply) = do_beat(
            &a,
            &n,
            beat_body(
                vec![target("pay", "payroll", "push", true, None)],
                vec![],
                0,
            ),
        )
        .await;
        assert!(reply["actions"].as_array().unwrap().is_empty());
        assert!(!reply.to_string().contains("do-not-send"));
        let (_, list) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        assert_eq!(list["nodes"][0]["targets"][0]["status"], "refused");
    }

    #[tokio::test]
    async fn a_locked_hub_observes_but_pushes_nothing_and_does_not_ack_results() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        h.state.shutdown_all_sessions();
        let res = ApplyResult {
            target: "env-main".into(),
            at: "t".into(),
            sha256: "aa".into(),
            ok: true,
            error: None,
        };
        let (st, reply) = do_beat(
            &a,
            &n,
            beat_body(
                vec![target("env-main", "edge", "push", true, None)],
                vec![res],
                0,
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(reply["hub_locked"], true);
        assert_eq!(reply["results_ack"], false);
        assert!(reply["actions"].as_array().unwrap().is_empty());
        let s = with_store(&h.state, |s| s.list()).unwrap();
        assert_eq!(s[0].targets[0].status, "unknown");
        assert!(
            s[0].last_seen.is_some(),
            "observe stopped when the hub locked"
        );
    }

    #[tokio::test]
    async fn apply_results_become_audit_rows_attributed_to_the_node_and_carry_no_content() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let res = ApplyResult {
            target: "env-main".into(),
            at: "2026-10-08T00:00:00Z".into(),
            sha256: rendered_sha(PASS),
            ok: false,
            error: Some("validate failed".into()),
        };
        let (_, reply) = do_beat(&a, &n, beat_body(vec![], vec![res], 0)).await;
        assert_eq!(reply["results_ack"], true);
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        let rows = vault_core::load_audit(&conn).unwrap();
        let row = rows
            .iter()
            .find(|r| r.action == "node.apply")
            .expect("no node.apply row");
        assert_eq!(row.actor.as_deref(), Some("node:vps-01"));
        assert!(row.details.as_deref().unwrap().contains("validate failed"));
        assert!(rows.iter().any(|r| r.action == "node.enroll"));
        assert!(rows.iter().any(|r| r.action == "node.token"));
        assert!(!rows
            .iter()
            .any(|r| r.details.as_deref().unwrap_or("").contains(PASS)));
        // Newest first: each row's prev_hash is the next row's entry_hash.
        for w in rows.windows(2) {
            assert_eq!(w[0].prev_hash, w[1].entry_hash, "audit chain broken");
        }
    }

    #[tokio::test]
    async fn heartbeats_write_no_audit_rows() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        let before = vault_core::load_audit(&conn).unwrap().len();
        for _ in 0..5 {
            do_beat(
                &a,
                &n,
                beat_body(
                    vec![target("env-main", "edge", "push", false, None)],
                    vec![],
                    0,
                ),
            )
            .await;
        }
        assert_eq!(vault_core::load_audit(&conn).unwrap().len(), before);
    }

    #[tokio::test]
    async fn replay_forgery_tamper_and_revocation_are_all_401() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let body = beat_body(vec![], vec![], 0);
        let ts = now_ms();
        assert_eq!(
            send(&a, n.signed_at("/api/nodes/beat", &body, ts)).await.0,
            StatusCode::OK
        );
        // The identical request again.
        assert_eq!(
            send(&a, n.signed_at("/api/nodes/beat", &body, ts)).await.0,
            StatusCode::UNAUTHORIZED
        );
        // A different key.
        let (other_seed, _) = generate_identity();
        let forged = Node {
            id: n.id.clone(),
            seed: other_seed,
            last_ts: std::cell::Cell::new(ts + 10),
        };
        assert_eq!(
            send(&a, forged.signed("/api/nodes/beat", &body)).await.0,
            StatusCode::UNAUTHORIZED
        );
        // A signature for one body used on another.
        let ts2 = ts + 100;
        let mut req = n.signed_at("/api/nodes/beat", &body, ts2);
        *req.body_mut() = Body::from(beat_body(
            vec![target("x", "edge", "push", true, None)],
            vec![],
            0,
        ));
        assert_eq!(send(&a, req).await.0, StatusCode::UNAUTHORIZED);
        // A signature for the beat route presented to the upload route.
        let mut up = n.signed_at("/api/nodes/beat", &body, ts2 + 1);
        *up.uri_mut() = "/api/nodes/upload".parse().unwrap();
        assert_eq!(send(&a, up).await.0, StatusCode::UNAUTHORIZED);
        // Skew.
        assert_eq!(
            send(
                &a,
                n.signed_at("/api/nodes/beat", &body, now_ms() + 120_000)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        // Revoked.
        let (st, _) = send(
            &a,
            owner_req(
                &h,
                "DELETE",
                &format!("/api/nodes/{}", n.id),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        assert_eq!(
            send(&a, n.signed("/api/nodes/beat", &body)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn an_enrollment_token_works_once() {
        let h = hub(true, true);
        let a = app(&h);
        let (_, tok) = send(
            &a,
            owner_req(
                &h,
                "POST",
                "/api/nodes/tokens",
                serde_json::json!({"name":"a","projects":["edge"]}),
            ),
        )
        .await;
        let enroll = |pk: String| {
            Request::builder()
                .method("POST")
                .uri("/api/nodes/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"token": tok["token"], "pubkey": pk}).to_string(),
                ))
                .unwrap()
        };
        assert_eq!(
            send(&a, enroll(generate_identity().1)).await.0,
            StatusCode::OK
        );
        assert_eq!(
            send(&a, enroll(generate_identity().1)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn guessing_enrollment_tokens_is_rate_limited() {
        let h = hub(true, true);
        let a = app(&h);
        let mut last = StatusCode::OK;
        for _ in 0..12 {
            last = send(
                &a,
                Request::builder()
                    .method("POST")
                    .uri("/api/nodes/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"token":"envn_guess","pubkey": generate_identity().1})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .0;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_pull_target_is_requested_uploaded_and_collected_exactly_once() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let pull = beat_body(
            vec![target("wg", "edge", "pull", false, Some("ab".repeat(32)))],
            vec![],
            0,
        );

        // Nothing to ask for before the node has reported the target.
        let (st, _) = send(
            &a,
            owner_req(
                &h,
                "POST",
                &format!("/api/nodes/{}/pull", n.id),
                serde_json::json!({"target":"wg"}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (_, r) = do_beat(&a, &n, pull.clone()).await;
        assert!(r["actions"].as_array().unwrap().is_empty());

        let (st, _) = send(
            &a,
            owner_req(
                &h,
                "POST",
                &format!("/api/nodes/{}/pull", n.id),
                serde_json::json!({"target":"wg"}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        // Not there yet.
        let get = || {
            owner_req(
                &h,
                "GET",
                &format!("/api/nodes/{}/content/wg", n.id),
                serde_json::json!({}),
            )
        };
        assert_eq!(send(&a, get()).await.0, StatusCode::NO_CONTENT);

        let (_, r) = do_beat(&a, &n, pull).await;
        assert_eq!(
            r["actions"][0],
            serde_json::json!({"kind":"upload","target":"wg"})
        );
        let body = serde_json::json!({
            "target": "wg",
            "content_b64": base64::engine::general_purpose::STANDARD
                .encode(b"[Interface]\nPrivateKey = abc\n")
        })
        .to_string();
        assert_eq!(
            send(&a, n.signed("/api/nodes/upload", body.as_bytes()))
                .await
                .0,
            StatusCode::NO_CONTENT
        );

        let (st, got) = send(&a, get()).await;
        assert_eq!(st, StatusCode::OK);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(got["content_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, b"[Interface]\nPrivateKey = abc\n");
        // Handed over once.
        assert_eq!(send(&a, get()).await.0, StatusCode::NOT_FOUND);
        // And the content was never written to the registry.
        let reg = std::fs::read_to_string(&h.state.nodes_path).unwrap();
        assert!(!reg.contains("PrivateKey"));
        assert!(!reg.contains(&base64::engine::general_purpose::STANDARD.encode(b"[Interface]")));
    }

    #[tokio::test]
    async fn an_unsolicited_upload_is_refused() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let body = serde_json::json!({"target":"wg","content_b64":"AAAA"}).to_string();
        assert_eq!(
            send(&a, n.signed("/api/nodes/upload", body.as_bytes()))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn accepting_a_pull_target_makes_it_in_sync_until_the_file_changes() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let sha = "ab".repeat(32);
        do_beat(
            &a,
            &n,
            beat_body(
                vec![target("wg", "edge", "pull", false, Some(sha.clone()))],
                vec![],
                0,
            ),
        )
        .await;
        let (st, r) = send(
            &a,
            owner_req(
                &h,
                "POST",
                &format!("/api/nodes/{}/accept", n.id),
                serde_json::json!({"target":"wg"}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{r}");
        assert_eq!(r["sha256"], sha);
        do_beat(
            &a,
            &n,
            beat_body(
                vec![target("wg", "edge", "pull", false, Some("cd".repeat(32)))],
                vec![],
                0,
            ),
        )
        .await;
        let s = with_store(&h.state, |s| s.list()).unwrap();
        assert_eq!(s[0].targets[0].status, "changed");
    }

    #[tokio::test]
    async fn a_vault_save_wakes_a_held_beat_and_the_new_content_arrives() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let body = beat_body(
            vec![target(
                "env-main",
                "edge",
                "push",
                true,
                Some(rendered_sha(PASS)),
            )],
            vec![],
            20,
        );
        let req = n.signed("/api/nodes/beat", &body);
        let a2 = a.clone();
        let task = tokio::spawn(async move { send(&a2, req).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "the beat returned without waiting");

        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        vault_core::save_vault(
            &conn,
            vault_with("second-value"),
            vault_core::SaveCtx::default(),
        )
        .unwrap();
        h.state.nodes_wake.notify_waiters();

        let (st, reply) = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("never woke")
            .unwrap();
        assert_eq!(st, StatusCode::OK);
        assert_eq!(reply["actions"][0]["sha256"], rendered_sha("second-value"));
    }

    fn wg_vault(second_ips: &str) -> serde_json::Value {
        let peer = |id: &str, ips: &str| {
            serde_json::json!({
                "id": id, "name": id, "chunk_type": "wg_peer",
                "fields": [{ "key": "AllowedIPs", "value": ips, "field_type": "var" }]
            })
        };
        serde_json::json!({
            "api_keys": [], "user_categories": [],
            "projects": [{
                "id": "w", "name": "w", "project_type": "wireguard",
                "chunks": [peer("a", "10.0.0.2/32"), peer("b", second_ips)]
            }]
        })
    }

    #[test]
    fn a_config_error_stops_a_project_from_being_rendered_for_a_node() {
        // Two peers claiming the same address is an error finding (the tunnel
        // would route to the wrong peer): exactly what a node must not be sent.
        let bad = wg_vault("10.0.0.2");
        let e = render_gated(&bad, &[], "w", "wireguard").unwrap_err();
        assert!(e.starts_with("config check:"), "{e}");
        // The same project with distinct addresses renders.
        let good = wg_vault("10.0.0.3/32");
        assert!(render_gated(&good, &[], "w", "wireguard").is_ok());
    }

    #[tokio::test]
    async fn a_project_that_fails_the_config_check_is_refused_not_pushed() {
        let h = hub(true, true);
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        vault_core::save_vault(&conn, wg_vault("10.0.0.2"), vault_core::SaveCtx::default())
            .unwrap();
        let a = app(&h);
        let n = enrolled(&h, &a, &["w"]).await;
        let mut t = target("wg", "w", "push", true, None);
        t.exporter = "wireguard".into();
        let (_, reply) = do_beat(&a, &n, beat_body(vec![t], vec![], 0)).await;
        assert!(reply["actions"].as_array().unwrap().is_empty());
        let s = with_store(&h.state, |s| s.list()).unwrap();
        assert_eq!(s[0].targets[0].status, "refused");
        assert!(s[0].targets[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("config check"));
    }
    #[tokio::test]
    async fn a_drifted_target_says_which_snapshot_of_the_history_it_still_matches() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        // The config as it was, recorded; then the vault moves on.
        let before =
            unv_cli::history::snapshot_all(&conn, &vault_with(PASS), Some("edge"), "save", None);
        assert_eq!(before.recorded, 1);
        vault_core::save_vault(&conn, vault_with("later"), vault_core::SaveCtx::default()).unwrap();
        let (_, _) = do_beat(
            &a,
            &n,
            beat_body(
                vec![target(
                    "env-main",
                    "edge",
                    "push",
                    false,
                    Some(rendered_sha(PASS)),
                )],
                vec![],
                0,
            ),
        )
        .await;
        let (_, list) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        let t = &list["nodes"][0]["targets"][0];
        assert_eq!(t["status"], "drift");
        assert_eq!(t["snapshot"]["seq"], 1, "{t}");
        assert!(!t.to_string().contains(PASS));
    }
    // ── Approval (Phase 37) ───────────────────────────────────────────────────

    async fn require(h: &Hub, a: &axum::Router, n: &Node) {
        let (st, r) = send(
            a,
            owner_req(
                h,
                "POST",
                &format!("/api/nodes/{}/policy", n.id),
                serde_json::json!({"approval":"required"}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{r}");
    }

    async fn approvals_of(h: &Hub, a: &axum::Router) -> Vec<serde_json::Value> {
        let (_, list) = send(a, owner_req(h, "GET", "/api/nodes", serde_json::json!({}))).await;
        list["nodes"][0]["approvals"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    async fn decide(
        h: &Hub,
        a: &axum::Router,
        id: &str,
        verb: &str,
    ) -> (StatusCode, serde_json::Value) {
        send(
            a,
            owner_req(
                h,
                "POST",
                &format!("/api/node-approvals/{id}/{verb}"),
                serde_json::json!({}),
            ),
        )
        .await
    }

    fn push_beat() -> Vec<u8> {
        beat_body(
            vec![target("env-main", "edge", "push", true, None)],
            vec![],
            0,
        )
    }

    #[tokio::test]
    async fn a_node_that_needs_a_human_is_sent_nothing_until_one_says_yes_to_those_bytes() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        require(&h, &a, &n).await;

        let (_, r) = do_beat(&a, &n, push_beat()).await;
        assert!(
            r["actions"].as_array().unwrap().is_empty(),
            "pushed without approval: {r}"
        );
        assert_eq!(r["pending"][0]["status"], "pending");
        assert!(!r.to_string().contains(PASS));

        // Asking again changes nothing: still one request, for the same bytes.
        do_beat(&a, &n, push_beat()).await;
        do_beat(&a, &n, push_beat()).await;
        let ap = approvals_of(&h, &a).await;
        assert_eq!(ap.len(), 1, "{ap:?}");
        assert_eq!(ap[0]["sha256"], rendered_sha(PASS));
        assert!(
            ap[0]["to_seq"].is_number(),
            "the proposal must be in the history: {ap:?}"
        );
        let (_, list) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        assert_eq!(
            list["nodes"][0]["targets"][0]["status"],
            "awaiting_approval"
        );

        let id = ap[0]["id"].as_str().unwrap().to_string();
        assert_eq!(decide(&h, &a, &id, "approve").await.0, StatusCode::OK);
        let (_, r) = do_beat(&a, &n, push_beat()).await;
        let act = &r["actions"][0];
        assert_eq!(act["kind"], "push");
        // The push carries a signed yes that verifies for this node, target and hash.
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        let public =
            vault_core::nodes::hub_public(&vault_core::nodes::hub_seed(&conn).unwrap()).unwrap();
        assert_eq!(r["hub_pubkey"], public);
        let signed: vault_core::nodes::SignedApproval =
            serde_json::from_value(act["approval"].clone()).unwrap();
        let tok = vault_core::nodes::verify_approval(
            &public,
            &signed,
            &n.id,
            "env-main",
            act["sha256"].as_str().unwrap(),
            now_secs(),
        )
        .unwrap();
        assert_eq!(tok.approved_by, "owner");
        assert_eq!(tok.approval_id, id);
        // Valid for an hour from the yes, not longer.
        assert!(
            tok.expires_secs <= now_secs() + vault_core::nodes::APPROVAL_TTL_SECS,
            "{}",
            tok.expires_secs
        );
        assert!(tok.expires_secs > now_secs());
    }

    #[tokio::test]
    async fn an_approval_is_for_the_bytes_that_were_shown_and_a_changed_vault_needs_a_new_one() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        require(&h, &a, &n).await;
        do_beat(&a, &n, push_beat()).await;
        let id = approvals_of(&h, &a).await[0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        decide(&h, &a, &id, "approve").await;

        // Before the node picks it up, the vault changes: the approved bytes are gone.
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        vault_core::save_vault(
            &conn,
            vault_with("second-value"),
            vault_core::SaveCtx::default(),
        )
        .unwrap();
        let (_, r) = do_beat(&a, &n, push_beat()).await;
        assert!(
            r["actions"].as_array().unwrap().is_empty(),
            "the old yes covered new bytes: {r}"
        );
        let ap = approvals_of(&h, &a).await;
        assert_eq!(ap.len(), 2);
        assert_eq!(ap[0]["sha256"], rendered_sha("second-value"));
        assert_eq!(ap[0]["status"], "pending");
        assert_eq!(
            ap[1]["status"], "approved",
            "the old approval stays what it was"
        );
    }

    #[tokio::test]
    async fn a_rejection_holds_the_push_and_is_final_for_those_bytes() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        require(&h, &a, &n).await;
        do_beat(&a, &n, push_beat()).await;
        let id = approvals_of(&h, &a).await[0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(decide(&h, &a, &id, "reject").await.0, StatusCode::OK);
        let (_, r) = do_beat(&a, &n, push_beat()).await;
        assert!(r["actions"].as_array().unwrap().is_empty());
        let (_, list) = send(
            &a,
            owner_req(&h, "GET", "/api/nodes", serde_json::json!({})),
        )
        .await;
        assert_eq!(list["nodes"][0]["targets"][0]["status"], "rejected");
        assert_eq!(
            approvals_of(&h, &a).await.len(),
            1,
            "a rejection must not be re-asked"
        );
        // A decided request cannot be decided again, either way.
        assert_eq!(decide(&h, &a, &id, "approve").await.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn only_the_owner_decides_and_a_node_cannot_approve_its_own_push() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        require(&h, &a, &n).await;
        do_beat(&a, &n, push_beat()).await;
        let id = approvals_of(&h, &a).await[0]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let no_auth = Request::builder()
            .method("POST")
            .uri(format!("/api/node-approvals/{id}/approve"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&a, no_auth).await.0, StatusCode::UNAUTHORIZED);
        // The node's own signed headers are not a session.
        let as_node = n.signed(&format!("/api/node-approvals/{id}/approve"), b"");
        assert_eq!(send(&a, as_node).await.0, StatusCode::UNAUTHORIZED);
        h.state.sessions.lock().unwrap().insert(
            "sub".into(),
            Session {
                vault_key: [7u8; 32],
                user_id: "someone".into(),
                is_owner: false,
                expires_at: Instant::now() + Duration::from_secs(600),
                hard_expires_at: Instant::now() + Duration::from_secs(600),
            },
        );
        let sub = Request::builder()
            .method("POST")
            .uri(format!("/api/node-approvals/{id}/approve"))
            .header("authorization", "Bearer sub")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&a, sub).await.0, StatusCode::FORBIDDEN);
        assert_eq!(approvals_of(&h, &a).await[0]["status"], "pending");
        // And the policy route is the owner's too.
        let sub_policy = Request::builder()
            .method("POST")
            .uri(format!("/api/nodes/{}/policy", n.id))
            .header("authorization", "Bearer sub")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"approval":"none"}"#))
            .unwrap();
        assert_eq!(send(&a, sub_policy).await.0, StatusCode::FORBIDDEN);
        let (st, _) = send(
            &a,
            owner_req(
                &h,
                "POST",
                &format!("/api/nodes/{}/policy", n.id),
                serde_json::json!({"approval":"maybe"}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn requests_and_decisions_are_audited_and_the_chain_holds() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        require(&h, &a, &n).await;
        do_beat(&a, &n, push_beat()).await;
        let id = approvals_of(&h, &a).await[0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        decide(&h, &a, &id, "approve").await;
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        let rows = vault_core::load_audit(&conn).unwrap();
        for action in ["node.policy", "node.approval.request", "node.approve"] {
            assert!(rows.iter().any(|r| r.action == action), "no {action} row");
        }
        let req = rows
            .iter()
            .find(|r| r.action == "node.approval.request")
            .unwrap();
        assert_eq!(req.actor.as_deref(), Some("node:vps-01"));
        assert!(!rows
            .iter()
            .any(|r| r.details.as_deref().unwrap_or("").contains(PASS)));
        // One request row per request, however many beats asked.
        do_beat(&a, &n, push_beat()).await;
        do_beat(&a, &n, push_beat()).await;
        let after = vault_core::load_audit(&conn).unwrap();
        assert_eq!(
            after
                .iter()
                .filter(|r| r.action == "node.approval.request")
                .count(),
            1
        );
        for w in after.windows(2) {
            assert_eq!(w[0].prev_hash, w[1].entry_hash, "audit chain broken");
        }
    }

    #[tokio::test]
    async fn turning_the_policy_off_lets_pushes_through_again_and_a_consumed_yes_does_not_linger() {
        let h = hub(true, true);
        let a = app(&h);
        let n = enrolled(&h, &a, &["edge"]).await;
        require(&h, &a, &n).await;
        do_beat(&a, &n, push_beat()).await;
        let id = approvals_of(&h, &a).await[0]["id"]
            .as_str()
            .unwrap()
            .to_string();
        decide(&h, &a, &id, "approve").await;
        // The node reports having the approved bytes: the approval is spent.
        do_beat(
            &a,
            &n,
            beat_body(
                vec![target(
                    "env-main",
                    "edge",
                    "push",
                    true,
                    Some(rendered_sha(PASS)),
                )],
                vec![],
                0,
            ),
        )
        .await;
        assert_eq!(approvals_of(&h, &a).await[0]["status"], "consumed");
        let (st, _) = send(
            &a,
            owner_req(
                &h,
                "POST",
                &format!("/api/nodes/{}/policy", n.id),
                serde_json::json!({"approval":"none"}),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let (_, r) = do_beat(&a, &n, push_beat()).await;
        assert_eq!(r["actions"][0]["kind"], "push");
        assert!(
            r["actions"][0]["approval"].is_null(),
            "a node that needs none is sent none"
        );
    }
    // ── Stack integrations (Phase 38) ─────────────────────────────────────────

    fn prom_vault(second_job: &str) -> serde_json::Value {
        let job = |id: &str, name: &str, targets: &str| {
            serde_json::json!({
                "id": id, "name": name, "chunk_type": "prom_scrape",
                "fields": [{ "key": "targets", "value": targets, "field_type": "list" }]
            })
        };
        serde_json::json!({
            "api_keys": [], "user_categories": [],
            "projects": [{
                "id": "mon", "name": "mon", "project_type": "prometheus",
                "chunks": [job("j1", "node", "n1:9100"), job("j2", second_job, "n2:9100")]
            }]
        })
    }

    #[tokio::test]
    async fn a_node_is_sent_a_prometheus_file_rendered_from_its_descriptor() {
        let h = hub(true, true);
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        vault_core::save_vault(&conn, prom_vault("api"), vault_core::SaveCtx::default()).unwrap();
        let a = app(&h);
        let n = enrolled(&h, &a, &["mon"]).await;
        let mut t = target("prom", "mon", "push", true, None);
        t.exporter = "prometheus".into();
        let (_, r) = do_beat(&a, &n, beat_body(vec![t], vec![], 0)).await;
        let act = &r["actions"][0];
        assert_eq!(act["kind"], "push", "{r}");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(act["content_b64"].as_str().unwrap())
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("job_name: node") && text.contains("job_name: api"),
            "{text}"
        );
        assert!(text.starts_with("# Generated by UnENVerse\n"));
    }

    #[tokio::test]
    async fn a_prometheus_file_the_descriptors_rules_forbid_is_withheld_not_pushed() {
        let h = hub(true, true);
        let conn = vault_core::open_db(&h.state.db_path, &h.key).unwrap();
        // Two jobs with one name: Prometheus would refuse the file.
        vault_core::save_vault(&conn, prom_vault("node"), vault_core::SaveCtx::default()).unwrap();
        let a = app(&h);
        let n = enrolled(&h, &a, &["mon"]).await;
        let mut t = target("prom", "mon", "push", true, None);
        t.exporter = "prometheus".into();
        let (_, r) = do_beat(&a, &n, beat_body(vec![t], vec![], 0)).await;
        assert!(r["actions"].as_array().unwrap().is_empty(), "{r}");
        let s = with_store(&h.state, |s| s.list()).unwrap();
        assert_eq!(s[0].targets[0].status, "refused");
        assert!(s[0].targets[0]
            .refusal
            .as_deref()
            .unwrap()
            .contains("two scrape jobs are named"));
    }
}
