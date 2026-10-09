//! Phase 34 end to end: a real `Agent` from `unv-cli` against a real hub over
//! a real TCP socket. The unit tests in `src/nodes.rs` prove each route; this
//! proves the two halves agree on the wire (signing, framing, the order of
//! events), which no test of either half alone can.

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::Request;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tower::ServiceExt;
use unv_cli::node_agent::{self, Agent};
use unv_server::{build_router, AppState};

fn scratch(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("unv-nodes-e2e-{tag}-{n}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn vault(value: &str) -> serde_json::Value {
    serde_json::json!({
        "api_keys": [], "user_categories": [],
        "projects": [{
            "id": "edge", "name": "edge", "project_type": "generic",
            "chunks": [{
                "id": "c1", "name": "app.env", "chunk_type": "env_file",
                "fields": [{ "key": "TOKEN", "value": value }]
            }]
        }]
    })
}

struct Hub {
    state: AppState,
    owner: String,
    key: [u8; 32],
    db: PathBuf,
    url: String,
}

async fn start() -> Hub {
    let d = scratch("hub");
    let key = [9u8; 32];
    let state = AppState::new(
        d.join("vault.db"),
        d.join("vault.salt"),
        None,
        480,
        24,
        false,
    )
    .with_nodes(true, None);
    let conn = vault_core::open_db(&d.join("vault.db"), &key).unwrap();
    vault_core::init_schema(&conn).unwrap();
    vault_core::save_vault(&conn, vault("first"), vault_core::SaveCtx::default()).unwrap();
    let owner = state.adopt_owner_key(key, "owner".into());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state.clone(), addr.port());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Hub {
        state,
        owner,
        key,
        db: d.join("vault.db"),
        url: format!("http://{addr}"),
    }
}

impl Hub {
    async fn owner(
        &self,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let app = build_router(self.state.clone(), 8743).layer(MockConnectInfo(
            "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
        ));
        let r = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {}", self.owner))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let st = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (
            st,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }

    fn save(&self, v: serde_json::Value) {
        let conn = vault_core::open_db(&self.db, &self.key).unwrap();
        vault_core::save_vault(&conn, v, vault_core::SaveCtx::default()).unwrap();
    }

    fn audit(&self) -> Vec<vault_core::AuditRow> {
        let conn = vault_core::open_db(&self.db, &self.key).unwrap();
        vault_core::load_audit(&conn).unwrap()
    }
}

fn config(dir: &Path, targets: &str) -> PathBuf {
    let p = dir.join("node.toml");
    std::fs::write(&p, targets).unwrap();
    p
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

async fn enroll(h: &Hub, dir: &Path, name: &str) {
    let (st, tok) = h
        .owner(
            "POST",
            "/api/nodes/tokens",
            serde_json::json!({ "name": name, "projects": ["edge"] }),
        )
        .await;
    assert_eq!(st, 200, "{tok}");
    let (dir, url, token) = (
        dir.to_path_buf(),
        h.url.clone(),
        tok["token"].as_str().unwrap().to_string(),
    );
    blocking(move || node_agent::enroll(&dir, &url, &token, None, false, None).map(|_| ()))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_enrolls_applies_reports_and_stays_in_sync() {
    let h = start().await;
    let dir = scratch("agent");
    let out = dir.join("app.env");
    enroll(&h, &dir, "vps-01").await;
    let cfg = config(
        &dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\nvalidate=\"exit 0\"\n",
            out.display()
        ),
    );
    let (d2, c2) = (dir.clone(), cfg.clone());
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();

    // Beat 1: the file does not exist; the hub pushes it; the agent writes it.
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert_eq!(r.unwrap().actions.len(), 1);
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("TOKEN=first"));

    // Beat 2: reports the new hash and the apply result; nothing left to do.
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    let reply = r.unwrap();
    assert!(reply.actions.is_empty());
    assert!(reply.results_ack);
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    assert_eq!(list["nodes"][0]["targets"][0]["status"], "in_sync");
    assert_eq!(list["nodes"][0]["targets"][0]["state"], "applied");
    let rows = h.audit();
    let apply = rows
        .iter()
        .find(|r| r.action == "node.apply")
        .expect("no apply row");
    assert!(apply.details.as_deref().unwrap().contains("\"ok\":true"));
    assert_eq!(apply.actor.as_deref(), Some("node:vps-01"));

    // The vault changes; the next beat carries the new file.
    h.save(vault("second"));
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert_eq!(r.unwrap().actions.len(), 1);
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("TOKEN=second"));
    // …and the previous version was kept, privately.
    let kept = vault_core::nodes_apply::kept_versions(&dir, "env-main");
    assert_eq!(kept.len(), 1);
    assert!(std::fs::read_to_string(&kept[0])
        .unwrap()
        .contains("TOKEN=first"));

    // Revoked: the next beat is refused and says so.
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    let id = list["nodes"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(
        h.owner("DELETE", &format!("/api/nodes/{id}"), serde_json::json!({}))
            .await
            .0,
        204
    );
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    let e = r.unwrap_err();
    assert_eq!(e.code, unv_cli::error::Code::Denied, "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_validate_leaves_the_file_alone_and_the_failure_reaches_the_audit_log() {
    let h = start().await;
    let dir = scratch("agent-bad");
    let out = dir.join("app.env");
    enroll(&h, &dir, "vps-02").await;
    let cfg = config(
        &dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\nvalidate=\"exit 1\"\n",
            out.display()
        ),
    );
    let (d2, c2) = (dir.clone(), cfg.clone());
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(
        !out.exists(),
        "a file that failed validation was left on disk"
    );
    let (_, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    let rows = h.audit();
    let apply = rows
        .iter()
        .find(|r| r.action == "node.apply")
        .expect("no apply row");
    assert!(apply.details.as_deref().unwrap().contains("\"ok\":false"));
    assert!(apply
        .details
        .as_deref()
        .unwrap()
        .contains("validate failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_off_is_observe_only_and_a_locked_hub_changes_nothing() {
    let h = start().await;
    let dir = scratch("agent-observe");
    let out = dir.join("app.env");
    enroll(&h, &dir, "vps-03").await;
    let cfg = config(
        &dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\n",
            out.display()
        ),
    );
    let (d2, c2) = (dir.clone(), cfg.clone());
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(r.unwrap().actions.is_empty());
    assert!(!out.exists());

    // Flip apply on, then lock the hub: still nothing is written.
    let cfg = config(
        &dir,
        &format!("[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\n", out.display()),
    );
    let (d2, c2) = (dir.clone(), cfg);
    drop(agent);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    h.state.shutdown_all_sessions();
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    let reply = r.unwrap();
    assert!(reply.hub_locked);
    assert!(reply.actions.is_empty());
    assert!(!out.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pull_target_travels_to_the_owner_once_and_only_on_request() {
    let h = start().await;
    let dir = scratch("agent-pull");
    let file = dir.join("wg0.conf");
    std::fs::write(&file, "[Interface]\nPrivateKey = abc123\n").unwrap();
    enroll(&h, &dir, "laptop").await;
    let cfg = config(
        &dir,
        &format!("[[target]]\nid=\"wg\"\npath='{}'\nproject=\"edge\"\nexporter=\"wireguard\"\nmode=\"pull\"\n", file.display()),
    );
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    let id = list["nodes"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(list["nodes"][0]["targets"][0]["status"], "unreviewed");
    // No pull requested: the file never leaves the host.
    assert_eq!(
        h.owner(
            "GET",
            &format!("/api/nodes/{id}/content/wg"),
            serde_json::json!({})
        )
        .await
        .0,
        404
    );

    assert_eq!(
        h.owner(
            "POST",
            &format!("/api/nodes/{id}/pull"),
            serde_json::json!({"target":"wg"})
        )
        .await
        .0,
        202
    );
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    assert_eq!(r.unwrap().actions.len(), 1);
    let (st, got) = h
        .owner(
            "GET",
            &format!("/api/nodes/{id}/content/wg"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(st, 200);
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(got["content_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(bytes, std::fs::read(&file).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn results_survive_a_locked_hub_and_are_reported_when_it_returns() {
    let h = start().await;
    let dir = scratch("agent-ack");
    let out = dir.join("app.env");
    enroll(&h, &dir, "vps-04").await;
    let cfg = config(
        &dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\n",
            out.display()
        ),
    );
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    // Apply while the hub is up, then lock it before the result is reported.
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(out.exists());
    h.state.shutdown_all_sessions();
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(
        !r.unwrap().results_ack,
        "a locked hub claimed to have kept the result"
    );
    // Unlock again: the same result arrives and is audited exactly once.
    let again = h.state.adopt_owner_key(h.key, "owner".into());
    assert!(!again.is_empty());
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(r.unwrap().results_ack);
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    assert!(r.unwrap().results_ack);
    let applies = h
        .audit()
        .iter()
        .filter(|r| r.action == "node.apply")
        .count();
    assert_eq!(applies, 1, "the apply was audited {applies} times");
}

fn vault_with_stripe(key: &str) -> serde_json::Value {
    serde_json::json!({
        "api_keys": [{ "id": "stripe-1", "provider": "Stripe", "secretType": "api_key", "api_key": key,
                       "console_url": "https://dashboard.stripe.example/keys" }],
        "user_categories": [],
        "projects": [{
            "id": "edge", "name": "edge", "project_type": "generic",
            "chunks": [{ "id": "c1", "name": "app.env", "chunk_type": "env_file",
                         "fields": [{ "key": "STRIPE_KEY", "value": "${Stripe/api_key}" }] }]
        }]
    })
}

async fn apply_once(h: &Hub, name: &str) -> (std::path::PathBuf, PathBuf) {
    let dir = scratch("agent-blast");
    let out = dir.join("app.env");
    enroll(h, &dir, name).await;
    let cfg = config(
        &dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\n",
            out.display()
        ),
    );
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    // The second beat reports the apply result, which is what the hub audits.
    let (_, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    (out, dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blast_radius_names_what_a_node_was_sent_and_stops_naming_it_once_rotated() {
    let h = start().await;
    h.save(vault_with_stripe("sk_live_BLASTONE_aaaa"));
    let (out, _dir) = apply_once(&h, "vps-05").await;
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("sk_live_BLASTONE_aaaa"));

    let (st, r) = h
        .owner(
            "POST",
            "/api/history",
            serde_json::json!({"op":"blast","args":{"host":"vps-05"}}),
        )
        .await;
    assert_eq!(st, 200, "{r}");
    assert_eq!(r["deployments"], 1, "{r}");
    let e = &r["entries"][0];
    assert_eq!(
        (e["provider"].as_str(), e["still_current"].as_bool()),
        (Some("Stripe"), Some(true)),
        "{r}"
    );
    assert_eq!(e["console_url"], "https://dashboard.stripe.example/keys");
    assert_eq!(r["command"], "unv entry rotate 'Stripe' --generate");
    // The report names the credential, never its value.
    assert!(!r.to_string().contains("sk_live_BLASTONE"), "{r}");

    // Rotated since: the value that was on the host is no longer the live one.
    let conn = vault_core::open_db(&h.db, &h.key).unwrap();
    let mut doc = vault_with_stripe("sk_live_BLASTTWO_bbbb");
    doc["api_keys"][0]["version_history"] =
        serde_json::json!([{ "value": "sk_live_BLASTONE_aaaa", "field": "api_key" }]);
    vault_core::save_vault(&conn, doc, vault_core::SaveCtx::default()).unwrap();
    let (_, r2) = h
        .owner(
            "POST",
            "/api/history",
            serde_json::json!({"op":"blast","args":{"host":"vps-05"}}),
        )
        .await;
    assert_eq!(r2["entries"][0]["still_current"], false, "{r2}");
    assert_eq!(r2["command"], "", "{r2}");
    // A host that was never sent anything has an empty answer, not an error.
    let (st, none) = h
        .owner(
            "POST",
            "/api/history",
            serde_json::json!({"op":"blast","args":{"host":"nobody"}}),
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(none["deployments"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_is_recorded_before_it_is_sent_and_a_missing_history_is_reported_not_hidden() {
    // With history on, the push itself creates the snapshot even though no save
    // went through the server's hook (the vault was written directly).
    let h = start().await;
    h.save(vault_with_stripe("sk_live_PUSHREC_cccc"));
    apply_once(&h, "vps-06").await;
    let (_, l) = h
        .owner(
            "POST",
            "/api/history",
            serde_json::json!({"op":"list","args":{"project":"edge"}}),
        )
        .await;
    assert!(
        l["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["cause"] == "push:vps-06"),
        "{l}"
    );

    // With history off, the apply still happens but its contents are unknown.
    let h2 = start().await;
    h2.save(vault_with_stripe("sk_live_NOHIST_dddd"));
    h2.owner(
        "POST",
        "/api/history",
        serde_json::json!({"op":"policy","args":{"enabled":false}}),
    )
    .await;
    apply_once(&h2, "vps-07").await;
    let (_, r) = h2
        .owner(
            "POST",
            "/api/history",
            serde_json::json!({"op":"blast","args":{"host":"vps-07"}}),
        )
        .await;
    assert_eq!(r["deployments"], 1, "{r}");
    assert_eq!(r["unaccounted"].as_array().unwrap().len(), 1, "{r}");
    assert!(r["entries"].as_array().unwrap().is_empty());
}

async fn set_policy(h: &Hub, node_name: &str) {
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    let id = list["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == node_name)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, r) = h
        .owner(
            "POST",
            &format!("/api/nodes/{id}/policy"),
            serde_json::json!({"approval":"required"}),
        )
        .await;
    assert_eq!(st, 200, "{r}");
}

async fn pending_approval(h: &Hub) -> String {
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    let all = list["nodes"][0]["approvals"].as_array().unwrap().clone();
    all.iter()
        .find(|a| a["status"] == "pending")
        .unwrap_or_else(|| panic!("nothing is awaiting approval: {all:?}"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn approval_config(dir: &Path, out: &Path) -> PathBuf {
    config(
        dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\nrequire_approval=true\n",
            out.display()
        ),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_push_waits_for_a_human_and_a_changed_vault_waits_again() {
    let h = start().await;
    let dir = scratch("agent-approval");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-1").await;
    set_policy(&h, "prod-1").await;
    let cfg = approval_config(&dir, &out);
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();

    // Held: nothing is written, and the node is told it is waiting.
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    let reply = r.unwrap();
    assert!(reply.actions.is_empty(), "{reply:?}");
    assert_eq!(reply.pending.len(), 1);
    assert!(!out.exists(), "a file was written before anyone said yes");

    // Approved: the next beat carries the signed yes, and the node, which
    // requires it, accepts it and writes.
    let id = pending_approval(&h).await;
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/node-approvals/{id}/approve"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(st, 200);
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert_eq!(r.unwrap().actions.len(), 1);
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("TOKEN=first"));
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;

    // The vault changes: new bytes, new question; the file stays as it was.
    h.save(vault("second"));
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(r.unwrap().actions.is_empty());
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("TOKEN=first"));
    let id2 = pending_approval(&h).await;
    assert_ne!(id2, id);
    h.owner(
        "POST",
        &format!("/api/node-approvals/{id2}/approve"),
        serde_json::json!({}),
    )
    .await;
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    assert_eq!(r.unwrap().actions.len(), 1);
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("TOKEN=second"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_requires_approval_refuses_every_push_that_is_not_exactly_approved() {
    use base64::Engine;
    use vault_core::nodes::{sign_approval, ApprovalToken, SignedApproval};
    let h = start().await;
    let dir = scratch("agent-forge");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-2").await;
    let cfg = approval_config(&dir, &out);
    // The node has pinned the hub's key (it learns it from a beat; set it here so
    // the forged pushes below are judged on their approvals alone).
    let conn = vault_core::open_db(&h.db, &h.key).unwrap();
    let hub_seed = vault_core::nodes::hub_seed(&conn).unwrap();
    let state_path = node_agent::state_path(&dir);
    let mut st: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    st["hub_pubkey"] = serde_json::json!(vault_core::nodes::hub_public(&hub_seed).unwrap());
    std::fs::write(&state_path, st.to_string()).unwrap();
    let node_id = st["node_id"].as_str().unwrap().to_string();

    let content = b"TOKEN=forged\n".to_vec();
    let sha = vault_core::nodes_apply::sha256_hex(&content);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let tok = |node: &str, target: &str, sha: &str, exp: i64, nonce: &str| ApprovalToken {
        v: 1,
        node_id: node.into(),
        target: target.into(),
        sha256: sha.into(),
        approval_id: "a".into(),
        approved_by: "owner".into(),
        approved_at: "t".into(),
        expires_secs: exp,
        nonce: nonce.into(),
    };
    let push = |approval: Option<SignedApproval>| vault_core::nodes::BeatReply {
        actions: vec![vault_core::nodes::Action::Push {
            target: "env-main".into(),
            sha256: sha.clone(),
            content_b64: base64::engine::general_purpose::STANDARD.encode(&content),
            approval,
        }],
        ..Default::default()
    };
    let other_seed = vault_core::nodes::generate_hub_seed();
    let cases: Vec<(&str, Option<SignedApproval>)> = vec![
        ("no approval", None),
        (
            "another hub's key",
            Some(
                sign_approval(
                    &other_seed,
                    &tok(&node_id, "env-main", &sha, now + 600, "n1"),
                )
                .unwrap(),
            ),
        ),
        (
            "other bytes",
            Some(
                sign_approval(
                    &hub_seed,
                    &tok(&node_id, "env-main", "deadbeef", now + 600, "n2"),
                )
                .unwrap(),
            ),
        ),
        (
            "other target",
            Some(sign_approval(&hub_seed, &tok(&node_id, "wg", &sha, now + 600, "n3")).unwrap()),
        ),
        (
            "other node",
            Some(
                sign_approval(
                    &hub_seed,
                    &tok("someone-else", "env-main", &sha, now + 600, "n4"),
                )
                .unwrap(),
            ),
        ),
        (
            "expired",
            Some(
                sign_approval(&hub_seed, &tok(&node_id, "env-main", &sha, now - 1, "n5")).unwrap(),
            ),
        ),
    ];
    let (d2, c2) = (dir.clone(), cfg.clone());
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    for (label, approval) in cases {
        let reply = push(approval);
        agent = blocking(move || {
            agent.act(&reply);
            agent
        })
        .await;
        assert!(!out.exists(), "wrote a file on a push with {label}");
    }

    // The right one writes, once; replaying it does not write again.
    let good = sign_approval(
        &hub_seed,
        &tok(&node_id, "env-main", &sha, now + 600, "n-good"),
    )
    .unwrap();
    let reply = push(Some(good.clone()));
    agent = blocking(move || {
        agent.act(&reply);
        agent
    })
    .await;
    assert_eq!(std::fs::read(&out).unwrap(), content);
    std::fs::remove_file(&out).unwrap();
    let reply = push(Some(good));
    agent = blocking(move || {
        agent.act(&reply);
        agent
    })
    .await;
    assert!(!out.exists(), "a spent approval was accepted twice");

    // Every refusal was reported, with its reason, to the hub's audit log.
    let (_, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    let errs: Vec<String> = h
        .audit()
        .iter()
        .filter(|r| r.action == "node.apply")
        .map(|r| r.details.clone().unwrap_or_default())
        .collect();
    for needle in [
        "carries no approval",
        "does not verify",
        "different bytes",
        "different target",
        "different node",
        "expired",
        "already used",
    ] {
        assert!(
            errs.iter().any(|e| e.contains(needle)),
            "no failed apply mentions '{needle}': {errs:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_hub_signing_key_is_refused() {
    let h = start().await;
    let dir = scratch("agent-pin");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-3").await;
    let cfg = approval_config(&dir, &out);
    // A node that has pinned a key that is not this hub's.
    let state_path = node_agent::state_path(&dir);
    let mut st: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let wrong = vault_core::nodes::hub_public(&vault_core::nodes::generate_hub_seed()).unwrap();
    st["hub_pubkey"] = serde_json::json!(wrong);
    std::fs::write(&state_path, st.to_string()).unwrap();
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    let e = r.unwrap_err();
    assert_eq!(e.code, unv_cli::error::Code::Denied, "{e}");
    assert!(e.message.contains("approval-signing key changed"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_has_not_yet_seen_the_hubs_key_writes_nothing_that_needs_approval() {
    use base64::Engine;
    let h = start().await;
    let dir = scratch("agent-nokey");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-4").await;
    let cfg = approval_config(&dir, &out);
    let content = b"TOKEN=x\n".to_vec();
    let sha = vault_core::nodes_apply::sha256_hex(&content);
    let conn = vault_core::open_db(&h.db, &h.key).unwrap();
    let seed = vault_core::nodes::hub_seed(&conn).unwrap();
    let st: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(node_agent::state_path(&dir)).unwrap())
            .unwrap();
    let signed = vault_core::nodes::sign_approval(
        &seed,
        &vault_core::nodes::ApprovalToken {
            v: 1,
            node_id: st["node_id"].as_str().unwrap().into(),
            target: "env-main".into(),
            sha256: sha.clone(),
            approval_id: "a".into(),
            approved_by: "owner".into(),
            approved_at: "t".into(),
            expires_secs: i64::MAX / 2,
            nonce: "n".into(),
        },
    )
    .unwrap();
    let reply = vault_core::nodes::BeatReply {
        actions: vec![vault_core::nodes::Action::Push {
            target: "env-main".into(),
            sha256: sha,
            content_b64: base64::engine::general_purpose::STANDARD.encode(&content),
            approval: Some(signed),
        }],
        ..Default::default()
    };
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    // The hub's key has not reached this node (no beat has happened), so a perfectly
    // valid approval is still not one the node can check.
    agent = blocking(move || {
        agent.act(&reply);
        agent
    })
    .await;
    assert!(!out.exists());
    let (_, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    let errs: Vec<String> = h
        .audit()
        .iter()
        .filter(|r| r.action == "node.apply")
        .map(|r| r.details.clone().unwrap_or_default())
        .collect();
    assert!(
        errs.iter()
            .any(|e| e.contains("has not yet seen the hub's approval key")),
        "{errs:?}"
    );
}

// ── Phase 34.1: the hub dials a node that listens ─────────────────────────────

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A listening node: enrolled, serving on its own thread. Dropping the guard
/// stops it.
struct Listening {
    dir: PathBuf,
    port: u16,
    fingerprint: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn listening_node(h: &Hub, name: &str, target_path: &Path, apply: bool) -> Listening {
    let dir = scratch(name);
    let port = free_port();
    let (st, tok) = h
        .owner(
            "POST",
            "/api/nodes/tokens",
            serde_json::json!({ "name": name, "projects": ["edge"] }),
        )
        .await;
    assert_eq!(st, 200, "{tok}");
    let (d, url, token) = (
        dir.clone(),
        h.url.clone(),
        tok["token"].as_str().unwrap().to_string(),
    );
    let bind = format!("127.0.0.1:{port}");
    let advertise = format!("https://127.0.0.1:{port}");
    blocking(move || node_agent::enroll(&d, &url, &token, None, false, Some((&bind, &advertise))))
        .await
        .unwrap();
    let cfg = config(
        &dir,
        &format!(
            "[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply={apply}\nvalidate=\"exit 0\"\n",
            target_path.display()
        ),
    );
    let fingerprint = vault_core::tls::fingerprint_of_pem(
        &std::fs::read_to_string(dir.join(node_agent::TLS_CERT_FILE)).unwrap(),
    )
    .unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (d, s2) = (dir.clone(), stop.clone());
    std::thread::spawn(move || {
        let mut agent = Agent::new(&d, &cfg).unwrap();
        let _ = unv_cli::node_listen::serve(&mut agent, &s2);
    });
    // Wait until it accepts.
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Listening {
        dir,
        port,
        fingerprint,
        stop,
    }
}

async fn wait_for(path: &Path, needle: &str, secs: u64) -> bool {
    for _ in 0..secs * 10 {
        if std::fs::read_to_string(path).is_ok_and(|t| t.contains(needle)) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hub_dials_a_listening_node_and_a_save_reaches_it() {
    let h = start().await;
    let out = scratch("listen-out").join("app.env");
    let node = listening_node(&h, "pub-1", &out, true).await;
    h.state.start_node_poller();

    // The poller's first tick polls every listening node at once.
    assert!(
        wait_for(&out, "TOKEN=first", 20).await,
        "the first push never arrived"
    );
    // The node writes the file while it is still answering the poll, so the hub
    // stamps `last_polled` a moment after the file appears (observed on Windows
    // runners). Wait for the stamp instead of reading it once.
    let mut list = serde_json::Value::Null;
    for _ in 0..100 {
        list = h.owner("GET", "/api/nodes", serde_json::json!({})).await.1;
        if list["nodes"][0]["last_polled"].is_string() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        list["nodes"][0]["listen"]["endpoint"],
        format!("https://127.0.0.1:{}", node.port)
    );
    assert!(list["nodes"][0]["last_polled"].is_string());

    // A save through the API wakes the poller; no waiting out the interval.
    let mut doc = vault("second");
    doc["projects"][0]["chunks"][0]["fields"][0]["value"] = serde_json::json!("second");
    let (st, _) = h.owner("PUT", "/api/vault", doc).await;
    assert_eq!(st, 204);
    assert!(
        wait_for(&out, "TOKEN=second", 10).await,
        "a save did not wake the poller"
    );

    // The apply was recorded exactly as a dialled node's is.
    let rows = h.audit();
    let apply = rows
        .iter()
        .find(|r| r.action == "node.apply")
        .expect("no apply row");
    assert_eq!(apply.actor.as_deref(), Some("node:pub-1"));
    drop(node);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listening_node_answers_only_the_hub_it_enrolled_with_and_only_once_per_request() {
    let h = start().await;
    let out = scratch("listen-auth").join("app.env");
    let node = listening_node(&h, "pub-2", &out, false).await;
    let base = format!("https://127.0.0.1:{}", node.port);
    let seed = vault_core::nodes::NodeStore::open(&h.db.parent().unwrap().join("nodes.json"))
        .unwrap()
        .hub_node_key()
        .unwrap()
        .0;
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    };
    let fp = node.fingerprint.clone();
    let post = move |path: &'static str, ts: i64, sig: String, body: &'static [u8]| {
        let (fp, base) = (fp.clone(), base.clone());
        blocking(move || unv_cli::tls::hub_post(&fp, &base, path, ts, &sig, body))
    };
    let sign = |seed: &str, path: &str, ts: i64, body: &[u8]| {
        vault_core::nodes::sign_hub_request(seed, "POST", path, ts, body).unwrap()
    };

    // A correctly signed poll is answered with a signed beat.
    let ts = now();
    let ok = post(
        "/node/v1/poll",
        ts,
        sign(&seed, "/node/v1/poll", ts, b""),
        b"",
    )
    .await
    .unwrap();
    assert_eq!(ok.status, 200);
    assert!(ok.headers.contains_key("x-node-sig"));
    // The same request again is a replay.
    let replay = post(
        "/node/v1/poll",
        ts,
        sign(&seed, "/node/v1/poll", ts, b""),
        b"",
    )
    .await
    .unwrap();
    assert_eq!(replay.status, 401);
    // Another key, a stale clock, a signature for another path or body: all 401.
    let other = vault_core::nodes::generate_hub_seed();
    let t1 = now() + 1;
    assert_eq!(
        post(
            "/node/v1/poll",
            t1,
            sign(&other, "/node/v1/poll", t1, b""),
            b""
        )
        .await
        .unwrap()
        .status,
        401
    );
    let old = now() - 5 * 60_000;
    assert_eq!(
        post(
            "/node/v1/poll",
            old,
            sign(&seed, "/node/v1/poll", old, b""),
            b""
        )
        .await
        .unwrap()
        .status,
        401
    );
    let future = now() + 5 * 60_000;
    assert_eq!(
        post(
            "/node/v1/poll",
            future,
            sign(&seed, "/node/v1/poll", future, b""),
            b""
        )
        .await
        .unwrap()
        .status,
        401
    );
    let t2 = now() + 2;
    assert_eq!(
        post(
            "/node/v1/act",
            t2,
            sign(&seed, "/node/v1/poll", t2, b"{}"),
            b"{}"
        )
        .await
        .unwrap()
        .status,
        401
    );
    // A node signature is not a hub signature.
    let node_state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(node_agent::state_path(&node.dir)).unwrap())
            .unwrap();
    let t3 = now() + 3;
    let node_sig = vault_core::nodes::sign_request(
        node_state["seed"].as_str().unwrap(),
        "POST",
        "/node/v1/poll",
        t3,
        b"",
    )
    .unwrap();
    assert_eq!(
        post("/node/v1/poll", t3, node_sig, b"")
            .await
            .unwrap()
            .status,
        401
    );
    // Unknown routes are 404 only after... nothing: they are refused before auth.
    let t4 = now() + 4;
    assert_eq!(
        post(
            "/node/v1/other",
            t4,
            sign(&seed, "/node/v1/other", t4, b""),
            b""
        )
        .await
        .unwrap()
        .status,
        404
    );

    // A client that can only speak TLS 1.2 is refused at the handshake (when openssl
    // is installed to be that client).
    if let Ok(o) = std::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{}", node.port),
            "-tls1_2",
        ])
        .stdin(std::process::Stdio::null())
        .output()
    {
        let text =
            String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
        assert!(
            text.contains("Cipher is (NONE)") && text.contains("no peer certificate"),
            "the node completed a TLS 1.2 handshake: {text}"
        );
    }

    // A client that pins another certificate never reaches the handler at all.
    let wrong = "00".repeat(32);
    let (base2, seed2) = (format!("https://127.0.0.1:{}", node.port), seed.clone());
    let t5 = now() + 5;
    let r = blocking(move || {
        let sig =
            vault_core::nodes::sign_hub_request(&seed2, "POST", "/node/v1/poll", t5, b"").unwrap();
        unv_cli::tls::hub_post(&wrong, &base2, "/node/v1/poll", t5, &sig, b"")
    })
    .await;
    assert!(r.is_err(), "a wrong pin must not connect");
    assert!(!out.exists());
    drop(node);
}

/// A stand-in for a listening node that answers a poll with whatever it is told
/// to, using the real node's certificate (so the pin holds and the only thing the
/// hub has left to check is the signature).
fn impostor(
    dir: &Path,
    port: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    use std::io::{Read, Write};
    use vault_core::tls::rustls;
    let cert = std::fs::read_to_string(dir.join(node_agent::TLS_CERT_FILE)).unwrap();
    let key = std::fs::read_to_string(dir.join(node_agent::TLS_KEY_FILE)).unwrap();
    let cfg = std::sync::Arc::new(vault_core::tls::server_config_tls13(&cert, &key).unwrap());
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    l.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = stop.clone();
    std::thread::spawn(move || {
        while !s2.load(std::sync::atomic::Ordering::Relaxed) {
            let Ok((mut tcp, _)) = l.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            };
            tcp.set_nonblocking(false).unwrap();
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .ok();
            let mut conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            let mut buf = [0u8; 8192];
            let _ = tls.read(&mut buf);
            let mut head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (k, v) in &headers {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(&body);
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    stop
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hub_ignores_a_beat_that_the_enrolled_node_did_not_sign() {
    // The pin holds (it is the node's own certificate), so only the signature on
    // the answer stands between an impostor and the hub's push.
    let beat = serde_json::to_vec(&vault_core::nodes::Beat {
        targets: vec![vault_core::nodes::TargetReport {
            id: "env-main".into(),
            project: "edge".into(),
            exporter: "env".into(),
            mode: "push".into(),
            apply: true,
            sha256: None,
            state: "missing".into(),
            error: None,
        }],
        ..Default::default()
    })
    .unwrap();

    for case in [
        "unsigned",
        "wrong key",
        "wrong id",
        "control: signed by the node",
    ] {
        let h = start().await;
        let out = scratch("impostor-out").join("app.env");
        // Enroll normally, but do not start the real listener: take its port.
        let dir = scratch("impostor");
        let port = free_port();
        let (_, tok) = h
            .owner(
                "POST",
                "/api/nodes/tokens",
                serde_json::json!({ "name": "pub-x", "projects": ["edge"] }),
            )
            .await;
        let (d, url, token) = (
            dir.clone(),
            h.url.clone(),
            tok["token"].as_str().unwrap().to_string(),
        );
        let (bind, adv) = (
            format!("127.0.0.1:{port}"),
            format!("https://127.0.0.1:{port}"),
        );
        blocking(move || node_agent::enroll(&d, &url, &token, None, false, Some((&bind, &adv))))
            .await
            .unwrap();
        let state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(node_agent::state_path(&dir)).unwrap())
                .unwrap();
        let node_id = state["node_id"].as_str().unwrap().to_string();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            + 60_000;
        let headers = match case {
            "unsigned" => vec![],
            "wrong key" => {
                let (other_seed, _) = vault_core::nodes::generate_identity();
                let sig = vault_core::nodes::sign_request(
                    &other_seed,
                    "POST",
                    "/api/nodes/beat",
                    ts,
                    &beat,
                )
                .unwrap();
                vec![
                    ("x-node-id".into(), node_id.clone()),
                    ("x-node-ts".into(), ts.to_string()),
                    ("x-node-sig".into(), sig),
                ]
            }
            _ => {
                let sig = vault_core::nodes::sign_request(
                    state["seed"].as_str().unwrap(),
                    "POST",
                    "/api/nodes/beat",
                    ts,
                    &beat,
                )
                .unwrap();
                vec![
                    ("x-node-id".into(), "someone-else".into()),
                    ("x-node-ts".into(), ts.to_string()),
                    ("x-node-sig".into(), sig),
                ]
            }
        };
        let stop = impostor(&dir, port, headers, beat.clone());
        h.state.start_node_poller();
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);

        let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
        assert!(
            list["nodes"][0]["last_polled"].is_null(),
            "{case}: the hub accepted the answer"
        );
        assert!(
            list["nodes"][0]["last_seen"].is_null(),
            "{case}: the hub recorded a beat"
        );
        assert!(!out.exists(), "{case}");
        assert!(h.audit().iter().all(|r| r.action != "node.apply"), "{case}");
    }
}

// ── Phase 37.1: approval signed on the owner's device ─────────────────────────

async fn node_id_of(h: &Hub) -> String {
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    list["nodes"][0]["id"].as_str().unwrap().to_string()
}

fn device_config(dir: &Path, out: &Path, approver: &str) -> PathBuf {
    config(
        dir,
        &format!(
            "approver = \"{approver}\"\n[[target]]\nid=\"env-main\"\npath='{}'\nproject=\"edge\"\nexporter=\"env\"\napply=true\nrequire_approval=true\n",
            out.display()
        ),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_node_is_approved_by_a_signature_made_off_the_hub_and_by_nothing_else() {
    let h = start().await;
    let dir = scratch("agent-device");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-d").await;
    let node_id = node_id_of(&h).await;
    let device_dir = scratch("device-key");
    let seed = vault_core::nodes::approver_seed(&device_dir).unwrap();
    let public = vault_core::nodes::hub_public(&seed).unwrap();

    // `device` is not available until a device is registered.
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/nodes/{node_id}/policy"),
            serde_json::json!({"approval":"device"}),
        )
        .await;
    assert_eq!(st, 400);
    let (st, reg) = h
        .owner(
            "POST",
            "/api/node-approvers",
            serde_json::json!({"pubkey": public, "label": "laptop"}),
        )
        .await;
    assert_eq!(st, 200, "{reg}");
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/nodes/{node_id}/policy"),
            serde_json::json!({"approval":"device"}),
        )
        .await;
    assert_eq!(st, 200);

    let cfg = device_config(&dir, &out, &public);
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    assert!(r.unwrap().actions.is_empty());
    assert!(!out.exists());

    // The hub's own click is not enough.
    let id = pending_approval(&h).await;
    let (st, body) = h
        .owner(
            "POST",
            &format!("/api/node-approvals/{id}/approve"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(st, 409, "{body}");
    // A signature from a key nobody registered is refused.
    let (_, list) = h.owner("GET", "/api/nodes", serde_json::json!({})).await;
    let rec = list["nodes"][0]["approvals"][0].clone();
    let sha = rec["sha256"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let stranger = vault_core::nodes::generate_hub_seed();
    let forged = vault_core::nodes::sign_device_approval(
        &stranger, &node_id, "env-main", &sha, &id, now, "t",
    )
    .unwrap();
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/node-approvals/{id}/approve"),
            serde_json::json!({"signed": forged}),
        )
        .await;
    assert_eq!(st, 409);
    assert!(!out.exists());

    // The registered device's signature for exactly this request is accepted.
    let signed =
        vault_core::nodes::sign_device_approval(&seed, &node_id, "env-main", &sha, &id, now, "t")
            .unwrap();
    let (st, done) = h
        .owner(
            "POST",
            &format!("/api/node-approvals/{id}/approve"),
            serde_json::json!({"signed": signed}),
        )
        .await;
    assert_eq!(st, 200, "{done}");
    assert!(done["decided_by"].as_str().unwrap().starts_with("device:"));
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    assert_eq!(r.unwrap().actions.len(), 1);
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .contains("TOKEN=first"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_names_an_approver_ignores_an_approval_the_hub_made_itself() {
    let h = start().await;
    let dir = scratch("agent-device-hub");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-e").await;
    // The node's config names a device the hub has never heard of, and the hub is
    // set to approve by itself: exactly a taken-over hub.
    let device_seed = vault_core::nodes::generate_hub_seed();
    let cfg = device_config(
        &dir,
        &out,
        &vault_core::nodes::hub_public(&device_seed).unwrap(),
    );
    set_policy(&h, "prod-e").await;
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    let id = pending_approval(&h).await;
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/node-approvals/{id}/approve"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(st, 200, "the hub is willing; the node is not");
    for _ in 0..2 {
        let (a, _) = blocking(move || {
            let r = agent.beat_once(0);
            (agent, r)
        })
        .await;
        agent = a;
    }
    assert!(
        !out.exists(),
        "the node wrote a file on the hub's say-so alone"
    );
    let rows = h.audit();
    let apply = rows
        .iter()
        .find(|r| r.action == "node.apply")
        .expect("the refusal is reported");
    let d = apply.details.as_deref().unwrap();
    assert!(d.contains("\"ok\":false") && d.contains("approval"), "{d}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn switching_a_node_to_device_approval_voids_a_yes_the_hub_gave_before() {
    let h = start().await;
    let dir = scratch("agent-device-switch");
    let out = dir.join("app.env");
    enroll(&h, &dir, "prod-f").await;
    let node_id = node_id_of(&h).await;
    set_policy(&h, "prod-f").await; // "required": the hub signs
    let device_dir = scratch("device-key2");
    let seed = vault_core::nodes::approver_seed(&device_dir).unwrap();
    let public = vault_core::nodes::hub_public(&seed).unwrap();
    let cfg = approval_config(&dir, &out);
    let (d2, c2) = (dir.clone(), cfg);
    let mut agent = blocking(move || Agent::new(&d2, &c2)).await.unwrap();
    let (a, _) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    agent = a;
    let id = pending_approval(&h).await;
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/node-approvals/{id}/approve"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(st, 200);
    // Before the node collects it, the owner decides only a device may approve.
    h.owner(
        "POST",
        "/api/node-approvers",
        serde_json::json!({"pubkey": public, "label": "laptop"}),
    )
    .await;
    let (st, _) = h
        .owner(
            "POST",
            &format!("/api/nodes/{node_id}/policy"),
            serde_json::json!({"approval":"device"}),
        )
        .await;
    assert_eq!(st, 200);
    let (_, r) = blocking(move || {
        let r = agent.beat_once(0);
        (agent, r)
    })
    .await;
    assert!(
        r.unwrap().actions.is_empty(),
        "a hub-made yes was honoured after the policy changed"
    );
    assert!(!out.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_stranger_cannot_lock_the_hub_out_of_a_listening_node() {
    let h = start().await;
    let out = scratch("listen-stall").join("app.env");
    let node = listening_node(&h, "pub-3", &out, false).await;
    let seed = vault_core::nodes::NodeStore::open(&h.db.parent().unwrap().join("nodes.json"))
        .unwrap()
        .hub_node_key()
        .unwrap()
        .0;
    // Twenty sockets that connect and say nothing: more than the listener serves at
    // once. Before connections were read on their own threads, the first one held
    // the whole listener for the I/O timeout.
    let held: Vec<std::net::TcpStream> = (0..20)
        .map(|_| std::net::TcpStream::connect(("127.0.0.1", node.port)).unwrap())
        .collect();
    let (fp, base) = (
        node.fingerprint.clone(),
        format!("https://127.0.0.1:{}", node.port),
    );
    let t0 = std::time::Instant::now();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let sig = vault_core::nodes::sign_hub_request(&seed, "POST", "/node/v1/poll", ts, b"").unwrap();
    let r = blocking(move || unv_cli::tls::hub_post(&fp, &base, "/node/v1/poll", ts, &sig, b""))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(5),
        "the legitimate poll waited behind the strangers: {:?}",
        t0.elapsed()
    );
    drop(held);
    drop(node);
}
