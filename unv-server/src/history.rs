//! Phase 35 — the config time machine on the server (ADR-0141).
//!
//! One owner-only route, `POST /api/history {op, args}`, that hands the request
//! to the same dispatcher the local CLI and the desktop app call, so the three
//! cannot disagree. History is part of the vault rather than an opt-in feature
//! (its retention policy is how a deployment limits it), so there is no flag.
//!
//! Snapshots are taken after every successful vault save, off the request path:
//! rendering every project is milliseconds, but a save should not wait on it.

use super::*;

#[derive(Deserialize)]
pub(crate) struct HistoryRequest {
    op: String,
    #[serde(default)]
    args: serde_json::Value,
}

pub(crate) async fn history_route(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<HistoryRequest>,
) -> axum::response::Response {
    let (_, session) = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    // Rendered configs hold secrets in the clear (the `reveal` form) and the
    // history spans every project, so it is the owner's, as the vault key is.
    if let Err(e) = require_owner(&session) {
        return e.into_response();
    }
    let (db, key, actor) = (
        state.db_path.clone(),
        session.vault_key,
        session.user_id.clone(),
    );
    let out = tokio::task::spawn_blocking(move || {
        let conn = open_db(&db, &key)?;
        unv_cli::history::call(&conn, &req.op, &req.args, Some(&actor))
    })
    .await;
    match out {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => err_json(StatusCode::BAD_REQUEST, &e).into_response(),
        Err(_) => {
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "history worker failed").into_response()
        }
    }
}

/// Snapshots every changed config after a save. Fire and forget: a failure is
/// logged, never returned to the writer whose save already succeeded.
pub(crate) fn snapshot_after_save(state: &AppState, key: VaultKey, actor: String) {
    let db = state.db_path.clone();
    drop(tokio::task::spawn_blocking(move || {
        let Ok(conn) = open_db(&db, &key) else {
            return;
        };
        if let Ok(Some(vault)) = load_vault(&conn) {
            unv_cli::history::after_save(&conn, &vault, Some(&actor));
        }
    }));
}

/// For a node's reported file hash: the newest snapshot that rendered exactly
/// that, so "drift" can say "this host is still running what was rendered on
/// 3 October".
pub(crate) fn snapshot_for_hash(
    conn: &vault_core::SqlConnection,
    sha256: &str,
) -> Option<serde_json::Value> {
    vault_core::config_history::find_by_sha(conn, sha256, 1)
        .ok()?
        .into_iter()
        .next()
        .map(|m| serde_json::json!({ "seq": m.seq, "at": m.at, "cause": m.cause }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt;

    fn vault(secret: &str) -> serde_json::Value {
        serde_json::json!({
            "api_keys": [{ "id": "e1", "provider": "Stripe", "secretType": "api_key", "api_key": secret }],
            "user_categories": [],
            "projects": [{
                "id": "web", "name": "web", "project_type": "generic",
                "chunks": [{
                    "id": "c1", "name": "app.env", "chunk_type": "env_file",
                    "fields": [{ "key": "STRIPE_KEY", "value": "${Stripe/api_key}" }]
                }]
            }]
        })
    }

    struct Hub {
        app: axum::Router,
        owner: String,
        state: AppState,
    }

    fn hub() -> Hub {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("unv-hist-srv-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        let key = [5u8; 32];
        let state = AppState::new(
            d.join("vault.db"),
            d.join("vault.salt"),
            None,
            480,
            24,
            false,
        );
        let conn = open_db(&state.db_path, &key).unwrap();
        init_schema(&conn).unwrap();
        save_vault(&conn, vault("sk_live_ONE"), vault_core::SaveCtx::default()).unwrap();
        let owner = state.adopt_owner_key(key, "owner".into());
        let app =
            build_router(state.clone(), 8743).layer(axum::extract::connect_info::MockConnectInfo(
                "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
            ));
        let _ = MockConnectInfo::<SocketAddr>;
        Hub { app, owner, state }
    }

    impl Hub {
        async fn call(
            &self,
            method: &str,
            path: &str,
            token: Option<&str>,
            body: serde_json::Value,
        ) -> (StatusCode, serde_json::Value) {
            let mut b = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            if let Some(t) = token {
                b = b.header("authorization", format!("Bearer {t}"));
            }
            let r = self
                .app
                .clone()
                .oneshot(b.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let st = r.status();
            let bytes = axum::body::to_bytes(r.into_body(), 4 << 20).await.unwrap();
            (
                st,
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            )
        }
        async fn op(&self, op: &str, args: serde_json::Value) -> (StatusCode, serde_json::Value) {
            self.call(
                "POST",
                "/api/history",
                Some(&self.owner),
                serde_json::json!({ "op": op, "args": args }),
            )
            .await
        }
        async fn put(&self, v: serde_json::Value) {
            let (st, _) = self.call("PUT", "/api/vault", Some(&self.owner), v).await;
            assert!(st.is_success(), "{st}");
        }
        /// The background snapshot is off the request path; wait for it.
        async fn until_snapshots(&self, n: usize) {
            for _ in 0..100 {
                let (_, v) = self
                    .op("list", serde_json::json!({ "project": "web" }))
                    .await;
                if v["snapshots"].as_array().is_some_and(|a| a.len() >= n) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("never reached {n} snapshots");
        }
    }

    #[tokio::test]
    async fn only_the_owner_reaches_the_history() {
        let h = hub();
        let (st, _) = h
            .call(
                "POST",
                "/api/history",
                None,
                serde_json::json!({"op":"list"}),
            )
            .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_signed_in_sub_user_is_refused() {
        let h = hub();
        // A live, valid session that is not the owner's.
        h.state.sessions.lock().unwrap().insert(
            "sub-token".into(),
            Session {
                vault_key: [5u8; 32],
                user_id: "someone".into(),
                is_owner: false,
                expires_at: Instant::now() + Duration::from_secs(600),
                hard_expires_at: Instant::now() + Duration::from_secs(600),
            },
        );
        let (st, _) = h
            .call(
                "POST",
                "/api/history",
                Some("sub-token"),
                serde_json::json!({"op":"list"}),
            )
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_save_that_changes_a_config_is_snapshotted_in_the_background() {
        let h = hub();
        h.put(vault("sk_live_ONE")).await;
        h.until_snapshots(1).await;
        // Saving the same thing again records nothing; changing the secret does.
        h.put(vault("sk_live_ONE")).await;
        // Let the background task for the repeat finish (and wrongly snapshot, if
        // it were going to) before the next save; under a loaded machine two
        // saves landing together coalesce into one snapshot and hide the count.
        tokio::time::sleep(Duration::from_millis(300)).await;
        h.put(vault("sk_live_TWO")).await;
        h.until_snapshots(2).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let (_, l) = h.op("list", serde_json::json!({ "project": "web" })).await;
        assert_eq!(l["snapshots"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn over_http_the_default_is_fingerprints_and_the_real_text_needs_reveal() {
        let h = hub();
        h.put(vault("sk_live_ONE")).await;
        // Saves in quick succession coalesce (a snapshot renders the vault as it
        // is when it runs), so wait for the first before making the second.
        h.until_snapshots(1).await;
        h.put(vault("sk_live_TWO")).await;
        h.until_snapshots(2).await;
        let (_, d) = h.op("diff", serde_json::json!({ "project": "web" })).await;
        assert!(!d.to_string().contains("sk_live_"), "{d}");
        assert!(d["added"] == 1 && d["removed"] == 1, "{d}");
        let (_, r) = h
            .op(
                "diff",
                serde_json::json!({ "project": "web", "reveal": true }),
            )
            .await;
        assert!(r["diff"].as_str().unwrap().contains("sk_live_TWO"));
        let (st, e) = h.op("explode", serde_json::json!({})).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(e["error"].as_str().unwrap().contains("Unknown"));
        let (_, v) = h.op("verify", serde_json::json!({})).await;
        assert_eq!(v["problems"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn a_save_never_fails_because_history_cannot_record() {
        let h = hub();
        h.op("policy", serde_json::json!({ "enabled": false }))
            .await;
        h.put(vault("sk_live_NINE")).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (_, l) = h.op("list", serde_json::json!({})).await;
        assert!(
            l["snapshots"].as_array().unwrap().is_empty(),
            "history was off but recorded"
        );
        let _ = &h.state;
    }
}
