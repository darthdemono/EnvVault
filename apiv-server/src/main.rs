//! `apiv-server` — HTTP remote vault server for API Vault.
//!
//! Binds to `127.0.0.1:8743` by default.  Swagger UI at `/docs`.
//!
//! # Auth
//! `POST /api/unlock` returns a Bearer token.  All other vault routes require
//! `Authorization: Bearer <token>` header.  Sessions are in-memory only.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use utoipa::{OpenApi, ToSchema};
use vault_core::{
    derive_key, get_expiring_entries, init_schema, load_audit, load_vault, open_db,
    read_or_create_salt, save_vault, VaultKey, Zeroize,
};

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    sessions:  Arc<Mutex<HashMap<String, VaultKey>>>,
    db_path:   PathBuf,
    salt_path: PathBuf,
}

// ── Request / response DTOs ───────────────────────────────────────────────────

/// Unlock request body.
#[derive(Deserialize, ToSchema)]
struct UnlockRequest {
    password: String,
}

/// Successful unlock response — contains the session Bearer token.
#[derive(Serialize, ToSchema)]
struct UnlockResponse {
    token: String,
}

/// Vault server status.
#[derive(Serialize, ToSchema)]
struct StatusResponse {
    unlocked:     bool,
    vault_exists: bool,
}

/// Generic error envelope.
#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct ExpiringQuery {
    #[serde(default = "default_days")]
    days: u32,
}
fn default_days() -> u32 { 30 }

// ── Auth helper ───────────────────────────────────────────────────────────────

fn extract_key(headers: &HeaderMap, state: &AppState) -> Result<VaultKey, (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err401("Missing Bearer token"))?;
    state.sessions.lock().unwrap().get(token).copied()
        .ok_or_else(|| err401("Invalid or expired token"))
}

fn err401(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: msg.into() }))
}
fn err500(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": msg })))
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// Authenticate with the master password and receive a session token.
#[utoipa::path(
    post, path = "/api/unlock",
    request_body = UnlockRequest,
    responses(
        (status = 200, description = "Authenticated",    body = UnlockResponse),
        (status = 401, description = "Wrong password",   body = ErrorResponse),
        (status = 500, description = "Internal error",   body = ErrorResponse),
    ),
    tag = "auth"
)]
async fn unlock(State(state): State<AppState>, Json(req): Json<UnlockRequest>) -> impl IntoResponse {
    let salt = match read_or_create_salt(&state.salt_path) {
        Ok(s)  => s,
        Err(e) => return err500(e).into_response(),
    };
    let key = match derive_key(&req.password, &salt) {
        Ok(k)  => k,
        Err(e) => return err500(e).into_response(),
    };
    match open_db(&state.db_path, &key) {
        Ok(conn) => { let _ = init_schema(&conn); }
        Err(e)   => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": e }))).into_response(),
    }
    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.lock().unwrap().insert(token.clone(), key);
    (StatusCode::OK, Json(serde_json::json!({ "token": token }))).into_response()
}

/// Invalidate the current session (lock the vault).
#[utoipa::path(
    delete, path = "/api/unlock",
    responses((status = 204, description = "Locked")),
    tag = "auth",
    security(("bearer_auth" = []))
)]
async fn lock(headers: HeaderMap, State(state): State<AppState>) -> StatusCode {
    if let Some(token) = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        let mut sessions = state.sessions.lock().unwrap();
        if let Some(mut k) = sessions.remove(token) { k.zeroize(); }
    }
    StatusCode::NO_CONTENT
}

/// Return whether the vault is currently unlocked and whether the DB file exists.
#[utoipa::path(
    get, path = "/api/status",
    responses((status = 200, description = "OK", body = StatusResponse)),
    tag = "auth"
)]
async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        unlocked:     !state.sessions.lock().unwrap().is_empty(),
        vault_exists: state.db_path.exists(),
    })
}

/// Load the entire vault data.
#[utoipa::path(
    get, path = "/api/vault",
    responses(
        (status = 200, description = "Vault data"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "vault",
    security(("bearer_auth" = []))
)]
async fn get_vault(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let key = match extract_key(&headers, &state) {
        Ok(k)  => k,
        Err(e) => return e.into_response(),
    };
    match open_db(&state.db_path, &key) {
        Ok(conn) => match load_vault(&conn) {
            Ok(Some(d)) => Json(d).into_response(),
            Ok(None)    => Json(serde_json::json!({
                "api_keys": [], "user_categories": [], "projects": []
            })).into_response(),
            Err(e) => err500(e).into_response(),
        },
        Err(e) => err500(e).into_response(),
    }
}

/// Save the entire vault data.
#[utoipa::path(
    put, path = "/api/vault",
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "vault",
    security(("bearer_auth" = []))
)]
async fn put_vault(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(data): Json<serde_json::Value>,
) -> impl IntoResponse {
    let key = match extract_key(&headers, &state) {
        Ok(k)  => k,
        Err(e) => return e.into_response(),
    };
    match open_db(&state.db_path, &key) {
        Ok(conn) => match save_vault(&conn, data) {
            Ok(())  => StatusCode::NO_CONTENT.into_response(),
            Err(e)  => err500(e).into_response(),
        },
        Err(e) => err500(e).into_response(),
    }
}

/// List entries expiring within the given number of days (default: 30).
#[utoipa::path(
    get, path = "/api/vault/expiring",
    params(("days" = Option<u32>, Query, description = "Lookahead window in days")),
    responses(
        (status = 200, description = "Expiring entries"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "vault",
    security(("bearer_auth" = []))
)]
async fn expiring(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(q): Query<ExpiringQuery>,
) -> impl IntoResponse {
    let key = match extract_key(&headers, &state) {
        Ok(k)  => k,
        Err(e) => return e.into_response(),
    };
    match open_db(&state.db_path, &key) {
        Ok(conn) => match get_expiring_entries(&conn, q.days) {
            Ok(entries) => Json(entries).into_response(),
            Err(e)      => err500(e).into_response(),
        },
        Err(e) => err500(e).into_response(),
    }
}

/// Return the append-only audit log (newest first).
#[utoipa::path(
    get, path = "/api/audit",
    responses(
        (status = 200, description = "Audit rows"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    tag = "audit",
    security(("bearer_auth" = []))
)]
async fn audit(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let key = match extract_key(&headers, &state) {
        Ok(k)  => k,
        Err(e) => return e.into_response(),
    };
    match open_db(&state.db_path, &key) {
        Ok(conn) => match load_audit(&conn) {
            Ok(rows) => Json(rows).into_response(),
            Err(e)   => err500(e).into_response(),
        },
        Err(e) => err500(e).into_response(),
    }
}

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(unlock, lock, status, get_vault, put_vault, expiring, audit),
    components(schemas(UnlockRequest, UnlockResponse, StatusResponse, ErrorResponse)),
    info(
        title   = "API Vault Server",
        version = "0.4.0",
        description = "Remote vault access API — authenticate once, then use the Bearer token."
    ),
    tags(
        (name = "auth",  description = "Session management"),
        (name = "vault", description = "Vault read/write"),
        (name = "audit", description = "Append-only audit log"),
    ),
    security(("bearer_auth" = [])),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new().scheme(HttpAuthScheme::Bearer).bearer_format("UUID").build(),
                ),
            );
        }
    }
}

// ── CLI args ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "apiv-server", version = "0.4.0", about = "API Vault remote vault server")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value_t = 8743)]
    port: u16,
    /// Host address to bind.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Path to vault.db (default: ~/.local/share/apiv-server/vault.db).
    #[arg(long)]
    db_path: Option<PathBuf>,
    /// Path to vault.salt (default: ~/.local/share/apiv-server/vault.salt).
    #[arg(long)]
    salt_path: Option<PathBuf>,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib"))
        .join("apiv-server");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let db_path   = args.db_path.unwrap_or_else(|| data_dir.join("vault.db"));
    let salt_path = args.salt_path.unwrap_or_else(|| data_dir.join("vault.salt"));

    let state = AppState {
        sessions:  Arc::new(Mutex::new(HashMap::new())),
        db_path,
        salt_path,
    };

    let cors = tower_http::cors::CorsLayer::permissive();

    // SwaggerUi converts to Router<()> only; vault routes need AppState.
    // Apply with_state to vault routes first (yields Router<()>), then merge both into a
    // stateless outer Router<()> with the CORS layer applied at the top.
    use axum::routing::post;
    let vault_routes = Router::new()
        .route("/api/unlock",         post(unlock).delete(lock))
        .route("/api/status",         get(status))
        .route("/api/vault",          get(get_vault).put(put_vault))
        .route("/api/vault/expiring", get(expiring))
        .route("/api/audit",          get(audit))
        .with_state(state);

    let app: Router = Router::new()
        .merge(vault_routes)
        .route("/api/openapi.json", get(|| async { Json(ApiDoc::openapi()) }))
        .layer(cors);

    let addr = format!("{}:{}", args.host, args.port);
    println!("apiv-server  →  http://{addr}");
    println!("OpenAPI JSON →  http://{addr}/api/openapi.json");

    let listener = tokio::net::TcpListener::bind(&addr).await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    axum::serve(listener, app).await.expect("server error");
}
