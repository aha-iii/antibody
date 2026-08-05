//! Dashboard 鉴权：复用 nerve-waf-auth（JWT / API Key）。
//! Native Dashboard 无 DB，账号密码走 `NERVE_AUTH_USER` / `NERVE_AUTH_PASSWORD`。

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use nerve_waf_auth::{AuthConfigResponse, AuthMethod, AuthState, LoginResponse};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// 避免对 `Arc<AuthState>` 直接 impl `FromRef`（orphan rule）。
#[derive(Clone)]
pub struct AuthStateRef(pub Arc<AuthState>);

pub fn auth_public(path: &str) -> bool {
    matches!(
        path,
        "/api/health" | "/api/auth/status" | "/api/auth/config" | "/api/auth/login"
    )
}

pub fn auth_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AuthStateRef: axum::extract::FromRef<S>,
{
    Router::new()
        .route("/api/auth/status", get(auth_status))
        .route("/api/auth/config", get(auth_config))
        .route("/api/auth/login", post(auth_login))
}

pub async fn auth_enforce_middleware(
    State(auth): State<AuthStateRef>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = &auth.0;
    if !auth.is_enabled() {
        return Ok(next.run(req).await);
    }
    if auth_public(req.uri().path()) {
        return Ok(next.run(req).await);
    }
    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok());
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let method = auth.authenticate(api_key, bearer).await;
    if method == AuthMethod::None {
        Err(StatusCode::UNAUTHORIZED)
    } else {
        Ok(next.run(req).await)
    }
}

async fn auth_status(State(auth): State<AuthStateRef>) -> Json<Value> {
    let auth = &auth.0;
    let cfg = auth.auth_config_response();
    Json(json!({
        "enabled": cfg.enabled,
        "method": auth.auth_method_label(),
        "mode": cfg.mode,
        "local": cfg.local,
        "keycloak": cfg.keycloak,
    }))
}

async fn auth_config(State(auth): State<AuthStateRef>) -> Json<AuthConfigResponse> {
    Json(auth.0.auth_config_response())
}

fn env_local_credentials() -> (String, String) {
    let user = std::env::var("NERVE_AUTH_USER").unwrap_or_else(|_| "admin".into());
    let pass = std::env::var("NERVE_AUTH_PASSWORD").unwrap_or_else(|_| "admin".into());
    (user.trim().to_string(), pass)
}

fn verify_env_login(username: &str, password: &str) -> bool {
    let (env_user, env_pass) = env_local_credentials();
    username == env_user && password == env_pass
}

#[derive(Deserialize)]
struct AuthLoginBody {
    username: String,
    password: String,
}

async fn auth_login(
    State(auth): State<AuthStateRef>,
    Json(body): Json<AuthLoginBody>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let auth = &auth.0;
    if !auth.local_config().enabled {
        return Err(StatusCode::NOT_FOUND);
    }
    let username = body.username.trim();
    if !verify_env_login(username, &body.password) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    auth.issue_local_token(username, "admin")
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
