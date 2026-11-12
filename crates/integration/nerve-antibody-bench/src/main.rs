//! Native 引擎 HTTP 适配：供 blazehttp 等工具测拦截率。
//!
//! - 动作 `block` → **403**
//! - 其它（放行 / observe）→ **200**
//!
//! ```bash
//! cargo run -p nerve-antibody-bench
//! # 另开终端：
//! /path/to/blazehttp -t http://127.0.0.1:8808 -c 20
//! ```

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use http_body_util::BodyExt;
use nerve_antibody_engine::{Engine, NativeLevel, NativeRequest};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info};

struct AppState {
    engine: Engine,
    level: NativeLevel,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let pack = resolve_pack();
    let level = NativeLevel::from_str(&std::env::var("LEVEL").unwrap_or_else(|_| "medium".into()))
        .unwrap_or(NativeLevel::Medium);

    info!(pack = %pack.display(), level = %level.as_str(), "loading expert pack");
    let engine = Engine::load_pack(&pack).unwrap_or_else(|e| {
        eprintln!("load pack failed: {e}");
        std::process::exit(1);
    });
    let h = engine.health();
    info!(
        pack_id = %h.pack_id,
        rules = h.rule_count,
        threshold = h.block_threshold,
        "engine ready"
    );

    let state = Arc::new(AppState { engine, level });
    let app = Router::new().fallback(any(inspect_http)).with_state(state);

    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8808".into());
    let addr: SocketAddr = listen.parse().unwrap_or_else(|_| {
        eprintln!("invalid LISTEN={listen}");
        std::process::exit(1);
    });
    info!(%addr, "bench HTTP listening — point blazehttp -t http://127.0.0.1:8808");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

fn resolve_pack() -> PathBuf {
    if let Ok(p) = std::env::var("NERVE_NATIVE_PACK").or_else(|_| std::env::var("PACK")) {
        return PathBuf::from(p);
    }
    let from_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs/baseline");
    if from_crate.join("pack.toml").is_file() {
        return from_crate;
    }
    PathBuf::from("packs/baseline")
}

async fn inspect_http(State(st): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let method = req.method().as_str().to_string();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut headers = HashMap::new();
    for (k, v) in req.headers().iter() {
        if let Ok(val) = v.to_str() {
            headers.insert(k.as_str().to_string(), val.to_string());
        }
    }

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => bytes::Bytes::new(),
    };
    let body = String::from_utf8_lossy(&body_bytes).into_owned();

    let expert_req = NativeRequest {
        method,
        host,
        uri: uri_path,
        query,
        headers,
        body,
        ..Default::default()
    };

    match st.engine.inspect(&expert_req, st.level) {
        Ok(Some(hit)) if hit.action == "block" => {
            debug!(
                rule = %hit.rule_id,
                score = hit.total_score,
                "block"
            );
            (StatusCode::FORBIDDEN, "blocked").into_response()
        }
        Ok(Some(hit)) => {
            debug!(
                rule = %hit.rule_id,
                action = %hit.action,
                score = hit.total_score,
                "observe/pass-through"
            );
            (StatusCode::OK, "ok").into_response()
        }
        Ok(None) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "inspect error");
            (StatusCode::INTERNAL_SERVER_ERROR, "inspect error").into_response()
        }
    }
}
