//! Nerve-antibody 独立 Dashboard（本地演示 / 试打规则包）。
//!
//! ```bash
//! cargo run -p nerve-antibody-dashboard
//! # 仅本机 http://127.0.0.1:8790（不对客户发行）
//! ```

mod bench;
mod datasets;
mod ris_calibrate;
mod vp;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bench::{
    list_results, refresh_ready, report_json, spawn_bench_listener, start_job, stop_job,
    BenchRuntime, BenchStartBody, BenchStatus, ResultsQuery,
};
use nerve_antibody_engine::{Engine, NativeHealth, NativeLevel, NativeRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

pub(crate) struct AppState {
    pub(crate) engine: Arc<Engine>,
    pub(crate) packs_root: PathBuf,
    /// 当前包目录名（相对 packs_root），如 `demo`。
    pub(crate) current_pack: RwLock<String>,
    pub(crate) bench: Arc<BenchRuntime>,
    /// 最近一次 RIS 校准曲线。
    pub(crate) last_ris_curve: RwLock<Option<nerve_antibody_runtime::RisCalibrateReport>>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // 内部 dashboard 允许明文 pack；客户 WAF 生产路径应使用 .sealed + License。
    if std::env::var("NERVE_NATIVE_DEV_PACK").is_err() {
        std::env::set_var("NERVE_NATIVE_DEV_PACK", "1");
    }

    let packs_root = resolve_packs_root();
    let default_pack = std::env::var("DEFAULT_PACK").unwrap_or_else(|_| "baseline".into());
    let pack_path = resolve_pack_path(&packs_root, &default_pack);
    if !pack_path.exists() {
        eprintln!(
            "pack not found: {} (set PACK_ROOT / DEFAULT_PACK / NERVE_EXPERT_PACK)",
            pack_path.display()
        );
        std::process::exit(1);
    }

    info!(pack = %pack_path.display(), "loading expert pack");
    let engine = match Engine::load_pack(&pack_path) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("failed to load pack: {e}");
            std::process::exit(1);
        }
    };
    let health = engine.health();
    info!(
        pack_id = %health.pack_id,
        version = %health.pack_version,
        rules = health.rule_count,
        "engine ready"
    );

    let bench_listen: SocketAddr = std::env::var("BENCH_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8808".into())
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("invalid BENCH_LISTEN");
            std::process::exit(1);
        });
    let bench_target =
        std::env::var("BENCH_TARGET").unwrap_or_else(|_| format!("http://{}", bench_listen));
    let bench_level = Arc::new(RwLock::new(NativeLevel::Medium));
    let bench_status = Arc::new(RwLock::new(BenchStatus {
        target: bench_target.clone(),
        ..BenchStatus::default()
    }));
    refresh_ready(&bench_status, "samples").await;
    let bench = Arc::new(BenchRuntime {
        engine: engine.clone(),
        level: bench_level,
        status: bench_status,
        results: Arc::new(RwLock::new(Vec::new())),
        cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        listen: bench_listen,
        target_url: bench_target,
    });
    tokio::spawn(spawn_bench_listener(bench.clone()));

    let state = Arc::new(AppState {
        engine,
        packs_root,
        current_pack: RwLock::new(default_pack),
        bench,
        last_ris_curve: RwLock::new(None),
    });

    let ui_dist = resolve_ui_dist();
    let api = Router::new()
        .route("/api/health", get(api_health))
        .route("/api/packs", get(api_packs))
        .route("/api/samples", get(api_samples))
        .route("/api/reload", post(api_reload))
        .route("/api/inspect", post(api_inspect))
        .route("/api/bench/status", get(api_bench_status))
        .route("/api/bench/datasets", get(api_bench_datasets))
        .route("/api/bench/start", post(api_bench_start))
        .route("/api/bench/stop", post(api_bench_stop))
        .route("/api/bench/results", get(api_bench_results))
        .route("/api/bench/report", get(api_bench_report))
        .route("/api/ris/calibrate", post(ris_calibrate::api_ris_calibrate))
        .route("/api/ris/curve", get(ris_calibrate::api_ris_curve_get))
        .route("/metrics", get(api_metrics_prometheus))
        .route("/api/metrics", get(api_metrics_json))
        .route("/api/shadow/recent", get(api_shadow_recent))
        .route("/api/shadow/feedback", post(api_shadow_feedback))
        .route("/api/shadow/feedback", get(api_shadow_feedback_list))
        .route("/api/shadow/export-rules", get(api_shadow_export_rules))
        .route("/api/vp", get(vp::api_vp_list))
        .route("/api/vp/status", get(vp::api_vp_status))
        .route("/api/vp/sandbox", post(vp::api_vp_sandbox))
        .route("/api/vp/promote", post(vp::api_vp_promote))
        .route("/api/vp/rollback", post(vp::api_vp_rollback))
        .route("/api/vp/import", post(vp::api_vp_import))
        .route("/api/vp/probe", post(vp::api_vp_probe))
        .route("/api/vp/updates/check", get(vp::api_vp_updates_check))
        .route("/api/vp/updates/fetch", post(vp::api_vp_updates_fetch))
        .route("/api/vp/ingest", post(vp::api_vp_ingest))
        .with_state(state);

    let app = if ui_dist.join("index.html").is_file() {
        info!(dir = %ui_dist.display(), "serving React UI from dist");
        let index = ServeFile::new(ui_dist.join("index.html"));
        let static_files = ServeDir::new(&ui_dist).not_found_service(index);
        api.fallback_service(static_files)
            .layer(CorsLayer::permissive())
    } else {
        warn!(
            expected = %ui_dist.display(),
            "UI dist missing — run: cd apps/dashboard && npm install && npm run build"
        );
        api.route("/", get(ui_missing_page))
            .layer(CorsLayer::permissive())
    };

    let listen = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:8790".into());
    let addr: SocketAddr = listen.parse().unwrap_or_else(|_| {
        eprintln!("invalid LISTEN={listen}");
        std::process::exit(1);
    });
    info!(%addr, "dashboard listening (localhost only) — open http://{addr}/");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

fn resolve_pack_path(packs_root: &Path, default_pack: &str) -> PathBuf {
    if let Ok(p) = std::env::var("NERVE_EXPERT_PACK") {
        let p = PathBuf::from(p.trim());
        if !p.as_os_str().is_empty() {
            return p;
        }
    }
    let as_sealed = packs_root.join(format!("{default_pack}.sealed"));
    if as_sealed.is_file() {
        return as_sealed;
    }
    packs_root.join(default_pack)
}

fn resolve_packs_root() -> PathBuf {
    if let Ok(p) = std::env::var("PACK_ROOT") {
        return PathBuf::from(p);
    }
    // crates/nerve-antibody-dashboard → ../../packs
    let from_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs");
    if from_crate.join("demo/pack.toml").is_file() {
        return from_crate.canonicalize().unwrap_or(from_crate);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let from_cwd = cwd.join("packs");
    if from_cwd.join("demo/pack.toml").is_file() {
        return from_cwd;
    }
    from_crate
}

fn resolve_ui_dist() -> PathBuf {
    if let Ok(p) = std::env::var("UI_DIST") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/dashboard/dist")
}

async fn ui_missing_page() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html><html lang="zh-CN"><head><meta charsett="utf-8"/><title>Build UI</title>
<style>body{font-family:system-ui;background:#0c1220;color:#e8eef8;padding:48px;line-height:1.6}
code{background:#182234;padding:2px 6px;border-radius:4px}</style></head><body>
<h1>React UI 尚未构建</h1>
<p>在仓库内执行：</p>
<pre><code>cd apps/dashboard
npm install
npm run build</code></pre>
<p>然后重新 <code>cargo run -p nerve-antibody-dashboard</code>。</p>
<p>开发模式也可：API 用 cargo run，前端 <code>npm run dev</code>（:5178，已代理 /api）。</p>
</body></html>"#,
    )
}

#[derive(Serialize)]
struct HealthOut {
    #[serde(flatten)]
    health: NativeHealth,
    pack: String,
    packs_root: String,
}

async fn api_health(State(st): State<Arc<AppState>>) -> Json<HealthOut> {
    let pack = st.current_pack.read().await.clone();
    Json(HealthOut {
        health: st.engine.health(),
        pack,
        packs_root: st.packs_root.display().to_string(),
    })
}

#[derive(Serialize)]
struct PackInfo {
    id: String,
    path: String,
    current: bool,
}

async fn api_packs(State(st): State<Arc<AppState>>) -> Json<Vec<PackInfo>> {
    let current = st.current_pack.read().await.clone();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&st.packs_root) else {
        return Json(out);
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        if !path.join("pack.toml").is_file() {
            continue;
        }
        let id = ent.file_name().to_string_lossy().into_owned();
        out.push(PackInfo {
            current: id == current,
            path: path.display().to_string(),
            id,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Json(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleRequest {
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleCase {
    id: String,
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    expect_action: String,
    #[serde(default = "default_level")]
    min_level: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    tags: Vec<String>,
    request: SampleRequest,
}

#[derive(Deserialize)]
struct SamplesQuery {
    /// 覆盖当前包：如 `baseline`
    pack: Option<String>,
    /// 分类过滤：如 `01-sqli`
    category: Option<String>,
    /// 规则 id 子串过滤
    q: Option<String>,
}

#[derive(Serialize)]
struct SamplesOut {
    pack: String,
    count: usize,
    categories: Vec<String>,
    samples: Vec<SampleCase>,
}

/// Recursively collect `samples/**/*.yaml` (mirrors `rules/<cat>/<id>.yaml`).
fn collect_sample_yaml_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut out = Vec::new();
    fn walk(d: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
        for e in std::fs::read_dir(d).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            let p = e.path();
            if p.is_dir() {
                walk(&p, out)?;
                continue;
            }
            let ok = p
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| x == "yaml" || x == "yml")
                .unwrap_or(false);
            if ok {
                out.push(p);
            }
        }
        Ok(())
    }
    walk(dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn load_pack_samples(packs_root: &Path, pack: &str) -> Result<Vec<SampleCase>, String> {
    let dir = packs_root.join(pack).join("samples");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let files = collect_sample_yaml_files(&dir)?;
    let mut out = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let list: Vec<SampleCase> =
            serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        out.extend(list);
    }
    Ok(out)
}

async fn api_samples(
    State(st): State<Arc<AppState>>,
    Query(q): Query<SamplesQuery>,
) -> Result<Json<SamplesOut>, ApiError> {
    let current = st.current_pack.read().await.clone();
    let pack = q
        .pack
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(current.as_str())
        .to_string();
    if pack.contains(['/', '\\']) {
        return Err(ApiError::bad("invalid pack name"));
    }
    let mut samples = load_pack_samples(&st.packs_root, &pack).map_err(ApiError::bad)?;
    if let Some(cat) = q
        .category
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        samples.retain(|s| s.category == cat);
    }
    if let Some(needle) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let n = needle.to_ascii_lowercase();
        samples.retain(|s| {
            s.id.to_ascii_lowercase().contains(&n)
                || s.rule_id.to_ascii_lowercase().contains(&n)
                || s.name.to_ascii_lowercase().contains(&n)
        });
    }
    let mut categories: Vec<String> = samples
        .iter()
        .map(|s| s.category.clone())
        .filter(|c| !c.is_empty())
        .collect();
    categories.sort();
    categories.dedup();
    // categories from full pack when filtered — recompute from unfiltered for nav
    let all = load_pack_samples(&st.packs_root, &pack).unwrap_or_default();
    let mut all_cats: Vec<String> = all.iter().map(|s| s.category.clone()).collect();
    all_cats.sort();
    all_cats.dedup();
    let count = samples.len();
    Ok(Json(SamplesOut {
        pack,
        count,
        categories: all_cats,
        samples,
    }))
}

#[derive(Deserialize)]
struct ReloadBody {
    pack: String,
}

async fn api_reload(
    State(st): State<Arc<AppState>>,
    Json(body): Json<ReloadBody>,
) -> Result<Json<HealthOut>, ApiError> {
    let name = body.pack.trim();
    if name.is_empty() || name.contains(['/', '\\', '.']) {
        return Err(ApiError::bad("invalid pack name"));
    }
    let path = st.packs_root.join(name);
    if !path.join("pack.toml").is_file() {
        return Err(ApiError::bad(format!("pack not found: {name}")));
    }
    info!(pack = %path.display(), "reloading pack");
    st.engine
        .reload(Some(Path::new(&path)))
        .map_err(|e| ApiError::bad(e.to_string()))?;
    *st.current_pack.write().await = name.to_string();
    Ok(Json(HealthOut {
        health: st.engine.health(),
        pack: name.to_string(),
        packs_root: st.packs_root.display().to_string(),
    }))
}

#[derive(Deserialize)]
struct InspectBody {
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
    #[serde(default = "default_level")]
    level: String,
}

fn default_method() -> String {
    "GET".into()
}
fn default_level() -> String {
    "medium".into()
}

#[derive(Serialize)]
struct InspectOut {
    hit: Option<nerve_antibody_engine::NativeHit>,
    elapsed_ms: u128,
    level: String,
    pack: String,
}

async fn api_inspect(
    State(st): State<Arc<AppState>>,
    Json(body): Json<InspectBody>,
) -> Result<Json<InspectOut>, ApiError> {
    let level = NativeLevel::from_str(&body.level)
        .map_err(|e| ApiError::bad(format!("invalid level: {e}")))?;
    let req = NativeRequest {
        method: body.method,
        host: body.host,
        uri: body.uri,
        query: body.query,
        headers: body.headers,
        body: body.body,
        ..Default::default()
    };
    let t0 = Instant::now();
    let hit = st
        .engine
        .inspect(&req, level)
        .map_err(|e| ApiError::bad(e.to_string()))?;
    let elapsed_ms = t0.elapsed().as_millis();
    let pack = st.current_pack.read().await.clone();
    Ok(Json(InspectOut {
        hit,
        elapsed_ms,
        level: level.as_str().into(),
        pack,
    }))
}

async fn api_bench_status(State(st): State<Arc<AppState>>) -> Json<BenchStatus> {
    let dataset = st.bench.status.read().await.dataset.clone();
    refresh_ready(
        &st.bench.status,
        if dataset.is_empty() {
            "samples"
        } else {
            &dataset
        },
    )
    .await;
    let mut status = st.bench.status.read().await.clone();
    let pack = st.current_pack.read().await.clone();
    if status.phase != bench::BenchPhase::Running {
        status.pack = pack;
    }
    Json(status)
}

async fn api_bench_datasets() -> Json<serde_json::Value> {
    Json(bench::list_datasets())
}

async fn api_bench_start(
    State(st): State<Arc<AppState>>,
    Json(body): Json<BenchStartBody>,
) -> Result<Json<BenchStatus>, ApiError> {
    let pack = st.current_pack.read().await.clone();
    start_job(st.bench.clone(), st.packs_root.clone(), pack, body)
        .await
        .map_err(ApiError::bad)?;
    let status = st.bench.status.read().await.clone();
    Ok(Json(status))
}

async fn api_bench_stop(State(st): State<Arc<AppState>>) -> Result<Json<BenchStatus>, ApiError> {
    stop_job(st.bench.clone()).await.map_err(ApiError::bad)?;
    let status = st.bench.status.read().await.clone();
    Ok(Json(status))
}

async fn api_bench_results(
    State(st): State<Arc<AppState>>,
    Query(q): Query<ResultsQuery>,
) -> Json<bench::ResultsOut> {
    Json(list_results(&st.bench, q).await)
}

async fn api_bench_report(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut report = report_json(&st.bench).await;
    if let Some(obj) = report.as_object_mut() {
        let s = st.engine.metrics_snapshot();
        obj.insert(
            "engine_metrics".to_string(),
            serde_json::json!({
                "inspect_total": s.inspect_total,
                "inspect_fast": s.inspect_fast,
                "inspect_deep": s.inspect_deep,
                "fast_ratio": if s.inspect_total > 0 { s.inspect_fast as f64 / s.inspect_total as f64 } else { 0.0 },
                "budget_exhausted": s.budget_exhausted,
                "latency_us_avg": if s.inspect_total > 0 { s.latency_us_sum / s.inspect_total } else { 0 },
                "latency_us_max": s.latency_us_max,
                "stage_decode_us_avg": s.stage_decode_us_avg,
                "stage_aho_us_avg": s.stage_aho_us_avg,
                "stage_regex_us_avg": s.stage_regex_us_avg,
                "stage_semantic_us_avg": s.stage_semantic_us_avg,
                "stage_fusion_us_avg": s.stage_fusion_us_avg,
                "route_gate_deep_ratio": if s.route_gate_total > 0 { s.route_gate_deep as f64 / s.route_gate_total as f64 } else { 0.0 },
                "shadow_would_hit": s.shadow_would_hit,
                "shadow_done": s.shadow_done,
                "fast_pool_escalate": s.fast_pool_escalate,
            }),
        );
    }
    Json(report)
}

async fn api_metrics_prometheus(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        st.engine.metrics_prometheus(),
    )
}

async fn api_metrics_json(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let s = st.engine.metrics_snapshot();
    Json(serde_json::json!({
        "inspect_total": s.inspect_total,
        "inspect_fast": s.inspect_fast,
        "inspect_deep": s.inspect_deep,
        "inspect_hit": s.inspect_hit,
        "inspect_block": s.inspect_block,
        "inspect_challenge": s.inspect_challenge,
        "inspect_observe": s.inspect_observe,
        "budget_exhausted": s.budget_exhausted,
        "latency_us_avg": if s.inspect_total > 0 { s.latency_us_sum / s.inspect_total } else { 0 },
        "latency_us_max": s.latency_us_max,
        "latency_fast_us_avg": if s.inspect_fast > 0 { s.latency_fast_us_sum / s.inspect_fast } else { 0 },
        "latency_deep_us_avg": if s.inspect_deep > 0 { s.latency_deep_us_sum / s.inspect_deep } else { 0 },
        "stage_decode_us_avg": s.stage_decode_us_avg,
        "stage_aho_us_avg": s.stage_aho_us_avg,
        "stage_regex_us_avg": s.stage_regex_us_avg,
        "stage_semantic_us_avg": s.stage_semantic_us_avg,
        "stage_fusion_us_avg": s.stage_fusion_us_avg,
        "route_gate_deep_ratio": if s.route_gate_total > 0 { s.route_gate_deep as f64 / s.route_gate_total as f64 } else { 0.0 },
        "latency_buckets": s.latency_buckets,
        "top_rules": s.top_rules.iter().map(|(id, n)| serde_json::json!({"rule_id": id, "hits": n})).collect::<Vec<_>>(),
        "shadow_done": s.shadow_done,
        "shadow_would_hit": s.shadow_would_hit,
        "shadow_dropped": s.shadow_dropped,
        "fast_pool_escalate": s.fast_pool_escalate,
    }))
}

#[derive(Deserialize)]
struct ShadowFeedbackBody {
    uri: String,
    label: String,
    #[serde(default)]
    note: String,
    /// 可选：误报关联规则 id（缺省时从 shadow recent 按 uri 解析）。
    #[serde(default)]
    rule_id: Option<String>,
}

async fn api_shadow_feedback(
    State(st): State<Arc<AppState>>,
    Json(body): Json<ShadowFeedbackBody>,
) -> Json<serde_json::Value> {
    st.engine
        .shadow_add_feedback_with_rule(body.uri, body.label, body.note, body.rule_id);
    Json(serde_json::json!({ "ok": true }))
}

async fn api_shadow_feedback_list(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows: Vec<_> = st
        .engine
        .shadow_feedback_recent(64)
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "uri": r.uri,
                "label": r.label,
                "note": r.note,
                "created_ms": r.created_ms,
                "matched_rule_id": r.matched_rule_id,
            })
        })
        .collect();
    Json(serde_json::json!({ "count": rows.len(), "items": rows }))
}

async fn api_shadow_export_rules(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/yaml; charsett=utf-8",
        )],
        st.engine.shadow_export_rules(),
    )
}

async fn api_shadow_recent(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rows: Vec<_> = st
        .engine
        .shadow_recent(32)
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "uri": r.uri,
                "would_hit": r.would_hit,
                "action": r.action,
                "total_score": r.total_score,
                "rule_id": r.rule_id,
                "source": r.source,
            })
        })
        .collect();
    Json(serde_json::json!({ "count": rows.len(), "samples": rows }))
}

pub(crate) struct ApiError {
    status: StatusCode,
    msg: String,
}

impl ApiError {
    pub(crate) fn bad(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            msg: msg.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        warn!(error = %self.msg, status = %self.status, "api error");
        (self.status, Json(serde_json::json!({ "error": self.msg }))).into_response()
    }
}
