//! Dashboard：Nerve RIS 阈值曲线校准 API。

use crate::bench::BenchRuntime;
use axum::extract::State;
use axum::Json;
use nerve_antibody_runtime::{
    extract_features, parse_request_summary, route_sample, scan_threshold_curve,
    train_logistic_with_stumps, NativeRequest, RisCalibrateReport, RouteTrainSample,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RisCalibrateBody {
    /// 使用最近一次 bench report 的 cases（默认 true）。
    #[serde(default = "default_true")]
    pub use_last_report: bool,
    #[serde(default = "default_max_miss")]
    pub max_miss: f64,
    #[serde(default = "default_true")]
    pub use_stumps: bool,
    /// 是否写回 packs/<pack>/config/route_weights.json 与 curve JSON。
    #[serde(default)]
    pub write_weights: bool,
    #[serde(default)]
    pub pack: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_max_miss() -> f64 {
    0.01
}

fn synthetic_samples() -> Vec<RouteTrainSample> {
    let mut out = Vec::new();
    let cleans = [
        ("GET", "/api/users", "page=1&size=20", ""),
        ("GET", "/health", "", ""),
        ("GET", "/api/search", "q=hello&page=1", ""),
        (
            "POST",
            "/open/api/msg/sms/v1/send",
            "",
            r#"{"phoneNumber":"13800138000"}"#,
        ),
    ];
    for (m, u, q, b) in cleans {
        let req = NativeRequest {
            method: m.into(),
            uri: u.into(),
            query: q.into(),
            body: b.into(),
            content_type: if b.starts_with('{') {
                Some("application/json".into())
            } else {
                None
            },
            ..Default::default()
        };
        let sample = route_sample(&req, 12 * 1024);
        out.push(RouteTrainSample {
            features: extract_features(&req, &sample),
            deep: false,
        });
    }
    let attacks = [
        ("GET", "/x", "id=1' union select null--", ""),
        ("GET", "/x", "id=1%27%20or%201%3D1", ""),
        ("GET", "/x", "q=<script>alert(1)</script>", ""),
    ];
    for (m, u, q, b) in attacks {
        let req = NativeRequest {
            method: m.into(),
            uri: u.into(),
            query: q.into(),
            body: b.into(),
            ..Default::default()
        };
        let sample = route_sample(&req, 12 * 1024);
        out.push(RouteTrainSample {
            features: extract_features(&req, &sample),
            deep: true,
        });
    }
    out
}

async fn samples_from_bench(rt: &BenchRuntime) -> Vec<RouteTrainSample> {
    let results = rt.results.read().await.clone();
    let mut out = Vec::new();
    for c in results {
        let deep = c.expect == "block" || c.kind == "black";
        if c.request_summary.is_empty() {
            continue;
        }
        let req = parse_request_summary(&c.request_summary);
        let sample = route_sample(&req, 12 * 1024);
        out.push(RouteTrainSample {
            features: extract_features(&req, &sample),
            deep,
        });
    }
    out
}

pub async fn api_ris_calibrate(
    State(st): State<Arc<crate::AppState>>,
    Json(body): Json<RisCalibrateBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let mut samples = if body.use_last_report {
        samples_from_bench(&st.bench).await
    } else {
        Vec::new()
    };
    if samples.len() < 8 {
        samples.extend(synthetic_samples());
    }
    let weights = if body.use_stumps {
        train_logistic_with_stumps(&samples, 60, 0.35, 8)
    } else {
        nerve_antibody_runtime::train_logistic(&samples, 60, 0.35)
    };
    let report: RisCalibrateReport = scan_threshold_curve(&samples, &weights, body.max_miss);

    let mut wrote = serde_json::Value::Null;
    if body.write_weights {
        let pack = body.pack.clone().unwrap_or_else(|| {
            st.current_pack
                .try_read()
                .map(|g| g.clone())
                .unwrap_or_else(|_| "baseline".into())
        });
        let root = st.packs_root.join(&pack).join("config");
        let _ = std::fs::create_dir_all(&root);
        let wpath = root.join("route_weights.json");
        let cpath = root.join("route_threshold_curve.json");
        let _ = std::fs::write(&wpath, format!("{}\n", weights.to_json_pretty()));
        if let Ok(body) = serde_json::to_string_pretty(&report) {
            let _ = std::fs::write(&cpath, format!("{body}\n"));
        }
        wrote = serde_json::json!({
            "weights": wpath.display().to_string(),
            "curve": cpath.display().to_string(),
        });
    }

    // 缓存最近曲线供 GET
    *st.last_ris_curve.write().await = Some(report.clone());

    Ok(Json(serde_json::json!({
        "ok": true,
        "report": report,
        "wrote": wrote,
        "sample_count": samples.len(),
    })))
}

pub async fn api_ris_curve_get(
    State(st): State<Arc<crate::AppState>>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    if let Some(r) = st.last_ris_curve.read().await.clone() {
        return Ok(Json(serde_json::json!({ "ok": true, "report": r })));
    }
    // 尝试读 pack 落盘
    let pack = st.current_pack.read().await.clone();
    let path = st
        .packs_root
        .join(&pack)
        .join("config/route_threshold_curve.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return Ok(Json(
                serde_json::json!({ "ok": true, "report": v, "path": path.display().to_string() }),
            ));
        }
    }
    Err((
        axum::http::StatusCode::NOT_FOUND,
        "no RIS curve yet — POST /api/ris/calibrate".into(),
    ))
}

#[allow(dead_code)]
pub fn curve_cache_path(packs_root: &PathBuf, pack: &str) -> PathBuf {
    packs_root
        .join(pack)
        .join("config/route_threshold_curve.json")
}
