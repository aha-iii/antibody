//! Route gate 离线训练（bench JSON → 逻辑回归权重）。

use crate::route_gate::{extract_features, feature_vector, RouteFeatures, RouteGateWeights, ROUTE_FEATURE_DIM};
use crate::types::NativeRequest;

/// 单条训练样本。
#[derive(Debug, Clone)]
pub struct RouteTrainSample {
    pub features: RouteFeatures,
    pub deep: bool,
}

/// 解析 bench `request_summary`（`METHOD path?query`）。
pub fn parse_request_summary(summary: &str) -> NativeRequest {
    let summary = summary.trim();
    let mut parts = summary.splitn(2, char::is_whitespace);
    let method = parts.next().unwrap_or("GET").to_string();
    let rest = parts.next().unwrap_or("/").trim();
    let (uri, query) = match rest.split_once('?') {
        Some((u, q)) => (u.to_string(), q.to_string()),
        None => (rest.to_string(), String::new()),
    };
    NativeRequest {
        method,
        uri,
        query,
        ..Default::default()
    }
}

/// 简易逻辑回归（批量梯度下降），输出线性权重。
pub fn train_logistic(samples: &[RouteTrainSample], epochs: usize, lr: f32) -> RouteGateWeights {
    let mut bias = 0.0f32;
    let mut w = [0.0f32; ROUTE_FEATURE_DIM];
    let n = samples.len().max(1) as f32;
    for _ in 0..epochs.max(1) {
        let mut db = 0.0f32;
        let mut dw = [0.0f32; ROUTE_FEATURE_DIM];
        for s in samples {
            let x = feature_vector(&s.features);
            let mut z = bias;
            for (i, xi) in x.iter().enumerate() {
                z += w[i] * xi;
            }
            let p = 1.0 / (1.0 + (-z).exp());
            let y = if s.deep { 1.0 } else { 0.0 };
            let err = p - y;
            db += err;
            for (i, xi) in x.iter().enumerate() {
                dw[i] += err * xi;
            }
        }
        bias -= lr * db / n;
        for (i, di) in dw.iter().enumerate() {
            w[i] -= lr * di / n;
        }
    }
    RouteGateWeights { bias, w }
}

impl RouteGateWeights {
    /// 导出为 pack 可读 JSON。
    pub fn to_json_pretty(&self) -> String {
        let names = crate::route_gate::feature_names();
        let mut obj = serde_json::Map::new();
        obj.insert("bias".into(), serde_json::json!(self.bias));
        let mut weights = serde_json::Map::new();
        for (i, name) in names.iter().enumerate() {
            weights.insert((*name).into(), serde_json::json!(self.w[i]));
        }
        obj.insert("weights".into(), serde_json::Value::Object(weights));
        serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap_or_default()
    }
}
