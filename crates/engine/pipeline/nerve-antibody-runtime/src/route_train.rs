//! Route gate 离线训练（bench JSON → 逻辑回归 / 轻量 stump 增强）。

use crate::route_gate::{
    feature_names, feature_vector, RouteFeatures, RouteGateWeights, RouteStump, ROUTE_FEATURE_DIM,
};
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
    RouteGateWeights {
        bias,
        w,
        stumps: Vec::new(),
    }
}

/// 轻量 stump 增强：在逻辑回归之上拟合若干单特征桩（类 GBDT 一阶）。
pub fn train_logistic_with_stumps(
    samples: &[RouteTrainSample],
    epochs: usize,
    lr: f32,
    stump_rounds: usize,
) -> RouteGateWeights {
    let mut base = train_logistic(samples, epochs, lr);
    if samples.is_empty() || stump_rounds == 0 {
        return base;
    }
    let mut stumps = Vec::new();
    let n = samples.len() as f32;
    for _ in 0..stump_rounds.min(16) {
        let mut best: Option<(f32, RouteStump)> = None;
        for feat in 0..ROUTE_FEATURE_DIM {
            for &thr in &[0.15f32, 0.35, 0.5, 0.65, 0.85] {
                let mut left_sum = 0.0f32;
                let mut left_n = 0.0f32;
                let mut right_sum = 0.0f32;
                let mut right_n = 0.0f32;
                for s in samples {
                    let x = feature_vector(&s.features);
                    let pred = score_linear_only(&s.features, &base) + stump_contrib(&stumps, &x);
                    let y = if s.deep { 1.0 } else { 0.0 };
                    let resid = y - pred;
                    if x[feat] < thr {
                        left_sum += resid;
                        left_n += 1.0;
                    } else {
                        right_sum += resid;
                        right_n += 1.0;
                    }
                }
                if left_n < 1.0 || right_n < 1.0 {
                    continue;
                }
                let left = (left_sum / left_n).clamp(-1.0, 1.0);
                let right = (right_sum / right_n).clamp(-1.0, 1.0);
                let gain = (left_sum.abs() + right_sum.abs()) / n;
                let stump = RouteStump {
                    feature: feat as u16,
                    threshold: thr,
                    left,
                    right,
                    alpha: 0.35,
                };
                if best.as_ref().map(|(g, _)| gain > *g).unwrap_or(true) {
                    best = Some((gain, stump));
                }
            }
        }
        if let Some((gain, stump)) = best {
            if gain < 1e-4 {
                break;
            }
            stumps.push(stump);
        } else {
            break;
        }
    }
    base.stumps = stumps;
    base
}

fn score_linear_only(f: &RouteFeatures, w: &RouteGateWeights) -> f32 {
    let fv = feature_vector(f);
    let mut s = w.bias;
    for (i, v) in fv.iter().enumerate() {
        s += w.w[i] * v;
    }
    s
}

fn stump_contrib(stumps: &[RouteStump], fv: &[f32; ROUTE_FEATURE_DIM]) -> f32 {
    let mut s = 0.0f32;
    for stump in stumps {
        let idx = stump.feature as usize;
        if idx >= ROUTE_FEATURE_DIM {
            continue;
        }
        let leaf = if fv[idx] < stump.threshold {
            stump.left
        } else {
            stump.right
        };
        s += stump.alpha * leaf;
    }
    s
}

impl RouteGateWeights {
    /// 导出为 pack 可读 JSON。
    pub fn to_json_pretty(&self) -> String {
        let names = feature_names();
        let mut obj = serde_json::Map::new();
        obj.insert("bias".into(), serde_json::json!(self.bias));
        obj.insert(
            "model".into(),
            serde_json::json!(if self.stumps.is_empty() {
                "logistic"
            } else {
                "logistic+stumps"
            }),
        );
        let mut weights = serde_json::Map::new();
        for (i, name) in names.iter().enumerate() {
            weights.insert((*name).into(), serde_json::json!(self.w[i]));
        }
        obj.insert("weights".into(), serde_json::Value::Object(weights));
        if !self.stumps.is_empty() {
            let arr: Vec<_> = self
                .stumps
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "feature": s.feature,
                        "threshold": s.threshold,
                        "left": s.left,
                        "right": s.right,
                        "alpha": s.alpha,
                    })
                })
                .collect();
            obj.insert("stumps".into(), serde_json::Value::Array(arr));
        }
        serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap_or_default()
    }
}
