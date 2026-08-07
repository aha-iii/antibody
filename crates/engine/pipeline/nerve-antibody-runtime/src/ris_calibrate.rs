//! Nerve RIS 阈值扫描（攻击 Fast 漏检约束下最大化干净 fast_ratio）。

use crate::route_gate::{score_features, RouteGateWeights};
use crate::route_train::RouteTrainSample;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ThresholdCurvePoint {
    pub threshold: f32,
    pub attack_fast_miss: f64,
    pub clean_fast_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RisCalibrateReport {
    pub recommended_deep_threshold: f32,
    pub recommended_gray_threshold: f32,
    pub attack_fast_miss: f64,
    pub clean_fast_ratio: f64,
    pub attack_count: usize,
    pub clean_count: usize,
    pub max_miss: f64,
    pub curve: Vec<ThresholdCurvePoint>,
    pub model: String,
}

fn eval_threshold(
    samples: &[RouteTrainSample],
    weights: &RouteGateWeights,
    thr: f32,
) -> (f64, f64, usize, usize) {
    let mut atk = 0usize;
    let mut atk_fast = 0usize;
    let mut clean = 0usize;
    let mut clean_fast = 0usize;
    for s in samples {
        let score = score_features(&s.features, weights);
        if s.deep {
            atk += 1;
            if score < thr {
                atk_fast += 1;
            }
        } else {
            clean += 1;
            if score < thr {
                clean_fast += 1;
            }
        }
    }
    let miss = if atk == 0 {
        0.0
    } else {
        atk_fast as f64 / atk as f64
    };
    let fast_ratio = if clean == 0 {
        0.0
    } else {
        clean_fast as f64 / clean as f64
    };
    (miss, fast_ratio, atk, clean)
}

/// 扫描阈值曲线并推荐 deep/gray。
pub fn scan_threshold_curve(
    samples: &[RouteTrainSample],
    weights: &RouteGateWeights,
    max_miss: f64,
) -> RisCalibrateReport {
    let mut best_thr = 0.28f32;
    let mut best_fast = -1.0f64;
    let mut curve = Vec::new();
    let mut t = 0.12f32;
    while t <= 0.55 {
        let (miss, fast_r, _, _) = eval_threshold(samples, weights, t);
        curve.push(ThresholdCurvePoint {
            threshold: (t * 100.0).round() / 100.0,
            attack_fast_miss: miss,
            clean_fast_ratio: fast_r,
        });
        if miss <= max_miss && fast_r + 1e-9 >= best_fast && t <= 0.40 && t >= best_thr {
            best_fast = fast_r;
            best_thr = t;
        }
        t += 0.01;
    }
    if best_fast < 0.0 {
        let mut best_miss = 1.0f64;
        for p in &curve {
            if p.attack_fast_miss < best_miss - 1e-12
                || ((p.attack_fast_miss - best_miss).abs() < 1e-9
                    && p.clean_fast_ratio > best_fast)
            {
                best_miss = p.attack_fast_miss;
                best_fast = p.clean_fast_ratio;
                best_thr = p.threshold.clamp(0.20, 0.40);
            }
        }
    }
    let (miss, fast_r, atk, clean) = eval_threshold(samples, weights, best_thr);
    let gray = (best_thr * 0.55).clamp(0.12, best_thr - 0.05);
    RisCalibrateReport {
        recommended_deep_threshold: (best_thr * 100.0).round() / 100.0,
        recommended_gray_threshold: (gray * 100.0).round() / 100.0,
        attack_fast_miss: miss,
        clean_fast_ratio: fast_r,
        attack_count: atk,
        clean_count: clean,
        max_miss,
        curve,
        model: if weights.stumps.is_empty() {
            "logistic".into()
        } else {
            "logistic+stumps".into()
        },
    }
}
