//! 自适应风险模型：trait + 启发式 / 线性权重 / 可选 ONNX 入口。

mod heuristic;
mod linear;
#[cfg(feature = "onnx")]
mod onnx;
mod scorer;

pub use heuristic::HeuristicModel;
pub use linear::{LinearModel, LinearWeights};
pub use scorer::{
    install_model, score, AdaptiveInput, AdaptiveOutput, FeatureSnapshot,
};

use nerve_antibody_dsl::NativeLevel;
use std::path::Path;
use std::sync::Arc;

/// 可插拔风险模型（assist-only）。
pub trait RiskModel: Send + Sync {
    fn version(&self) -> &str;
    fn score(&self, input: &AdaptiveInput<'_>) -> AdaptiveOutput;
}

/// 按路径加载模型；失败或不存在则回退启发式。
pub fn load_model(path: Option<&Path>) -> Arc<dyn RiskModel> {
    if let Some(p) = path {
        if p.is_file() {
            #[cfg(feature = "onnx")]
            {
                if p
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("onnx"))
                {
                    if let Ok(m) = onnx::OnnxModel::load(p) {
                        return Arc::new(m);
                    }
                }
            }
            if let Ok(m) = LinearModel::load(p) {
                return Arc::new(m);
            }
        }
    }
    if let Ok(p) = std::env::var("NERVE_NATIVE_MODEL") {
        let p = Path::new(p.trim());
        if p.is_file() {
            if let Ok(m) = LinearModel::load(p) {
                return Arc::new(m);
            }
        }
    }
    Arc::new(HeuristicModel)
}

/// 模型权重：low 不贡献；medium/high 递增。
pub fn level_weight(level: NativeLevel) -> f32 {
    match level {
        NativeLevel::Low => 0.0,
        NativeLevel::Medium => 0.7,
        NativeLevel::High => 1.0,
    }
}

/// medium 封顶 25，high 封顶 35（仍不可裸模型硬拦）。
pub fn score_cap(level: NativeLevel) -> u32 {
    match level {
        NativeLevel::Low => 0,
        NativeLevel::Medium => 25,
        NativeLevel::High => 35,
    }
}

/// 模型贡献门闩：必须有可解释的攻击佐证，否则不贡献（静态 JS/API 噪声不得刷 challenge）。
///
/// 清晰边界：
/// - **不贡献** → Fusion 走 observe（界面 pass）
/// - **贡献** → Fusion 可 challenge（深检）
///
/// 刻意不含：
/// - `special_ratio`（JSON/JS 引号会淹没生产）
/// - 单纯 `decode_depth`（URL/HTML 正规化也会 ≥2）
pub fn is_suspicious(f: &FeatureSnapshot) -> bool {
    let kw = f.sql_keyword_hits
        + f.xss_keyword_hits
        + f.path_keyword_hits
        + f.rce_keyword_hits;
    kw > 0 || f.rule_hit_count > 0 || f.semantic_score > 0
}
