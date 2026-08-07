//! 特征快照与统一 score() 入口。

use crate::{load_model, RiskModel};
use nerve_antibody_dsl::NativeLevel;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// 供模型使用的特征快照。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureSnapshot {
    pub uri_len: u32,
    pub query_len: u32,
    pub body_len: u32,
    pub special_ratio: f32,
    pub sql_keyword_hits: u32,
    pub xss_keyword_hits: u32,
    pub path_keyword_hits: u32,
    #[serde(default)]
    pub rce_keyword_hits: u32,
    pub rule_hit_count: u32,
    pub rule_block_count: u32,
    pub semantic_score: u32,
    pub semantic_veto: bool,
    #[serde(default)]
    pub view_count: u32,
    #[serde(default)]
    pub param_count: u32,
    #[serde(default)]
    pub decode_depth: u32,
}

/// 自适应输入。
#[derive(Debug, Clone)]
pub struct AdaptiveInput<'a> {
    pub level: NativeLevel,
    pub features: &'a FeatureSnapshot,
    pub contribute: bool,
    /// 来自 `[policy.levels.*.adaptive_level_weight]`；`None` 时回退默认档权重。
    pub level_weight: Option<f32>,
    /// 来自 `[policy.levels.*.adaptive_score_cap]`；`None` 时回退默认档封顶。
    pub score_cap: Option<u32>,
}

/// 自适应输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveOutput {
    pub p: f32,
    pub model_score: u32,
    pub contributed: bool,
    pub version: String,
    pub top_features: Vec<String>,
}

static GLOBAL_MODEL: RwLock<Option<Arc<dyn RiskModel>>> = RwLock::new(None);

/// 安装/替换进程级模型（引擎 load/reload 时调用）。
pub fn install_model(model: Arc<dyn RiskModel>) {
    if let Ok(mut g) = GLOBAL_MODEL.write() {
        *g = Some(model);
    }
}

fn current_model() -> Arc<dyn RiskModel> {
    if let Ok(g) = GLOBAL_MODEL.read() {
        if let Some(m) = g.as_ref() {
            return Arc::clone(m);
        }
    }
    load_model(None)
}

/// 计算自适应分（走已安装或默认模型）。
pub fn score(input: AdaptiveInput<'_>) -> AdaptiveOutput {
    current_model().score(&input)
}
