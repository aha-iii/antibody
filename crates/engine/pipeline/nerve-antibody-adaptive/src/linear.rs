//! 线性权重模型（JSON）：真实可校准 ML，非手工 if/else。

use crate::scorer::{AdaptiveInput, AdaptiveOutput, FeatureSnapshot};
use crate::{is_suspicious, level_weight, score_cap, RiskModel};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// JSON 权重文件格式。
#[derive(Debug, Clone, Deserialize)]
pub struct LinearWeights {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub bias: f32,
    #[serde(default)]
    pub special_ratio: f32,
    #[serde(default)]
    pub sql_keyword_hits: f32,
    #[serde(default)]
    pub xss_keyword_hits: f32,
    #[serde(default)]
    pub path_keyword_hits: f32,
    #[serde(default)]
    pub rce_keyword_hits: f32,
    #[serde(default)]
    pub decode_depth: f32,
    #[serde(default)]
    pub rule_block_count: f32,
    #[serde(default)]
    pub semantic_score: f32,
    #[serde(default)]
    pub view_count: f32,
    #[serde(default)]
    pub param_count: f32,
    #[serde(default)]
    pub semantic_veto: f32,
    #[serde(default)]
    pub short_benign: f32,
}

fn default_version() -> String {
    "linear-v1".into()
}

impl Default for LinearWeights {
    fn default() -> Self {
        Self {
            version: default_version(),
            bias: -2.2,
            special_ratio: 1.8,
            sql_keyword_hits: 0.9,
            xss_keyword_hits: 0.85,
            path_keyword_hits: 0.7,
            rce_keyword_hits: 0.9,
            decode_depth: 0.12,
            rule_block_count: 0.35,
            semantic_score: 0.0125,
            view_count: 0.05,
            param_count: 0.04,
            semantic_veto: -2.5,
            short_benign: -1.2,
        }
    }
}

/// 线性逻辑回归风格风险模型。
pub struct LinearModel {
    weights: LinearWeights,
}

impl LinearModel {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let weights: LinearWeights = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        Ok(Self { weights })
    }

    pub fn from_weights(weights: LinearWeights) -> Self {
        Self { weights }
    }

    fn logit(&self, f: &FeatureSnapshot) -> (f32, Vec<String>) {
        let w = &self.weights;
        let mut logit = w.bias;
        let mut tops = Vec::new();
        let special = f.special_ratio.clamp(0.0, 1.0);
        logit += special * w.special_ratio;
        if special > 0.12 {
            tops.push(format!("special_ratio={special:.2}"));
        }
        logit += f.sql_keyword_hits.min(3) as f32 * w.sql_keyword_hits;
        if f.sql_keyword_hits > 0 {
            tops.push(format!("sql_kw={}", f.sql_keyword_hits));
        }
        logit += f.xss_keyword_hits.min(3) as f32 * w.xss_keyword_hits;
        logit += f.path_keyword_hits.min(2) as f32 * w.path_keyword_hits;
        logit += f.rce_keyword_hits.min(3) as f32 * w.rce_keyword_hits;
        logit += f.decode_depth.min(8) as f32 * w.decode_depth;
        logit += f.rule_block_count.min(4) as f32 * w.rule_block_count;
        logit += f.semantic_score.min(40) as f32 * w.semantic_score;
        logit += f.view_count.min(20) as f32 * w.view_count;
        logit += f.param_count.min(32) as f32 * w.param_count;
        if f.query_len < 8 && f.body_len < 8 && f.rule_hit_count == 0 {
            logit += w.short_benign;
        }
        if f.semantic_veto {
            logit += w.semantic_veto;
            tops.push("semantic_veto".into());
        }
        (logit, tops)
    }
}

impl RiskModel for LinearModel {
    fn version(&self) -> &str {
        self.weights.version.as_str()
    }

    fn score(&self, input: &AdaptiveInput<'_>) -> AdaptiveOutput {
        let (logit, tops) = self.logit(input.features);
        let p = 1.0 / (1.0 + (-logit).exp());
        let lw = level_weight(input.level);
        let cap = score_cap(input.level);
        let raw = (p * lw * cap as f32).round() as u32;
        let mut model_score = raw.min(cap);
        let suspicious = is_suspicious(input.features);
        if !suspicious {
            model_score = 0;
        }
        let contributed = input.contribute && model_score > 0 && lw > 0.0 && suspicious;
        AdaptiveOutput {
            p,
            model_score,
            contributed,
            version: self.version().into(),
            top_features: tops,
        }
    }
}
