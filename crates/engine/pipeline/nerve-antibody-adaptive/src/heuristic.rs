//! 内置启发式 logit 模型（heuristic-v1）。
//!
//! 贡献门闩：仅当存在可疑佐证时才 `contributed=true`，避免「多 view 静态资源」刷出模型分。

use crate::scorer::{AdaptiveInput, AdaptiveOutput};
use crate::{effective_level_weight, effective_score_cap, is_suspicious, RiskModel};

/// 浅特征启发式。
pub struct HeuristicModel;

impl RiskModel for HeuristicModel {
    fn version(&self) -> &str {
        "heuristic-v1"
    }

    fn score(&self, input: &AdaptiveInput<'_>) -> AdaptiveOutput {
        let f = input.features;
        let mut logit = -2.2_f32;
        let mut tops = Vec::new();

        let special = f.special_ratio.clamp(0.0, 1.0);
        logit += special * 1.8;
        if special > 0.12 {
            tops.push(format!("special_ratio={special:.2}"));
        }

        if f.sql_keyword_hits > 0 {
            logit += 0.9 * f.sql_keyword_hits.min(3) as f32;
            tops.push(format!("sql_kw={}", f.sql_keyword_hits));
        }
        if f.xss_keyword_hits > 0 {
            logit += 0.85 * f.xss_keyword_hits.min(3) as f32;
            tops.push(format!("xss_kw={}", f.xss_keyword_hits));
        }
        if f.path_keyword_hits > 0 {
            logit += 0.7 * f.path_keyword_hits.min(2) as f32;
            tops.push(format!("path_kw={}", f.path_keyword_hits));
        }
        if f.rce_keyword_hits > 0 {
            logit += 0.9 * f.rce_keyword_hits.min(3) as f32;
            tops.push(format!("rce_kw={}", f.rce_keyword_hits));
        }
        if f.decode_depth >= 2 {
            logit += 0.45 * f.decode_depth.min(6) as f32;
            tops.push(format!("decode_depth={}", f.decode_depth));
        }

        logit += 0.35 * f.rule_block_count.min(4) as f32;
        logit += 0.25 * f.semantic_score.min(40) as f32 / 20.0;
        // view/param 只作微调，不能单独贡献
        logit += 0.02 * f.view_count.min(20) as f32;
        logit += 0.02 * f.param_count.min(32) as f32;

        if f.query_len < 8 && f.body_len < 8 && f.rule_hit_count == 0 {
            logit -= 1.2;
        }
        if f.semantic_veto {
            logit -= 2.5;
            tops.push("semantic_veto".into());
        }

        let p = 1.0 / (1.0 + (-logit).exp());
        let w = effective_level_weight(input);
        let cap = effective_score_cap(input);
        let raw = (p * w * cap as f32).round() as u32;
        let mut model_score = raw.min(cap);
        let suspicious = is_suspicious(f);
        if !suspicious {
            model_score = 0;
        }
        let contributed = input.contribute && model_score > 0 && w > 0.0 && suspicious;

        AdaptiveOutput {
            p,
            model_score,
            contributed,
            version: self.version().into(),
            top_features: tops,
        }
    }
}
