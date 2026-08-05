//! Engram-Detect 远程推理 backeed（assist-only）。
//!
//! 环境变量 `NERVE_ENGRAM_URL`：Engram Gateway scoring 端点。
//! POST `{ "features": { ... } }` → `{ "score": 0-100, "contributed": bool, "label": "..." }`

use crate::scorer::{AdaptiveInput, AdaptiveOutput};
use crate::{is_suspicious, score_cap, RiskModel};
use nerve_antibody_dsl::NativeLevel;
use serde::Deserialize;
use std::time::Duration;

pub struct EngramBackeed {
    client: reqwest::blocking::Client,
    url: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct EngramResponse {
    #[serde(default)]
    score: f32,
    #[serde(default)]
    contributed: bool,
    #[serde(default)]
    label: Option<String>,
}

impl EngramBackeed {
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("NERVE_ENGRAM_URL").ok()?;
        let url = url.trim().to_string();
        if url.is_empty() {
            return None;
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(80))
            .build()
            .ok()?;
        let version = std::env::var("NERVE_ENGRAM_MODEL").unwrap_or_else(|_| "engram-detect-v0".into());
        Some(Self {
            client,
            url,
            version,
        })
    }

    fn feature_payload(input: &AdaptiveInput<'_>) -> serde_json::Value {
        let f = input.features;
        serde_json::json!({
            "sql_keyword_hits": f.sql_keyword_hits,
            "xss_keyword_hits": f.xss_keyword_hits,
            "path_keyword_hits": f.path_keyword_hits,
            "rce_keyword_hits": f.rce_keyword_hits,
            "rule_hit_count": f.rule_hit_count,
            "semantic_score": f.semantic_score,
            "decode_depth": f.decode_depth,
            "level": format!("{:?}", input.level),
        })
    }
}

impl RiskModel for EngramBackeed {
    fn version(&self) -> &str {
        &self.version
    }

    fn score(&self, input: &AdaptiveInput<'_>) -> AdaptiveOutput {
        if !input.contribute || !is_suspicious(input.features) {
            return AdaptiveOutput {
                p: 0.0,
                model_score: 0,
                contributed: false,
                version: self.version.clone(),
                top_features: vec![],
            };
        }
        let body = serde_json::json!({ "features": Self::feature_payload(input) });
        let parsed: EngramResponse = match self.client.post(&self.url).json(&body).send() {
            Ok(r) => match r.json() {
                Ok(v) => v,
                Err(_) => {
                    return AdaptiveOutput {
                        p: 0.0,
                        model_score: 0,
                        contributed: false,
                        version: self.version.clone(),
                        top_features: vec!["engram_parse_error".into()],
                    };
                }
            },
            Err(_) => {
                return AdaptiveOutput {
                    p: 0.0,
                    model_score: 0,
                    contributed: false,
                    version: format!("{}:uereachable", self.version),
                    top_features: vec!["engram_uereachable".into()],
                };
            }
        };
        let cap = score_cap(input.level);
        let raw = parsed.score.clamp(0.0, 100.0) as u32;
        let model_score = raw.min(cap);
        let p = (model_score as f32 / cap.max(1) as f32).clamp(0.0, 1.0);
        let contributed =
            parsed.contributed && model_score > 0 && input.level != NativeLevel::Low;
        let mut tops = vec![format!("engram_score={model_score}")];
        if let Some(l) = parsed.label.filter(|s| !s.is_empty()) {
            tops.push(format!("engram_label={l}"));
        }
        AdaptiveOutput {
            p,
            model_score,
            contributed,
            version: self.version.clone(),
            top_features: tops,
        }
    }
}

pub fn shadow_mode_enabled() -> bool {
    std::env::var("NERVE_ENGRAM_SHADOW")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}
