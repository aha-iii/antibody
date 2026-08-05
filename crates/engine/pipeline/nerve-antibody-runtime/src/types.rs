//! 检测请求与命中结果类型。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 送入自研引擎的归一化 HTTP 请求/响应视图。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NativeRequest {
    pub method: String,
    pub host: String,
    pub uri: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    /// Content-Type（可从 headers 推断；显式传入优先）。
    #[serde(default)]
    pub content_type: Option<String>,
    /// 响应体（响应阶段检测；请求阶段可空）。
    #[serde(default)]
    pub response_body: Option<String>,
}

impl NativeRequest {
    /// 解析 Content-Type：显式字段优先，否则扫 headers。
    pub fn content_type(&self) -> Option<&str> {
        if let Some(ct) = self.content_type.as_deref() {
            if !ct.is_empty() {
                return Some(ct);
            }
        }
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
    }
}

/// 单条规则命中明细。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub score: u32,
    /// `block` / `observe` / `allow`。
    pub action: String,
    pub evidence: String,
    /// 命中参数路径（如 `query.id` / `body.user.name`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_path: Option<String>,
    /// 解码链证据。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode_chain: Option<Vec<String>>,
}

/// 语义信号（序列化到 API）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSignalDto {
    pub kind: String,
    pub id: String,
    pub confidence: f32,
    pub score_delta: u32,
    pub veto: bool,
    #[serde(default)]
    pub block_eligible: bool,
    pub evidence: String,
}

/// 自适应模型明细。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelHitDto {
    pub p: f32,
    pub model_score: u32,
    pub contributed: bool,
    pub version: String,
    pub top_features: Vec<String>,
}

/// 一次 inspect 的融合结果（仅当至少有规则/语义/模型信号时返回 `Some`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NativeHit {
    pub total_score: u32,
    pub block_threshold: u32,
    /// 融合后动作：`block` | `challenge` | `observe`。
    pub action: String,
    pub matched: Vec<MatchedRule>,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub evidence: String,
    /// 强度档。
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub rule_score: u32,
    #[serde(default)]
    pub allow_score: u32,
    #[serde(default)]
    pub semantic_score: u32,
    #[serde(default)]
    pub model_score: u32,
    #[serde(default)]
    pub semantic_signals: Vec<SemanticSignalDto>,
    #[serde(default)]
    pub model: Option<ModelHitDto>,
    /// 主命中参数路径。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_path: Option<String>,
    /// 主命中解码链。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode_chain: Option<Vec<String>>,
    /// 预算熔断原因（若触发）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_exhausted: Option<String>,
    /// 本次 inspect 路径：`fast` | `deep`。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inspect_path: String,
}
