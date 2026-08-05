//! 引擎健康快照（运维 / Console 状态条）。

use serde::Serialize;

/// [`crate::Engine::health`] 返回值。
#[derive(Debug, Clone, Serialize)]
pub struct NativeHealth {
    pub ready: bool,
    pub pack_id: String,
    pub pack_version: String,
    pub content_hash: String,
    pub rule_count: usize,
    /// 默认阈值（兼容）。
    pub block_threshold: u32,
    pub threshold_low: u32,
    pub threshold_medium: u32,
    pub threshold_high: u32,
    pub rules_low: usize,
    pub rules_medium: usize,
    pub rules_high: usize,
    pub observe_only: bool,
    pub semantic_enabled: bool,
    pub adaptive_enabled: bool,
    pub adaptive_contribute: bool,
    pub accel: String,
    pub pipeline_decode: bool,
    pub pipeline_structural: bool,
    pub pipeline_base64: bool,
    pub max_inspect_ms: u64,
    pub model_version: String,
    /// `[policy.inspect].mode`（`auto` / `deep` / `fast`）。
    pub inspect_mode: String,
    pub fast_max_inspect_ms: Option<u64>,
    /// 语义包路径（相对 pack 根）；空=仅内置。
    pub semantic_pack_path: Option<String>,
    pub semantic_pack_version: Option<String>,
    pub semantic_signature_count: usize,
    /// 声明式信号包。
    pub signals_enabled: bool,
    pub signals_pack_path: Option<String>,
    pub signals_pack_version: Option<String>,
    pub signals_feature_count: usize,
    pub signals_fingerprint_count: usize,
}
