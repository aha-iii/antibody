use crate::route_gate::RouteGateConfig;
use nerve_antibody_metrics::InspectPath;
use nerve_antibody_pipeline::{PipelineConfig, RequestViews};
use nerve_antibody_signals::SignalPack;
use std::sync::Arc;

/// inspect 模式：`auto` 双路径 · `deep` 全量（bench）· `fast` 仅预过滤。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectMode {
    Auto,
    Deep,
    Fast,
}

impl InspectMode {
    pub fn resolve(config: &str) -> Self {
        if let Ok(v) = std::env::var("NERVE_NATIVE_INSPECT_MODE") {
            return Self::parse(&v);
        }
        Self::parse(config)
    }

    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "deep" => Self::Deep,
            "fast" => Self::Fast,
            _ => Self::Auto,
        }
    }
}

/// Evaluator 附加策略（来自 pack.toml）。
#[derive(Clone)]
pub struct EvalPolicy {
    pub semantic_enabled: bool,
    pub adaptive_enabled: bool,
    pub adaptive_contribute: bool,
    pub pipeline: PipelineConfig,
    /// pack `[policy.inspect].mode`；可被 `NERVE_NATIVE_INSPECT_MODE` 覆盖。
    pub inspect_mode: String,
    pub fast_max_inspect_ms: Option<u64>,
    pub route_gate: RouteGateConfig,
    /// Fusion v3：`block` 弱信号组合至少需要的独立信号类数。
    pub fusion_min_independent: u8,
    /// 深路径两阶段解码：先浅层，无命中再全量。
    pub lazy_decode: bool,
    /// 声明式信号包（与内置叠加）。
    pub signal_pack: Option<Arc<SignalPack>>,
    /// Deep decode 视图 LRU（engine 注入）。
    pub deep_view_cache: Option<Arc<dyn crate::decode_cache::DeepViewCache>>,
}

impl Default for EvalPolicy {
    fn default() -> Self {
        Self {
            semantic_enabled: true,
            adaptive_enabled: true,
            adaptive_contribute: true,
            pipeline: PipelineConfig::default(),
            inspect_mode: "auto".into(),
            fast_max_inspect_ms: None,
            route_gate: RouteGateConfig::default(),
            fusion_min_independent: 1,
            lazy_decode: true,
            signal_pack: None,
            deep_view_cache: None,
        }
    }
}

/// 一次 inspect 的路由规划（engine 预览与 worker 执行共用，避免重复 build_views）。
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanCacheHints {
    /// Bloom 高置信干净：降低 deep 倾向（仍跑 L1）。
    pub bloom_clear: bool,
}

/// 一次 inspect 的路由规划（engine 预览与 worker 执行共用，避免重复 build_views）。
#[derive(Debug, Clone)]
pub struct InspectPlan {
    pub path: InspectPath,
    pub views_preview: RequestViews,
    pub decode_hint: bool,
    pub evasion_hint: bool,
    pub route_deep: bool,
    pub route_score: f32,
    /// 干净 JSON / API 正向快通道：同步 Fast，不进池、不升 Deep。
    pub inline_fast_lane: bool,
    /// 仅 L1 Aho + allow，跳过 tail regex（API 正向模型）。
    pub api_positive_lane: bool,
    /// plan_inspect 已算好的 signals，避免 inspect 热路径重复扫描。
    pub route_signals: nerve_antibody_signals::RequestSignals,
    /// 预拼接 prefilter haystack（64KB cap）。
    pub prefilter_hay: String,
}

/// 条件命中证据。
#[derive(Debug, Clone)]
pub(super) struct CondHit {
    pub(super) evidence: String,
    pub(super) param_path: Option<String>,
    pub(super) decode_chain: Option<Vec<String>>,
}
