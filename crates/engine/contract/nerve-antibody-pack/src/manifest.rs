//! pack.toml 清单结构。

use serde::Deserialize;
use std::collections::HashMap;

/// 规则包清单（对应包根目录 `pack.toml`）。
#[derive(Debug, Clone, Deserialize)]
pub struct PackManifest {
    /// 包 ID（稳定标识，写入命中 `rule_set=expert-<id>`）。
    pub id: String,
    /// 语义版本或发版标签。
    pub version: String,
    /// 显示名。
    #[serde(default)]
    pub name: String,
    /// 要求的最低引擎版本（semver；加载时强制校验）。
    #[serde(default)]
    pub min_engine: String,
    /// 评分与观察策略。
    #[serde(default)]
    pub policy: PackPolicy,
}

/// 按强度档覆盖 `block_threshold`。
#[derive(Debug, Clone, Deserialize)]
pub struct ThresholdByLevel {
    #[serde(default = "default_thr_low")]
    pub low: u32,
    #[serde(default = "default_thr_medium")]
    pub medium: u32,
    #[serde(default = "default_thr_high")]
    pub high: u32,
}

impl Default for ThresholdByLevel {
    fn default() -> Self {
        Self {
            low: default_thr_low(),
            medium: default_thr_medium(),
            high: default_thr_high(),
        }
    }
}

fn default_thr_low() -> u32 {
    48
}
fn default_thr_medium() -> u32 {
    40
}
fn default_thr_high() -> u32 {
    32
}

/// 语义分析开关。
#[derive(Debug, Clone, Deserialize)]
pub struct SemanticPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 可选语义包（相对 pack 根），如 `semantic/signatures.yaml`。
    #[serde(default)]
    pub pack_path: Option<String>,
}

impl Default for SemanticPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            pack_path: None,
        }
    }
}

/// 声明式 feature / fingerprint 信号包。
#[derive(Debug, Clone, Deserialize)]
pub struct SignalsPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 相对 pack 根，如 `signals/signals.yaml`；空则尝试默认路径。
    #[serde(default)]
    pub pack_path: Option<String>,
}

impl Default for SignalsPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            pack_path: None,
        }
    }
}

/// inspect 双路径策略（生产 auto / bench deep）。
#[derive(Debug, Clone, Deserialize)]
pub struct InspectPolicy {
    /// `auto`（默认）：干净流量快路径；`deep`：全量 regex（bench）；`fast`：仅 Aho+allow。
    #[serde(default = "default_inspect_mode")]
    pub mode: String,
    /// auto 模式下快路径 inspect 预算上限（毫秒）；0=沿用 pipeline。
    #[serde(default)]
    pub fast_max_inspect_ms: Option<u64>,
    /// Stage-0 路由门闩（特征线性分 → deep）。
    #[serde(default)]
    pub route_gate: RouteGatePolicy,
}

/// 轻量路由门闩（Learned Fast Filter 白盒版）。
#[derive(Debug, Clone, Deserialize)]
pub struct RouteGatePolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Nerve RIS：score ≥ deep_threshold → hot → Deep。
    #[serde(default = "default_deep_threshold")]
    pub deep_threshold: f32,
    /// Nerve RIS：gray_threshold ≤ score < deep_threshold → gray → Fast(+escalate)。
    #[serde(default = "default_gray_threshold")]
    pub gray_threshold: f32,
    #[serde(default = "default_true")]
    pub hard_decode_hint: bool,
    /// 可选 JSON 权重（相对 pack 根），bench 校准输出。
    #[serde(default)]
    pub weights_path: Option<String>,
    /// inline 权重覆盖（键名见 route_gate::feature_names）。
    #[serde(default)]
    pub weights: HashMap<String, f32>,
    #[serde(default)]
    pub bias: f32,
}

fn default_deep_threshold() -> f32 {
    0.35
}

fn default_gray_threshold() -> f32 {
    0.20
}

impl Default for RouteGatePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            deep_threshold: default_deep_threshold(),
            gray_threshold: default_gray_threshold(),
            hard_decode_hint: true,
            weights_path: None,
            weights: HashMap::new(),
            bias: 0.0,
        }
    }
}

fn default_inspect_mode() -> String {
    "auto".into()
}

impl Default for InspectPolicy {
    fn default() -> Self {
        Self {
            mode: default_inspect_mode(),
            fast_max_inspect_ms: None,
            route_gate: RouteGatePolicy::default(),
        }
    }
}

/// 自适应模型开关。
#[derive(Debug, Clone, Deserialize)]
pub struct AdaptivePolicy {
    /// 是否计算模型分（可仅 shadow）。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 为 true 时 model_score 参与融合；false 时只记录（shadow）。
    #[serde(default)]
    pub contribute: bool,
    /// 可选模型文件路径（相对 pack 根或绝对）；空则用内置启发式/线性权重。
    #[serde(default)]
    pub model_path: Option<String>,
}

impl Default for AdaptivePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            contribute: true,
            model_path: None,
        }
    }
}

/// 单档完整配置（挂在 `[policy.levels.{low,medium,high}]`；字段缺省 = 继承全局 `[policy.pipeline]`）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LevelProfile {
    #[serde(default)]
    pub block_threshold: Option<u32>,
    #[serde(default)]
    pub max_inspect_ms: Option<u64>,
    #[serde(default)]
    pub max_regex_evals: Option<u32>,
    #[serde(default)]
    pub max_decode_blobs: Option<usize>,
    #[serde(default)]
    pub max_decode_depth: Option<u8>,
    #[serde(default)]
    pub max_blob_chars: Option<usize>,
    #[serde(default)]
    pub max_field_chars: Option<usize>,
    #[serde(default)]
    pub max_params: Option<usize>,
    #[serde(default)]
    pub base64_expand: Option<bool>,
    #[serde(default)]
    pub decode_enabled: Option<bool>,
    #[serde(default)]
    pub structural_enabled: Option<bool>,
    /// 自适应模型档权重（原硬编码 0 / 0.7 / 1.0）。
    #[serde(default)]
    pub adaptive_level_weight: Option<f32>,
    /// 自适应模型分贡献上限（原硬编码 0 / 25 / 35）。
    #[serde(default)]
    pub adaptive_score_cap: Option<u32>,
}

/// 三档策略（与全局 `[policy.pipeline]` 分离）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LevelsPolicy {
    #[serde(default)]
    pub low: LevelProfile,
    #[serde(default)]
    pub medium: LevelProfile,
    #[serde(default)]
    pub high: LevelProfile,
}

impl LevelsPolicy {
    pub fn get(&self, level: &str) -> &LevelProfile {
        match level {
            "low" => &self.low,
            "high" => &self.high,
            _ => &self.medium,
        }
    }
}

/// 兼容旧字段：仅预算两项（若同时配置 `levels`，以 `levels` 为准）。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PipelineLevelBudget {
    #[serde(default)]
    pub max_inspect_ms: Option<u64>,
    #[serde(default)]
    pub max_regex_evals: Option<u32>,
}

/// 兼容旧 `[policy.pipeline.by_level]`。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PipelineByLevel {
    #[serde(default)]
    pub low: PipelineLevelBudget,
    #[serde(default)]
    pub medium: PipelineLevelBudget,
    #[serde(default)]
    pub high: PipelineLevelBudget,
}

/// 路由预览浅解码上限（`[policy.pipeline.route_preview]`）。
#[derive(Debug, Clone, Deserialize)]
pub struct RoutePreviewPolicy {
    #[serde(default = "default_rp_blobs")]
    pub max_decode_blobs: usize,
    #[serde(default = "default_rp_blob_chars")]
    pub max_blob_chars: usize,
    #[serde(default = "default_rp_field_chars")]
    pub max_field_chars: usize,
    #[serde(default = "default_rp_depth")]
    pub max_decode_depth: u8,
    #[serde(default = "default_rp_params")]
    pub max_params: usize,
}

fn default_rp_blobs() -> usize {
    8
}
fn default_rp_blob_chars() -> usize {
    4096
}
fn default_rp_field_chars() -> usize {
    8192
}
fn default_rp_depth() -> u8 {
    2
}
fn default_rp_params() -> usize {
    64
}

impl Default for RoutePreviewPolicy {
    fn default() -> Self {
        Self {
            max_decode_blobs: default_rp_blobs(),
            max_blob_chars: default_rp_blob_chars(),
            max_field_chars: default_rp_field_chars(),
            max_decode_depth: default_rp_depth(),
            max_params: default_rp_params(),
        }
    }
}

/// 快路径开关（`[policy.pipeline.fast_path]`）。
#[derive(Debug, Clone, Deserialize)]
pub struct FastPathPolicy {
    #[serde(default)]
    pub decode_enabled: bool,
    #[serde(default)]
    pub base64_expand: bool,
    #[serde(default)]
    pub structural_enabled: bool,
    #[serde(default)]
    pub max_decode_blobs: usize,
    #[serde(default)]
    pub max_decode_depth: u8,
}

impl Default for FastPathPolicy {
    fn default() -> Self {
        Self {
            decode_enabled: false,
            base64_expand: false,
            structural_enabled: false,
            max_decode_blobs: 0,
            max_decode_depth: 0,
        }
    }
}

/// 边缘内联收紧默认（`[policy.pipeline.edge]`；可被 env 覆盖）。
#[derive(Debug, Clone, Deserialize)]
pub struct EdgePipelinePolicy {
    #[serde(default = "default_edge_ms")]
    pub max_inspect_ms: u64,
    #[serde(default = "default_edge_regex")]
    pub max_regex_evals: u32,
}

fn default_edge_ms() -> u64 {
    300
}
fn default_edge_regex() -> u32 {
    20_000
}

impl Default for EdgePipelinePolicy {
    fn default() -> Self {
        Self {
            max_inspect_ms: default_edge_ms(),
            max_regex_evals: default_edge_regex(),
        }
    }
}

/// 引擎级 Decode / Structural / Budget 策略。
#[derive(Debug, Clone, Deserialize)]
pub struct PipelinePolicy {
    #[serde(default = "default_true")]
    pub decode_enabled: bool,
    #[serde(default = "default_true")]
    pub base64_expand: bool,
    #[serde(default = "default_true")]
    pub structural_enabled: bool,
    #[serde(default = "default_max_blobs")]
    pub max_decode_blobs: usize,
    #[serde(default = "default_max_blob_chars")]
    pub max_blob_chars: usize,
    /// 规则字段 head-tail 截断（uri/query/body）；默认 65536。
    #[serde(default = "default_max_field_chars")]
    pub max_field_chars: usize,
    #[serde(default = "default_max_params")]
    pub max_params: usize,
    #[serde(default = "default_max_decode_depth")]
    pub max_decode_depth: u8,
    /// 基值（档未覆盖时使用）；`0` = 不限制。
    #[serde(default = "default_max_inspect_ms")]
    pub max_inspect_ms: u64,
    #[serde(default = "default_max_regex")]
    pub max_regex_evals: u32,
    /// 深路径两阶段解码（浅层优先，可疑再全量）。
    #[serde(default = "default_true")]
    pub lazy_decode: bool,
    /// 旧分档预算（兼容）；优先使用 `[policy.levels]`。
    #[serde(default)]
    pub by_level: PipelineByLevel,
    /// 安全硬顶（防误配）；`0` = 不设硬顶。默认 60s。
    #[serde(default = "default_abs_max_inspect_ms")]
    pub abs_max_inspect_ms: u64,
    /// 正则求值次数硬顶；`0` = 不设硬顶。默认 500_000。
    #[serde(default = "default_abs_max_regex_evals")]
    pub abs_max_regex_evals: u32,
    #[serde(default)]
    pub route_preview: RoutePreviewPolicy,
    #[serde(default)]
    pub fast_path: FastPathPolicy,
    #[serde(default)]
    pub edge: EdgePipelinePolicy,
}

impl Default for PipelinePolicy {
    fn default() -> Self {
        Self {
            decode_enabled: true,
            base64_expand: true,
            structural_enabled: true,
            max_decode_blobs: default_max_blobs(),
            max_blob_chars: default_max_blob_chars(),
            max_field_chars: default_max_field_chars(),
            max_params: default_max_params(),
            max_decode_depth: default_max_decode_depth(),
            max_inspect_ms: default_max_inspect_ms(),
            max_regex_evals: default_max_regex(),
            lazy_decode: true,
            by_level: PipelineByLevel::default(),
            abs_max_inspect_ms: default_abs_max_inspect_ms(),
            abs_max_regex_evals: default_abs_max_regex_evals(),
            route_preview: RoutePreviewPolicy::default(),
            fast_path: FastPathPolicy::default(),
            edge: EdgePipelinePolicy::default(),
        }
    }
}

fn default_max_blobs() -> usize {
    32
}
fn default_max_blob_chars() -> usize {
    8192
}
fn default_max_field_chars() -> usize {
    65536
}
fn default_max_params() -> usize {
    256
}
fn default_max_decode_depth() -> u8 {
    4
}
fn default_max_inspect_ms() -> u64 {
    80
}
fn default_max_regex() -> u32 {
    4000
}
fn default_abs_max_inspect_ms() -> u64 {
    60_000
}
fn default_abs_max_regex_evals() -> u32 {
    500_000
}

fn default_true() -> bool {
    true
}

/// 包级策略：决定「观察还是拦截」。
#[derive(Debug, Clone, Deserialize)]
pub struct PackPolicy {
    /// 默认阈值（无 per-level 覆盖时的回退；也作 medium 兼容）。
    #[serde(default = "default_threshold")]
    pub block_threshold: u32,
    /// 为 true 时整包强制观察（只记不拦，用于灰度）。
    #[serde(default)]
    pub observe_only: bool,
    /// 按档阈值（兼容旧包；优先 `[policy.levels.*.block_threshold]`）。
    #[serde(default)]
    pub threshold_by_level: ThresholdByLevel,
    /// 分档完整配置（阈值 / 预算 / 解码 / 自适应）。
    #[serde(default)]
    pub levels: LevelsPolicy,
    /// 语义层。
    #[serde(default)]
    pub semantic: SemanticPolicy,
    /// 声明式信号（feature / fingerprint YAML）。
    #[serde(default)]
    pub signals: SignalsPolicy,
    /// 自适应模型层。
    #[serde(default)]
    pub adaptive: AdaptivePolicy,
    /// 引擎管线。
    #[serde(default)]
    pub pipeline: PipelinePolicy,
    /// inspect 快/深路径。
    #[serde(default)]
    pub inspect: InspectPolicy,
    /// Fusion v3：可审计融合策略。
    #[serde(default)]
    pub fusion: FusionPolicy,
}

/// 融合层策略（Attribution-preserving）。
#[derive(Debug, Clone, Deserialize)]
pub struct FusionPolicy {
    /// block 至少需要的独立信号类数（1=兼容 v2；2=金融/合规推荐）。
    #[serde(default = "default_min_independent")]
    pub min_independent_signals: u8,
}

fn default_min_independent() -> u8 {
    1
}

impl Default for FusionPolicy {
    fn default() -> Self {
        Self {
            min_independent_signals: default_min_independent(),
        }
    }
}

impl Default for PackPolicy {
    fn default() -> Self {
        Self {
            block_threshold: default_threshold(),
            observe_only: false,
            threshold_by_level: ThresholdByLevel::default(),
            levels: LevelsPolicy::default(),
            semantic: SemanticPolicy::default(),
            signals: SignalsPolicy::default(),
            adaptive: AdaptivePolicy::default(),
            pipeline: PipelinePolicy::default(),
            inspect: InspectPolicy::default(),
            fusion: FusionPolicy::default(),
        }
    }
}

impl PackPolicy {
    /// 取某一强度档的拦截阈值（`levels` 优先于 `threshold_by_level`）。
    pub fn threshold_for(&self, level: &str) -> u32 {
        if let Some(t) = self.levels.get(level).block_threshold {
            return t;
        }
        match level {
            "low" => self.threshold_by_level.low,
            "high" => self.threshold_by_level.high,
            _ => self.threshold_by_level.medium,
        }
    }
}

fn default_threshold() -> u32 {
    40
}
