//! 可热更新的自研检测引擎实现。
//!
//! 治理：live Program 热路径定罪；可选 sandbox Program 旁路观察（不改响应）。
//! 详见 `docs/GOVERNANCE-ARCHITECTURE-zh.md`。

use crate::error::NativeError;
use crate::health::NativeHealth;
use crate::pool;
use crate::shadow::{ShadowConfig, ShadowRuntime};
use nerve_antibody_adaptive::{self as adaptive, load_model};
use nerve_antibody_compiler::{compile, CompileOptions, ProgramArtifact};
use nerve_antibody_dsl::NativeLevel;
use nerve_antibody_metrics::{self, InspectPath};
use nerve_antibody_pack::NativePack;
use nerve_antibody_pipeline::PipelineConfig;
use nerve_antibody_runtime::{
    EvalPolicy, Evaluator, InspectExec, NativeHit, NativeRequest, PlanCacheHints, RouteGateConfig,
    RouteGateWeights,
};
use crate::inspect_cache::{global_verdict_cache, RisL1CacheProbe};
use nerve_antibody_semantic::{self as semantic, install_semantic_pack};
use nerve_antibody_signals::{load_signal_pack, SignalPack};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

static SHADOW: OnceLock<ShadowRuntime> = OnceLock::new();

fn shadow_runtime() -> &'static ShadowRuntime {
    SHADOW.get_or_init(|| ShadowRuntime::new(ShadowConfig::from_env()))
}

fn pool_enabled() -> bool {
    if edge_inline_enabled() {
        return false;
    }
    !matches!(
        std::env::var("NERVE_NATIVE_INSPECT_POOL").as_deref(),
        Ok("0") | Ok("false") | Ok("off")
    )
}

fn edge_inline_enabled() -> bool {
    matches!(
        std::env::var("NERVE_NATIVE_EDGE_INLINE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn apply_runtime_env_overrides(pipeline: &mut PipelineConfig, eval_policy: &mut EvalPolicy) {
    // 运维覆盖：改基值，并同步写入三档（避免 by_level 旧值压住 env）
    if let Ok(v) = std::env::var("NERVE_NATIVE_MAX_INSPECT_MS") {
        if let Ok(n) = v.parse::<u64>() {
            pipeline.max_inspect_ms = n;
            pipeline.by_level.low.max_inspect_ms = Some(n);
            pipeline.by_level.medium.max_inspect_ms = Some(n);
            pipeline.by_level.high.max_inspect_ms = Some(n);
        }
    }
    if let Ok(v) = std::env::var("NERVE_NATIVE_MAX_REGEX_EVALS") {
        if let Ok(n) = v.parse::<u32>() {
            pipeline.max_regex_evals = n;
            pipeline.by_level.low.max_regex_evals = Some(n);
            pipeline.by_level.medium.max_regex_evals = Some(n);
            pipeline.by_level.high.max_regex_evals = Some(n);
        }
    }
    if let Ok(v) = std::env::var("NERVE_NATIVE_ABS_MAX_INSPECT_MS") {
        if let Ok(n) = v.parse::<u64>() {
            pipeline.abs_max_inspect_ms = n;
        }
    }
    if let Ok(v) = std::env::var("NERVE_NATIVE_ABS_MAX_REGEX_EVALS") {
        if let Ok(n) = v.parse::<u32>() {
            pipeline.abs_max_regex_evals = n;
        }
    }
    if let Ok(v) = std::env::var("NERVE_NATIVE_FAST_MAX_INSPECT_MS") {
        if let Ok(n) = v.parse::<u64>() {
            eval_policy.fast_max_inspect_ms = Some(n);
        }
    }
    pipeline.apply_abs_caps();
    if edge_inline_enabled() {
        // 边缘内联：默认来自 pack `[policy.pipeline.edge]`；可被 env 覆盖
        let edge_ms = std::env::var("NERVE_NATIVE_EDGE_MAX_INSPECT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(pipeline.edge.max_inspect_ms);
        let edge_re = std::env::var("NERVE_NATIVE_EDGE_MAX_REGEX_EVALS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(pipeline.edge.max_regex_evals);
        pipeline.max_inspect_ms = if pipeline.max_inspect_ms == 0 {
            edge_ms
        } else {
            pipeline.max_inspect_ms.min(edge_ms)
        };
        pipeline.max_regex_evals = if pipeline.max_regex_evals == 0 {
            edge_re
        } else {
            pipeline.max_regex_evals.min(edge_re)
        };
        pipeline.by_level.low.max_inspect_ms = Some(pipeline.max_inspect_ms);
        pipeline.by_level.medium.max_inspect_ms = Some(pipeline.max_inspect_ms);
        pipeline.by_level.high.max_inspect_ms = Some(pipeline.max_inspect_ms);
        pipeline.by_level.low.max_regex_evals = Some(pipeline.max_regex_evals);
        pipeline.by_level.medium.max_regex_evals = Some(pipeline.max_regex_evals);
        pipeline.by_level.high.max_regex_evals = Some(pipeline.max_regex_evals);
        pipeline.apply_abs_caps();
    }
}

fn map_level_profile(
    profile: &nerve_antibody_pack::LevelProfile,
    legacy: &nerve_antibody_pack::PipelineLevelBudget,
) -> nerve_antibody_pipeline::LevelBudgetOverride {
    nerve_antibody_pipeline::LevelBudgetOverride {
        max_inspect_ms: profile.max_inspect_ms.or(legacy.max_inspect_ms),
        max_regex_evals: profile.max_regex_evals.or(legacy.max_regex_evals),
        max_decode_blobs: profile.max_decode_blobs,
        max_decode_depth: profile.max_decode_depth,
        max_blob_chars: profile.max_blob_chars,
        max_field_chars: profile.max_field_chars,
        max_params: profile.max_params,
        base64_expand: profile.base64_expand,
        decode_enabled: profile.decode_enabled,
        structural_enabled: profile.structural_enabled,
        adaptive_level_weight: profile.adaptive_level_weight,
        adaptive_score_cap: profile.adaptive_score_cap,
    }
}

fn map_budget_by_level(
    levels: &nerve_antibody_pack::LevelsPolicy,
    legacy: &nerve_antibody_pack::PipelineByLevel,
) -> nerve_antibody_pipeline::BudgetByLevel {
    nerve_antibody_pipeline::BudgetByLevel {
        low: map_level_profile(&levels.low, &legacy.low),
        medium: map_level_profile(&levels.medium, &legacy.medium),
        high: map_level_profile(&levels.high, &legacy.high),
    }
}

fn map_route_preview(
    src: &nerve_antibody_pack::RoutePreviewPolicy,
) -> nerve_antibody_pipeline::RoutePreviewConfig {
    nerve_antibody_pipeline::RoutePreviewConfig {
        max_decode_blobs: src.max_decode_blobs,
        max_blob_chars: src.max_blob_chars,
        max_field_chars: src.max_field_chars,
        max_decode_depth: src.max_decode_depth,
        max_params: src.max_params,
    }
}

fn map_fast_path(
    src: &nerve_antibody_pack::FastPathPolicy,
) -> nerve_antibody_pipeline::FastPathConfig {
    nerve_antibody_pipeline::FastPathConfig {
        decode_enabled: src.decode_enabled,
        base64_expand: src.base64_expand,
        structural_enabled: src.structural_enabled,
        max_decode_blobs: src.max_decode_blobs,
        max_decode_depth: src.max_decode_depth,
    }
}

fn map_edge(
    src: &nerve_antibody_pack::EdgePipelinePolicy,
) -> nerve_antibody_pipeline::EdgePipelineConfig {
    nerve_antibody_pipeline::EdgePipelineConfig {
        max_inspect_ms: src.max_inspect_ms,
        max_regex_evals: src.max_regex_evals,
    }
}

/// 引擎内部状态：一包三档 Evaluator（Low/Medium/High 各编译一份）。
struct EngineInner {
    pack_root: PathBuf,
    /// sealed 解密临时目录守卫。
    _sealed_guard: Option<nerve_antibody_pack::SealedExtractGuard>,
    pack: NativePack,
    signal_pack: Option<Arc<SignalPack>>,
    low: Arc<Evaluator>,
    medium: Arc<Evaluator>,
    high: Arc<Evaluator>,
    cache_dir: Option<PathBuf>,
    /// live 编译用的 EvalPolicy 模板（沙箱复用，避免重装全局 semantic）。
    eval_policy: EvalPolicy,
    /// 候选沙箱：L1 Program 强制 observe；不重装全局 semantic/model。
    sandbox: Option<SandboxSlot>,
}

struct SandboxSlot {
    pack_root: PathBuf,
    pack_id: String,
    pack_version: String,
    /// Medium 档足够做旁路对比。
    medium: Arc<Evaluator>,
}

/// 可热更新的自研检测引擎（线程安全读；写路径用于 reload）。
pub struct Engine {
    inner: RwLock<EngineInner>,
}

impl Engine {
    pub fn load_pack(path: impl AsRef<Path>) -> Result<Self, NativeError> {
        Self::load_pack_with_cache(path, None)
    }

    pub fn load_pack_with_cache(
        path: impl AsRef<Path>,
        cache_dir: Option<PathBuf>,
    ) -> Result<Self, NativeError> {
        let pack_root = path.as_ref().to_path_buf();
        let mut inner = build_inner(pack_root, cache_dir)?;
        if let Ok(p) = std::env::var("NERVE_NATIVE_SANDBOX_PACK") {
            let trimmed = p.trim();
            if !trimmed.is_empty() {
                inner.sandbox = Some(build_sandbox_slot(
                    PathBuf::from(trimmed),
                    inner.eval_policy.clone(),
                    inner.cache_dir.clone(),
                )?);
            }
        }
        Ok(Self {
            inner: RwLock::new(inner),
        })
    }

    pub fn reload(&self, path: Option<&Path>) -> Result<(), NativeError> {
        let mut g = self.inner.write();
        let root = path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| g.pack_root.clone());
        let cache = g.cache_dir.clone();
        let sandbox_root = g.sandbox.as_ref().map(|s| s.pack_root.clone());
        *g = build_inner(root, cache)?;
        if let Some(sb) = sandbox_root {
            g.sandbox = Some(build_sandbox_slot(
                sb,
                g.eval_policy.clone(),
                g.cache_dir.clone(),
            )?);
        } else if let Ok(p) = std::env::var("NERVE_NATIVE_SANDBOX_PACK") {
            let trimmed = p.trim();
            if !trimmed.is_empty() {
                g.sandbox = Some(build_sandbox_slot(
                    PathBuf::from(trimmed),
                    g.eval_policy.clone(),
                    g.cache_dir.clone(),
                )?);
            }
        }
        Ok(())
    }

    /// 挂载候选沙箱 Program（强制 observe，旁路采样；不改 live 响应）。
    pub fn mount_sandbox(&self, path: impl AsRef<Path>) -> Result<(), NativeError> {
        let mut g = self.inner.write();
        let slot = build_sandbox_slot(
            path.as_ref().to_path_buf(),
            g.eval_policy.clone(),
            g.cache_dir.clone(),
        )?;
        g.sandbox = Some(slot);
        Ok(())
    }

    /// 卸载沙箱 Program。
    pub fn unmount_sandbox(&self) {
        self.inner.write().sandbox = None;
    }

    pub fn sandbox_mounted(&self) -> bool {
        self.inner.read().sandbox.is_some()
    }

    pub fn inspect(
        &self,
        req: &NativeRequest,
        level: NativeLevel,
    ) -> Result<Option<NativeHit>, NativeError> {
        self.inspect_pooled(req, level)
    }

    /// 同 [`inspect`]，附带 RIS / Fast / Deep 分段耗时。
    ///
    /// 始终直连执行（不经 inspect 池），保证 per-case 耗时可观测；生产热路径请用 [`inspect`]。
    pub fn inspect_exec(
        &self,
        req: &NativeRequest,
        level: NativeLevel,
    ) -> Result<InspectExec, NativeError> {
        let g = self.inner.read();
        let ev = match level {
            NativeLevel::Low => g.low.clone(),
            NativeLevel::Medium => g.medium.clone(),
            NativeLevel::High => g.high.clone(),
        };
        let plan = ev.plan_inspect(req, PlanCacheHints::default());
        Ok(ev.inspect_plan_exec(req, plan))
    }

    fn inspect_pooled(
        &self,
        req: &NativeRequest,
        level: NativeLevel,
    ) -> Result<Option<NativeHit>, NativeError> {
        let g = self.inner.read();
        let ev = match level {
            NativeLevel::Low => g.low.clone(),
            NativeLevel::Medium => g.medium.clone(),
            NativeLevel::High => g.high.clone(),
        };
        let sandbox_ev = g.sandbox.as_ref().map(|s| s.medium.clone());
        #[cfg(feature = "inspect-trace")]
        let plan = {
            let t0 = std::time::Instant::now();
            let plan = ev.plan_inspect(req, PlanCacheHints::default());
            nerve_inspect_trace::record_native_plan(
                t0.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            );
            nerve_inspect_trace::record_native_path(plan.path.as_str());
            plan
        };
        #[cfg(not(feature = "inspect-trace"))]
        let plan = ev.plan_inspect(req, PlanCacheHints::default());
        let use_pool = pool_enabled()
            && !(plan.inline_fast_lane && plan.path == InspectPath::Fast)
            && !{
                #[cfg(feature = "inspect-trace")]
                {
                    nerve_inspect_trace::tracing_sink_active()
                }
                #[cfg(not(feature = "inspect-trace"))]
                {
                    false
                }
            };
        let hit = if use_pool {
            pool::global().inspect_with_plan(ev.clone(), req.clone(), plan.clone())
        } else {
            ev.inspect_plan(req, plan.clone())
        };
        if plan.path == InspectPath::Fast {
            if let Some(sb) = sandbox_ev {
                shadow_runtime().submit_sandbox_for_ris_zone(
                    plan.ris_zone,
                    sb,
                    req.clone(),
                    hit.as_ref(),
                );
            }
            shadow_runtime().submit_for_ris_zone(
                plan.ris_zone,
                ev,
                req.clone(),
                hit.as_ref(),
            );
        }
        Ok(hit)
    }

    /// Shadow deep 最近采样（FP/FN 闭环入口）。
    pub fn shadow_recent(&self, limit: usize) -> Vec<crate::shadow::ShadowRecord> {
        shadow_runtime().recent(limit)
    }

    pub fn shadow_add_feedback(&self, uri: String, label: String, note: String) {
        shadow_runtime().add_feedback(uri, label, note, None);
    }

    /// 人工标注并可显式附带误报规则 id（优先于 shadow ring 解析）。
    pub fn shadow_add_feedback_with_rule(
        &self,
        uri: String,
        label: String,
        note: String,
        matched_rule_id: Option<String>,
    ) {
        shadow_runtime().add_feedback(uri, label, note, matched_rule_id);
    }

    pub fn shadow_feedback_recent(&self, limit: usize) -> Vec<crate::shadow::ShadowFeedback> {
        shadow_runtime().feedback_recent(limit)
    }

    pub fn shadow_export_rules(&self) -> String {
        shadow_runtime().export_rule_drafts()
    }

    /// 克隆指定强度档 Evaluator，供 bench 等 CPU 密集场景在 blocking 线程池内直接调用。
    pub fn evaluator_for(&self, level: NativeLevel) -> Arc<Evaluator> {
        let g = self.inner.read();
        match level {
            NativeLevel::Low => g.low.clone(),
            NativeLevel::Medium => g.medium.clone(),
            NativeLevel::High => g.high.clone(),
        }
    }

    pub fn pack_version(&self) -> String {
        self.inner.read().pack.version().to_string()
    }

    pub fn pack_id(&self) -> String {
        self.inner.read().pack.id().to_string()
    }

    pub fn health(&self) -> NativeHealth {
        let g = self.inner.read();
        let p = g.pack.policy();
        NativeHealth {
            ready: true,
            pack_id: g.pack.id().into(),
            pack_version: g.pack.version().into(),
            content_hash: g.pack.content_hash.clone(),
            rule_count: g.pack.rules.len(),
            block_threshold: g.pack.block_threshold(),
            threshold_low: p.threshold_for("low"),
            threshold_medium: p.threshold_for("medium"),
            threshold_high: p.threshold_for("high"),
            rules_low: g.low.program().rule_count(),
            rules_medium: g.medium.program().rule_count(),
            rules_high: g.high.program().rule_count(),
            observe_only: g.pack.observe_only(),
            semantic_enabled: p.semantic.enabled,
            signals_enabled: p.signals.enabled,
            adaptive_enabled: p.adaptive.enabled,
            adaptive_contribute: p.adaptive.contribute,
            accel: g.medium.program().accel.clone(),
            pipeline_decode: p.pipeline.decode_enabled,
            pipeline_structural: p.pipeline.structural_enabled,
            pipeline_base64: p.pipeline.base64_expand,
            max_inspect_ms: p.pipeline.max_inspect_ms,
            model_version: adaptive::score(adaptive::AdaptiveInput {
                level: NativeLevel::Medium,
                features: &adaptive::FeatureSnapshot::default(),
                contribute: false,
                level_weight: p.levels.medium.adaptive_level_weight,
                score_cap: p.levels.medium.adaptive_score_cap,
            })
            .version,
            inspect_mode: p.inspect.mode.clone(),
            fast_max_inspect_ms: p.inspect.fast_max_inspect_ms,
            semantic_pack_path: p.semantic.pack_path.clone(),
            semantic_pack_version: semantic::loaded_semantic_pack().map(|sp| sp.version),
            semantic_signature_count: semantic::loaded_semantic_pack()
                .map(|sp| sp.signature_count())
                .unwrap_or(0),
            signals_pack_path: p.signals.pack_path.clone(),
            signals_pack_version: g.signal_pack.as_ref().map(|sp| sp.version.clone()),
            signals_feature_count: g
                .signal_pack
                .as_ref()
                .map(|sp| sp.features.len())
                .unwrap_or(0),
            signals_fingerprint_count: g
                .signal_pack
                .as_ref()
                .map(|sp| sp.fingerprints.len())
                .unwrap_or(0),
            sandbox_mounted: g.sandbox.is_some(),
            sandbox_pack_id: g.sandbox.as_ref().map(|s| s.pack_id.clone()),
            sandbox_pack_version: g.sandbox.as_ref().map(|s| s.pack_version.clone()),
            sandbox_sample_bps: shadow_runtime().sandbox_sample_bps(),
        }
    }

    /// Prometheus 文本指标（runtime 热路径计数）。
    pub fn metrics_prometheus(&self) -> String {
        nerve_antibody_metrics::global().render_prometheus()
    }

    /// JSON 指标快照。
    pub fn metrics_snapshot(&self) -> nerve_antibody_metrics::MetricsSnapshot {
        nerve_antibody_metrics::global().snapshot()
    }

    /// 在线 License 状态（sealed pack 生产路径）。
    pub fn license_status(&self) -> nerve_antibody_license::LicenseStatus {
        nerve_antibody_license::license_status()
    }
}

fn build_inner(pack_root: PathBuf, cache_dir: Option<PathBuf>) -> Result<EngineInner, NativeError> {
    let loaded = NativePack::load_auto(&pack_root)?;
    let guard = loaded.guard;
    let pack = loaded.pack;
    let effective_root = guard
        .as_ref()
        .map(|g| g.root.clone())
        .unwrap_or_else(|| pack_root.clone());
    let policy = pack.policy().clone();

    let model_path = policy.adaptive.model_path.as_ref().map(|p| {
        let pb = PathBuf::from(p);
        if pb.is_absolute() {
            pb
        } else {
            effective_root.join(pb)
        }
    });
    adaptive::install_model(load_model(model_path.as_deref()));

    let semantic_path = policy.semantic.pack_path.as_ref().map(|p| {
        let pb = PathBuf::from(p);
        if pb.is_absolute() {
            pb
        } else {
            effective_root.join(pb)
        }
    });
    if policy.semantic.enabled {
        install_semantic_pack(semantic_path.as_deref()).map_err(NativeError::Msg)?;
    } else {
        install_semantic_pack(None).map_err(NativeError::Msg)?;
    }

    let signal_pack = load_engine_signal_pack(&effective_root, &policy.signals)?;

    let mut pipeline = PipelineConfig {
        decode_enabled: policy.pipeline.decode_enabled,
        base64_expand: policy.pipeline.base64_expand,
        structural_enabled: policy.pipeline.structural_enabled,
        max_decode_blobs: policy.pipeline.max_decode_blobs,
        max_blob_chars: policy.pipeline.max_blob_chars,
        max_field_chars: policy.pipeline.max_field_chars,
        max_params: policy.pipeline.max_params,
        max_decode_depth: policy.pipeline.max_decode_depth,
        max_inspect_ms: policy.pipeline.max_inspect_ms,
        max_regex_evals: policy.pipeline.max_regex_evals,
        max_view_slices: 0,
        by_level: map_budget_by_level(&policy.levels, &policy.pipeline.by_level),
        abs_max_inspect_ms: policy.pipeline.abs_max_inspect_ms,
        abs_max_regex_evals: policy.pipeline.abs_max_regex_evals,
        route_preview: map_route_preview(&policy.pipeline.route_preview),
        fast_path: map_fast_path(&policy.pipeline.fast_path),
        edge: map_edge(&policy.pipeline.edge),
        adaptive_level_weight: None,
        adaptive_score_cap: None,
    };
    pipeline.apply_abs_caps();
    let mut eval_policy = EvalPolicy {
        semantic_enabled: policy.semantic.enabled,
        adaptive_enabled: policy.adaptive.enabled,
        adaptive_contribute: policy.adaptive.contribute,
        pipeline: pipeline.clone(),
        inspect_mode: policy.inspect.mode.clone(),
        fast_max_inspect_ms: policy.inspect.fast_max_inspect_ms,
        route_gate: load_route_gate_config(&effective_root, &policy.inspect.route_gate),
        fusion_min_independent: policy.fusion.min_independent_signals,
        lazy_decode: policy.pipeline.lazy_decode,
        signal_pack: signal_pack.clone(),
        deep_view_cache: None,
        ris_l1: Some(std::sync::Arc::new(RisL1CacheProbe::new(global_verdict_cache()))),
    };
    apply_runtime_env_overrides(&mut pipeline, &mut eval_policy);
    eval_policy.pipeline = pipeline.clone();
    let observe = pack.observe_only();

    let low = compile_level(
        &pack,
        NativeLevel::Low,
        policy.threshold_for("low"),
        &cache_dir,
        observe,
        eval_policy.clone(),
    )?;
    let medium = compile_level(
        &pack,
        NativeLevel::Medium,
        policy.threshold_for("medium"),
        &cache_dir,
        observe,
        eval_policy.clone(),
    )?;
    let high = compile_level(
        &pack,
        NativeLevel::High,
        policy.threshold_for("high"),
        &cache_dir,
        observe,
        eval_policy.clone(),
    )?;

    Ok(EngineInner {
        pack_root,
        _sealed_guard: guard,
        pack,
        signal_pack,
        low,
        medium,
        high,
        cache_dir,
        eval_policy,
        sandbox: None,
    })
}

/// 加载候选沙箱：只编译 L1 Program 并强制 observe_only；复用 live 的 EvalPolicy（不重装全局 semantic）。
fn build_sandbox_slot(
    pack_root: PathBuf,
    eval_policy: EvalPolicy,
    cache_dir: Option<PathBuf>,
) -> Result<SandboxSlot, NativeError> {
    let loaded = NativePack::load_auto(&pack_root)?;
    let pack = loaded.pack;
    let threshold = pack.policy().threshold_for("medium");
    let medium = compile_level(
        &pack,
        NativeLevel::Medium,
        threshold,
        &cache_dir,
        true, // 沙箱拦截许可恒为 0
        eval_policy,
    )?;
    Ok(SandboxSlot {
        pack_root,
        pack_id: pack.id().into(),
        pack_version: pack.version().into(),
        medium,
    })
}

/// 解析并加载声明式信号包；disabled 时返回 None。
fn load_engine_signal_pack(
    effective_root: &Path,
    policy: &nerve_antibody_pack::SignalsPolicy,
) -> Result<Option<Arc<SignalPack>>, NativeError> {
    if !policy.enabled {
        return Ok(None);
    }
    let path = resolve_signal_pack_path(effective_root, policy.pack_path.as_deref());
    match path {
        Some(p) if p.is_file() => {
            let pack = load_signal_pack(Some(&p)).map_err(NativeError::Msg)?;
            Ok(Some(Arc::new(pack)))
        }
        Some(p) if policy.pack_path.is_some() => Err(NativeError::Msg(format!(
            "signal pack not found: {}",
            p.display()
        ))),
        _ => Ok(None),
    }
}

fn resolve_signal_pack_path(effective_root: &Path, pack_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = pack_path {
        let pb = PathBuf::from(p);
        return Some(if pb.is_absolute() {
            pb
        } else {
            effective_root.join(pb)
        });
    }
    let candidates = [
        effective_root.join("signals/signals.yaml"),
        effective_root.join("signals.yaml"),
    ];
    candidates.into_iter().find(|c| c.is_file())
}

fn compile_level(
    pack: &NativePack,
    level: NativeLevel,
    threshold: u32,
    cache_dir: &Option<PathBuf>,
    observe_only: bool,
    eval_policy: EvalPolicy,
) -> Result<Arc<Evaluator>, NativeError> {
    let opts = CompileOptions {
        pack_id: pack.id().into(),
        pack_version: pack.version().into(),
        block_threshold: threshold,
    };
    let prog = if let Some(dir) = cache_dir {
        // 缓存键含 pack + engine artifact format，避免跨 format 误用旧 IR。
        let path = dir.join(format!(
            "{}-{}-{}-f{}.json",
            pack.id(),
            pack.version(),
            level.as_str(),
            ProgramArtifact::FORMAT
        ));
        let cached = path.is_file().then(|| ProgramArtifact::load(&path)).and_then(|r| {
            r.ok().filter(|a| {
                a.pack_version == pack.version() && ProgramArtifact::format_compatible(a.format)
            })
        });
        match cached.and_then(|a| nerve_antibody_compiler::Program::from_artifact(a).ok()) {
            Some(mut p) => {
                // 缓存可能带旧阈值；以当前策略覆盖
                p.block_threshold = threshold;
                p
            }
            None => {
                let p = compile(&pack.rules, level, &opts)?;
                let _ = p.to_artifact().save(&path);
                p
            }
        }
    } else {
        compile(&pack.rules, level, &opts)?
    };
    Ok(Arc::new(
        Evaluator::from_program(prog)
            .with_observe_only(observe_only)
            .with_policy(eval_policy),
    ))
}

fn load_route_gate_config(
    pack_root: &Path,
    rg: &nerve_antibody_pack::RouteGatePolicy,
) -> RouteGateConfig {
    let mut weights = if let Some(ref p) = rg.weights_path {
        let pb = PathBuf::from(p);
        let path = if pb.is_absolute() {
            pb
        } else {
            pack_root.join(pb)
        };
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| RouteGateWeights::from_json(&t).ok())
            .unwrap_or_else(RouteGateWeights::builtin)
    } else {
        RouteGateWeights::builtin()
    };
    weights.bias = rg.bias;
    weights.apply_named_overrides(&rg.weights);
    RouteGateConfig {
        enabled: rg.enabled,
        deep_threshold: rg.deep_threshold,
        gray_threshold: rg.gray_threshold.min(rg.deep_threshold),
        hard_decode_hint: rg.hard_decode_hint,
        weights,
    }
}
