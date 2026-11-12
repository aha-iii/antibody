//! # nerve-antibody-pipeline
//!
//! 引擎级管线层（与规则 DSL 解耦）：
//!
//! 1. **DecodePipeline** — 标准归一化 + base64 候选展开 → 多视图  
//! 2. **Structural** — form / JSON / multipart / XML(SOAP) 拆参  
//! 3. **Budget** — inspect 时间/步数熔断  
//!
//! Runtime 在规则匹配前消费 [`RequestViews`]。

mod budget;
mod decode;
mod sidechannel;
mod structural;
mod text_plausibility;
mod views;

pub use budget::{BudgetExhausted, InspectBudget};
pub use decode::{
    expand_base64_candidates, expand_one_layer, DecodeMode, DecodeOptions, DecodePipeline,
};
pub use sidechannel::expand_sidechannel_headers;
pub use structural::{StructuralOptions, StructuralParser};
pub use text_plausibility::{
    is_plausible_b64_candidate, is_plausible_decoded_text, is_plausible_inspect_text,
};
pub use views::{DecodeChain, ParamUnit, RequestViews, ViewKind, ViewSlice};

use nerve_antibody_dsl::NativeLevel;

/// 单档覆盖（`None` = 继承基值；预算维 `Some(0)` = 该维不限制）。
#[derive(Debug, Clone, Default)]
pub struct LevelBudgetOverride {
    pub max_inspect_ms: Option<u64>,
    pub max_regex_evals: Option<u32>,
    pub max_decode_blobs: Option<usize>,
    pub max_decode_depth: Option<u8>,
    pub max_blob_chars: Option<usize>,
    pub max_field_chars: Option<usize>,
    pub max_params: Option<usize>,
    pub base64_expand: Option<bool>,
    pub decode_enabled: Option<bool>,
    pub structural_enabled: Option<bool>,
    pub adaptive_level_weight: Option<f32>,
    pub adaptive_score_cap: Option<u32>,
}

/// 按防护档覆盖。
#[derive(Debug, Clone, Default)]
pub struct BudgetByLevel {
    pub low: LevelBudgetOverride,
    pub medium: LevelBudgetOverride,
    pub high: LevelBudgetOverride,
}

/// 路由预览浅解码上限（来自 pack）。
#[derive(Debug, Clone)]
pub struct RoutePreviewConfig {
    pub max_decode_blobs: usize,
    pub max_blob_chars: usize,
    pub max_field_chars: usize,
    pub max_decode_depth: u8,
    pub max_params: usize,
}

impl Default for RoutePreviewConfig {
    fn default() -> Self {
        Self {
            max_decode_blobs: 8,
            max_blob_chars: 4096,
            max_field_chars: 8192,
            max_decode_depth: 2,
            max_params: 64,
        }
    }
}

/// 快路径开关（来自 pack）。
#[derive(Debug, Clone, Default)]
pub struct FastPathConfig {
    pub decode_enabled: bool,
    pub base64_expand: bool,
    pub structural_enabled: bool,
    pub max_decode_blobs: usize,
    pub max_decode_depth: u8,
}

/// 边缘内联收紧默认（来自 pack；可被 env 覆盖）。
#[derive(Debug, Clone)]
pub struct EdgePipelineConfig {
    pub max_inspect_ms: u64,
    pub max_regex_evals: u32,
}

impl Default for EdgePipelineConfig {
    fn default() -> Self {
        Self {
            max_inspect_ms: 300,
            max_regex_evals: 20_000,
        }
    }
}

/// 管线总开关（来自 pack.toml `[policy.pipeline]` + `[policy.levels]`）。
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub decode_enabled: bool,
    pub base64_expand: bool,
    pub structural_enabled: bool,
    pub max_decode_blobs: usize,
    pub max_blob_chars: usize,
    /// 规则字段求值（uri/query/body 等）head-tail 截断上限；深路径与快路径共用。
    pub max_field_chars: usize,
    pub max_params: usize,
    /// 递归解码深度。
    pub max_decode_depth: u8,
    /// 基值；`0` = 不限制。分档覆盖见 [`Self::by_level`]。
    pub max_inspect_ms: u64,
    pub max_regex_evals: u32,
    /// 视图 slice 数上限；0 = 不限制。
    pub max_view_slices: u32,
    /// 按档覆盖（来自 pack；引擎不写死启发式）。
    pub by_level: BudgetByLevel,
    /// 安全硬顶；`0` = 不设硬顶。
    pub abs_max_inspect_ms: u64,
    pub abs_max_regex_evals: u32,
    pub route_preview: RoutePreviewConfig,
    pub fast_path: FastPathConfig,
    pub edge: EdgePipelineConfig,
    /// `for_level` 应用后写入，供自适应读取。
    pub adaptive_level_weight: Option<f32>,
    pub adaptive_score_cap: Option<u32>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            decode_enabled: true,
            base64_expand: true,
            structural_enabled: true,
            max_decode_blobs: 32,
            max_blob_chars: 8192,
            max_field_chars: 65536,
            max_params: 256,
            max_decode_depth: 4,
            max_inspect_ms: 80,
            max_regex_evals: 4000,
            max_view_slices: 0,
            by_level: BudgetByLevel::default(),
            abs_max_inspect_ms: 60_000,
            abs_max_regex_evals: 500_000,
            route_preview: RoutePreviewConfig::default(),
            fast_path: FastPathConfig::default(),
            edge: EdgePipelineConfig::default(),
            adaptive_level_weight: None,
            adaptive_score_cap: None,
        }
    }
}

impl PipelineConfig {
    fn level_budget(&self, level: NativeLevel) -> &LevelBudgetOverride {
        match level {
            NativeLevel::Low => &self.by_level.low,
            NativeLevel::Medium => &self.by_level.medium,
            NativeLevel::High => &self.by_level.high,
        }
    }

    /// 应用安全硬顶（pack / 环境可配；`abs_*=0` 表示不封顶）。
    pub fn apply_abs_caps(&mut self) {
        if self.abs_max_inspect_ms > 0 && self.max_inspect_ms > 0 {
            self.max_inspect_ms = self.max_inspect_ms.min(self.abs_max_inspect_ms);
        }
        if self.abs_max_regex_evals > 0 && self.max_regex_evals > 0 {
            self.max_regex_evals = self.max_regex_evals.min(self.abs_max_regex_evals);
        }
    }

    /// 按强度档应用 **配置文件** 覆盖（禁止硬编码 min/max 启发式）。
    pub fn for_level(&self, level: NativeLevel) -> Self {
        let mut c = self.clone();
        let ov = self.level_budget(level);
        if let Some(v) = ov.decode_enabled {
            c.decode_enabled = v;
        }
        if let Some(v) = ov.base64_expand {
            c.base64_expand = v;
        }
        if let Some(v) = ov.structural_enabled {
            c.structural_enabled = v;
        }
        if let Some(v) = ov.max_decode_blobs {
            c.max_decode_blobs = v;
        }
        if let Some(v) = ov.max_decode_depth {
            c.max_decode_depth = v;
        }
        if let Some(v) = ov.max_blob_chars {
            c.max_blob_chars = v;
        }
        if let Some(v) = ov.max_field_chars {
            c.max_field_chars = v;
        }
        if let Some(v) = ov.max_params {
            c.max_params = v;
        }
        if let Some(ms) = ov.max_inspect_ms {
            c.max_inspect_ms = ms;
        }
        if let Some(n) = ov.max_regex_evals {
            c.max_regex_evals = n;
        }
        c.adaptive_level_weight = ov.adaptive_level_weight;
        c.adaptive_score_cap = ov.adaptive_score_cap;
        c.apply_abs_caps();
        c
    }

    /// 路由预览：使用 `[policy.pipeline.route_preview]`。
    pub fn for_route_preview(&self) -> Self {
        let mut c = self.clone();
        let rp = &self.route_preview;
        c.max_decode_blobs = rp.max_decode_blobs;
        c.max_blob_chars = rp.max_blob_chars;
        c.max_field_chars = rp.max_field_chars;
        c.max_decode_depth = rp.max_decode_depth;
        c.max_params = rp.max_params;
        c
    }

    /// 快路径：使用 `[policy.pipeline.fast_path]`。
    pub fn for_fast_path(&self) -> Self {
        let mut c = self.clone();
        let fp = &self.fast_path;
        c.decode_enabled = fp.decode_enabled;
        c.base64_expand = fp.base64_expand;
        c.structural_enabled = fp.structural_enabled;
        c.max_decode_blobs = fp.max_decode_blobs;
        c.max_decode_depth = fp.max_decode_depth;
        c
    }
}

/// 对请求执行完整管线，产出可匹配视图。
#[allow(clippy::too_many_arguments)]
pub fn build_views(
    method: &str,
    uri: &str,
    query: &str,
    body: &str,
    headers: &[(String, String)],
    content_type: Option<&str>,
    response_body: Option<&str>,
    cfg: &PipelineConfig,
) -> RequestViews {
    let dec_opts = DecodeOptions {
        enabled: cfg.decode_enabled,
        base64_expand: cfg.base64_expand,
        max_blobs: cfg.max_decode_blobs,
        max_blob_chars: cfg.max_blob_chars,
        max_decode_depth: cfg.max_decode_depth,
        mode: DecodeMode::Full,
        max_view_slices: cfg.max_view_slices,
    };
    let mut views = DecodePipeline::build(uri, query, body, response_body, &dec_opts);

    if cfg.structural_enabled {
        let st = StructuralOptions {
            max_params: cfg.max_params,
        };
        let params = StructuralParser::extract(method, uri, query, body, content_type, &st);
        views.params = params;
        if cfg.decode_enabled {
            DecodePipeline::expand_params(&mut views, &dec_opts);
        }
    }

    // Referer / Cookie / UA / 可注入头侧信道
    expand_sidechannel_headers(&mut views, headers, &dec_opts);
    views
}

/// 路由预览用 build_views（与 [`PipelineConfig::for_route_preview`] 配合）。
#[allow(clippy::too_many_arguments)]
pub fn build_views_unbudgeted(
    method: &str,
    uri: &str,
    query: &str,
    body: &str,
    headers: &[(String, String)],
    content_type: Option<&str>,
    response_body: Option<&str>,
    cfg: &PipelineConfig,
) -> RequestViews {
    build_views(
        method,
        uri,
        query,
        body,
        headers,
        content_type,
        response_body,
        cfg,
    )
}

/// 浅层 decode 首屏视图（Stage-0：Raw + 单层 URL + lowercase）；预算耗尽时返回 `None`。
#[allow(clippy::too_many_arguments)]
pub fn build_views_shallow(
    method: &str,
    uri: &str,
    query: &str,
    body: &str,
    headers: &[(String, String)],
    content_type: Option<&str>,
    response_body: Option<&str>,
    cfg: &PipelineConfig,
    budget: Option<&mut InspectBudget>,
) -> Option<RequestViews> {
    if let Some(b) = budget {
        if b.check_time().is_err() {
            return None;
        }
    }
    let dec_opts = DecodeOptions {
        enabled: cfg.decode_enabled,
        base64_expand: false,
        max_blobs: 0,
        max_blob_chars: cfg.max_blob_chars,
        max_decode_depth: 1,
        mode: DecodeMode::Shallow,
        max_view_slices: cfg.max_view_slices,
    };
    let mut views = DecodePipeline::build(uri, query, body, response_body, &dec_opts);

    if cfg.structural_enabled {
        let st = StructuralOptions {
            max_params: cfg.max_params,
        };
        let params = StructuralParser::extract(method, uri, query, body, content_type, &st);
        views.params = params;
        if cfg.decode_enabled {
            DecodePipeline::expand_params(&mut views, &dec_opts);
        }
    }

    expand_sidechannel_headers(&mut views, headers, &dec_opts);
    Some(views)
}

/// 对所有字段视图再展开一层 decode（lazy 增量路径）。
pub fn expand_all_fields_one_layer(
    views: &mut RequestViews,
    cfg: &PipelineConfig,
    budget: &mut InspectBudget,
) -> Result<(), BudgetExhausted> {
    budget.check_time()?;
    let opts = DecodeOptions {
        enabled: cfg.decode_enabled,
        base64_expand: cfg.base64_expand,
        max_blobs: cfg.max_decode_blobs,
        max_blob_chars: cfg.max_blob_chars,
        max_decode_depth: cfg.max_decode_depth,
        mode: DecodeMode::Full,
        max_view_slices: cfg.max_view_slices,
    };
    let paths: Vec<(String, String)> = views
        .slices
        .iter()
        .map(|s| (s.path.clone(), s.text.clone()))
        .collect();
    for (path, text) in paths {
        expand_one_layer(views, &path, &text, &opts);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::ViewKind;

    #[test]
    fn build_views_expands_b64_and_form() {
        let cfg = PipelineConfig::default();
        // PGlmcmFtZQ== → <iframe
        let views = build_views(
            "POST",
            "/api",
            "q=1",
            "name=PGlmcmFtZQ==&x=1",
            &[],
            Some("application/x-www-form-urlencoded"),
            None,
            &cfg,
        );
        assert!(views.params.iter().any(|p| p.path.contains("name")));
        assert!(views
            .slices
            .iter()
            .any(|s| s.text.to_ascii_lowercase().contains("iframe")));
    }

    #[test]
    fn openapi_sign_query_does_not_expand_as_b64() {
        let cfg = PipelineConfig::default();
        let q = "tenantCode=coretest1&mchOrderNo=M1902534480440528898&tenant=coretest1&appid=1740450354690&reqid=7ffc86be-15e4-4f7f-b15b-dab483793a53&timestamp=1785289955109&sign=05A6E5389357923F02BCC67FAA5036131ECCDC122950646D3A1178FD1F7E5976";
        let views = build_views(
            "POST",
            "/api/auth-center/auth",
            q,
            "",
            &[],
            None,
            None,
            &cfg,
        );
        assert!(
            !views.slices.iter().any(|s| s.kind == ViewKind::DecodedBlob),
            "hex sign / numeric IDs must not produce decoded blobs"
        );
    }

    #[test]
    fn budget_trips_on_view_slices() {
        let mut b = InspectBudget::new(0, 0, 2);
        assert!(b.charge_view_slice(0).is_ok());
        assert!(b.charge_view_slice(1).is_ok());
        assert!(b.charge_view_slice(2).is_err());
    }

    #[test]
    fn budget_trips_on_regex() {
        let mut b = InspectBudget::new(0, 2, 0);
        assert!(b.charge_regex().is_ok());
        assert!(b.charge_regex().is_ok());
        assert!(b.charge_regex().is_err());
    }

    #[test]
    fn shallow_build_views_skips_b64_sidechannel() {
        let cfg = PipelineConfig::default();
        let views = build_views_shallow(
            "GET",
            "/",
            "",
            "",
            &[("X-Nerve-Test".into(), "PGlmcmFtZQ==".into())],
            None,
            None,
            &cfg,
            None,
        )
        .expect("shallow views");
        assert!(
            !views.slices.iter().any(|s| s.kind == ViewKind::DecodedBlob),
            "shallow must not b64-expand sidechannel headers"
        );
    }

    #[test]
    fn referer_sidechannel_in_build_views() {
        let cfg = PipelineConfig::default();
        let views = build_views(
            "GET",
            "/vulnerabilities/xss_r/",
            "name=",
            "",
            &[(
                "Referer".into(),
                "http://h/x?name=%3Cscript%3Ealert(1)%3C/script%3E".into(),
            )],
            None,
            None,
            &cfg,
        );
        assert!(views.slices.iter().any(|s| {
            s.path.starts_with("header.Referer") && s.text.to_ascii_lowercase().contains("<script")
        }));
    }

    #[test]
    fn injectable_headers_sidechannel_in_build_views() {
        let cfg = PipelineConfig::default();
        let views = build_views(
            "GET",
            "/",
            "",
            "",
            &[
                ("User-Agent".into(), "<svg/onload=alert(1)>".into()),
                ("X-Nerve-Test".into(), "PGlmcmFtZQ==".into()),
            ],
            None,
            None,
            &cfg,
        );
        assert!(views.slices.iter().any(|s| {
            s.path.to_ascii_lowercase().contains("user-agent")
                && s.text.to_ascii_lowercase().contains("onload")
        }));
        assert!(views.slices.iter().any(|s| {
            s.path.to_ascii_lowercase().contains("x-nerve-test")
                && s.text.to_ascii_lowercase().contains("iframe")
        }));
    }

    #[test]
    fn for_level_uses_pack_budget_not_hardcoded_clamp() {
        let mut cfg = PipelineConfig {
            max_inspect_ms: 1000,
            ..Default::default()
        };
        cfg.by_level.low.max_inspect_ms = Some(200);
        cfg.by_level.medium.max_inspect_ms = Some(2500);
        cfg.by_level.high.max_inspect_ms = Some(4000);
        cfg.abs_max_inspect_ms = 60_000;

        assert_eq!(cfg.for_level(NativeLevel::Low).max_inspect_ms, 200);
        assert_eq!(cfg.for_level(NativeLevel::Medium).max_inspect_ms, 2500);
        assert_eq!(cfg.for_level(NativeLevel::High).max_inspect_ms, 4000);

        cfg.abs_max_inspect_ms = 3000;
        assert_eq!(cfg.for_level(NativeLevel::High).max_inspect_ms, 3000);
    }

    #[test]
    fn for_level_applies_decode_overrides_from_config_only() {
        let mut cfg = PipelineConfig {
            max_decode_blobs: 32,
            ..Default::default()
        };
        cfg.max_decode_depth = 4;
        cfg.base64_expand = false;
        cfg.by_level.low.max_decode_blobs = Some(12);
        cfg.by_level.low.max_decode_depth = Some(2);
        cfg.by_level.low.base64_expand = Some(true);
        cfg.by_level.low.adaptive_level_weight = Some(0.0);
        cfg.by_level.low.adaptive_score_cap = Some(0);

        let low = cfg.for_level(NativeLevel::Low);
        assert_eq!(low.max_decode_blobs, 12);
        assert_eq!(low.max_decode_depth, 2);
        assert!(low.base64_expand);
        assert_eq!(low.adaptive_level_weight, Some(0.0));
        assert_eq!(low.adaptive_score_cap, Some(0));

        // 未配置分档字段时保持全局基值，不做硬编码 clamp
        let med = cfg.for_level(NativeLevel::Medium);
        assert_eq!(med.max_decode_blobs, 32);
        assert_eq!(med.max_decode_depth, 4);
        assert!(!med.base64_expand);
    }

    #[test]
    fn route_preview_and_fast_path_use_pack_sections() {
        let mut cfg = PipelineConfig::default();
        cfg.route_preview.max_decode_blobs = 5;
        cfg.route_preview.max_decode_depth = 1;
        cfg.fast_path.decode_enabled = true;
        cfg.fast_path.max_decode_blobs = 3;

        let rp = cfg.for_route_preview();
        assert_eq!(rp.max_decode_blobs, 5);
        assert_eq!(rp.max_decode_depth, 1);

        let fp = cfg.for_fast_path();
        assert!(fp.decode_enabled);
        assert_eq!(fp.max_decode_blobs, 3);
    }
}
