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
pub use decode::{expand_base64_candidates, expand_one_layer, DecodeMode, DecodeOptions, DecodePipeline};
pub use sidechannel::expand_sidechannel_headers;
pub use structural::{StructuralOptions, StructuralParser};
pub use text_plausibility::{
    is_plausible_b64_candidate, is_plausible_decoded_text, is_plausible_inspect_text,
};
pub use views::{DecodeChain, ParamUnit, RequestViews, ViewKind, ViewSlice};

use nerve_antibody_dsl::NativeLevel;

/// 管线总开关（来自 pack.toml `[policy.pipeline]`）。
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub decode_enabled: bool,
    /// medium/high 默认开；low 开浅层 base64。
    pub base64_expand: bool,
    pub structural_enabled: bool,
    pub max_decode_blobs: usize,
    pub max_blob_chars: usize,
    /// 规则字段求值（uri/query/body 等）head-tail 截断上限；深路径与快路径共用。
    pub max_field_chars: usize,
    pub max_params: usize,
    /// 递归解码深度。
    pub max_decode_depth: u8,
    /// 0 = 不限制。
    pub max_inspect_ms: u64,
    pub max_regex_evals: u32,
    /// 视图 slice 数上限；0 = 不限制。
    pub max_view_slices: u32,
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
        }
    }
}

impl PipelineConfig {
    /// 按强度档微调（low 浅解码，high 更激进）。
    pub fn for_level(&self, level: NativeLevel) -> Self {
        let mut c = self.clone();
        match level {
            NativeLevel::Low => {
                // low：保留解码能力；勿把 inspect 预算压到无法跑完规则集
                c.base64_expand = true;
                c.max_decode_blobs = c.max_decode_blobs.min(24).max(12);
                c.max_decode_depth = c.max_decode_depth.min(3).max(2);
                if c.max_inspect_ms > 0 {
                    c.max_inspect_ms = c.max_inspect_ms.min(250).max(150);
                }
            }
            NativeLevel::Medium => {
                c.base64_expand = true;
                c.max_decode_blobs = c.max_decode_blobs.max(48);
                c.max_decode_depth = c.max_decode_depth.max(4);
                if c.max_inspect_ms > 0 {
                    c.max_inspect_ms = c.max_inspect_ms.max(300);
                }
            }
            NativeLevel::High => {
                c.base64_expand = true;
                c.max_decode_blobs = c.max_decode_blobs.max(64);
                c.max_decode_depth = c.max_decode_depth.max(6);
                if c.max_inspect_ms > 0 {
                    c.max_inspect_ms = c.max_inspect_ms.clamp(300, 1200);
                }
            }
        }
        c
    }

    /// 路由预览：浅解码，供 Stage-0 门闩使用。
    pub fn for_route_preview(&self) -> Self {
        let mut c = self.clone();
        c.max_decode_blobs = c.max_decode_blobs.min(8);
        c.max_blob_chars = c.max_blob_chars.min(4096);
        c.max_field_chars = c.max_field_chars.min(8192);
        c.max_decode_depth = c.max_decode_depth.min(2);
        c.max_params = c.max_params.min(64);
        c
    }

    /// 快路径：跳过深解码与拆参，干净流量专用。
    pub fn for_fast_path(&self) -> Self {
        let mut c = self.clone();
        c.decode_enabled = false;
        c.base64_expand = false;
        c.structural_enabled = false;
        c.max_decode_blobs = 0;
        c.max_decode_depth = 0;
        c
    }
}

/// 对请求执行完整管线，产出可匹配视图。
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
            s.path.starts_with("header.Referer")
                && s.text.to_ascii_lowercase().contains("<script")
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
}
