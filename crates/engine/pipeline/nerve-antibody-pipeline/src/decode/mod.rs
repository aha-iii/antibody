//! 解码管线：有界递归归一化 + base64 候选展开。

mod base64_expand;
mod recursive;

use crate::views::{DecodeChain, RequestViews, ViewKind, ViewSlice};
use nerve_antibody_dsl::{apply_transforms, Transform};
use nerve_waf_canonical::canonical_shallow;
use recursive::{expand_text_recursive, expand_text_shallow};

pub use base64_expand::expand_base64_candidates;
pub use recursive::expand_one_layer;

/// 解码深度模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecodeMode {
    /// Stage-0：Raw + 单层 URL + lowercase，无 b64/递归。
    Shallow,
    /// Stage-1/2：完整递归 + 按需 b64。
    #[default]
    Full,
}

/// 解码选项。
#[derive(Debug, Clone)]
pub struct DecodeOptions {
    pub enabled: bool,
    pub base64_expand: bool,
    pub max_blobs: usize,
    pub max_blob_chars: usize,
    /// 递归解码最大深度（含归一化 / 再展开）。
    pub max_decode_depth: u8,
    pub mode: DecodeMode,
    /// 视图 slice 数上限；0 = 不限制。
    pub max_view_slices: u32,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            base64_expand: true,
            max_blobs: 32,
            max_blob_chars: 8192,
            max_decode_depth: 4,
            mode: DecodeMode::Full,
            max_view_slices: 0,
        }
    }
}

impl DecodeOptions {
    pub fn shallow() -> Self {
        Self {
            enabled: true,
            base64_expand: false,
            max_blobs: 0,
            max_decode_depth: 1,
            mode: DecodeMode::Shallow,
            ..Self::default()
        }
    }

    pub fn for_lazy_increment(&self) -> Self {
        Self {
            mode: DecodeMode::Full,
            base64_expand: self.base64_expand,
            ..self.clone()
        }
    }
}

/// 引擎级解码管线。
pub struct DecodePipeline;

impl DecodePipeline {
    /// 从原始字段构建多视图。
    pub fn build(
        uri: &str,
        query: &str,
        body: &str,
        response_body: Option<&str>,
        opts: &DecodeOptions,
    ) -> RequestViews {
        let mut views = RequestViews::default();
        if !opts.enabled {
            for (path, text) in [("uri", uri), ("query", query), ("body", body)] {
                views.push_slice(ViewSlice {
                    kind: ViewKind::Raw,
                    path: path.into(),
                    text: text.into(),
                    decode_chain: DecodeChain::new(["raw"]),
                });
            }
            if let Some(rb) = response_body {
                views.push_slice(ViewSlice {
                    kind: ViewKind::Raw,
                    path: "response_body".into(),
                    text: rb.into(),
                    decode_chain: DecodeChain::new(["raw"]),
                });
            }
            return views;
        }

        Self::add_text(&mut views, "uri", uri, opts);
        Self::add_text(&mut views, "query", query, opts);
        Self::add_text(&mut views, "body", body, opts);
        if let Some(rb) = response_body {
            Self::add_text(&mut views, "response_body", rb, opts);
        }
        views
    }

    /// 对任意路径文本做 raw / 递归归一化 / base64 展开（供侧信道复用）。
    pub fn add_text(views: &mut RequestViews, path: &str, raw: &str, opts: &DecodeOptions) {
        if opts.mode == DecodeMode::Shallow {
            expand_text_shallow(views, path, raw, opts.max_view_slices);
            return;
        }
        expand_text_recursive(views, path, raw, opts);
    }

    /// 对已拆出的参数值做归一化与 base64 展开。
    pub fn expand_params(views: &mut RequestViews, opts: &DecodeOptions) {
        let params = views.params.clone();
        for p in params {
            views.push_slice(ViewSlice {
                kind: ViewKind::Param,
                path: p.path.clone(),
                text: p.value.clone(),
                decode_chain: DecodeChain::new([format!("structural:{}", p.source)]),
            });
            if !opts.enabled {
                continue;
            }
            if opts.mode == DecodeMode::Shallow {
                let norm = canonical_shallow(&p.value);
                views.push_slice(ViewSlice {
                    kind: ViewKind::ParamDecoded,
                    path: p.path.clone(),
                    text: norm,
                    decode_chain: DecodeChain::new([
                        format!("structural:{}", p.source),
                        "url_decode_uni".into(),
                        "lowercase".into(),
                    ]),
                });
                continue;
            }

            let mut param_opts = opts.clone();
            param_opts.max_decode_depth = opts.max_decode_depth.min(3);
            param_opts.max_blobs = opts.max_blobs.min(8);
            expand_text_recursive(views, &p.path, &p.value, &param_opts);

            let norm = apply_transforms(
                &p.value,
                &[
                    Transform::UrlDecodeUni,
                    Transform::HtmlEntityDecode,
                    Transform::Lowercase,
                ],
            );
            views.push_slice(ViewSlice {
                kind: ViewKind::ParamDecoded,
                path: p.path.clone(),
                text: norm,
                decode_chain: DecodeChain::new([
                    format!("structural:{}", p.source),
                    "url_decode_uni".into(),
                    "html_entity_decode".into(),
                    "lowercase".into(),
                ]),
            });

            if opts.base64_expand && nerve_waf_canonical::text_may_contain_b64_payload(&p.value) {
                for (i, blob) in expand_base64_candidates(&p.value, 4, opts.max_blob_chars)
                    .into_iter()
                    .enumerate()
                {
                    let t = apply_transforms(
                        &blob,
                        &[
                            Transform::UrlDecodeUni,
                            Transform::HtmlEntityDecode,
                            Transform::HtmlNumericDecode,
                            Transform::JsUnescape,
                            Transform::Lowercase,
                        ],
                    );
                    views.push_slice(ViewSlice {
                        kind: ViewKind::DecodedBlob,
                        path: format!("{}#b64[{i}]", p.path),
                        text: t,
                        decode_chain: DecodeChain::new([
                            format!("structural:{}", p.source),
                            "base64_decode".into(),
                            "url_decode_uni".into(),
                            "html_entity_decode".into(),
                            "html_numeric_decode".into(),
                            "js_unescape".into(),
                            "lowercase".into(),
                        ]),
                    });
                }
            }
        }
    }
}
