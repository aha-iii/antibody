//! 有界递归解码：URL / HTML / JS / Base64 迭代展开，带去环与预算。

use crate::views::{DecodeChain, RequestViews, ViewKind, ViewSlice};
use nerve_antibody_dsl::{apply_transforms, Transform};
use nerve_waf_canonical::{canonical_shallow, text_may_contain_b64_payload};
use std::collections::HashSet;

use super::base64_expand::expand_base64_candidates;
use super::{DecodeMode, DecodeOptions};

const NORMALIZE_TRANSFORMS: &[Transform] = &[
    Transform::UrlDecodeUni,
    Transform::HtmlEntityDecode,
    Transform::HtmlNumericDecode,
    Transform::JsUnescape,
    Transform::StripNull,
    Transform::Lowercase,
];

/// Stage-0 浅层视图：Raw + 单层 URL + lowercase。
pub fn expand_text_shallow(views: &mut RequestViews, path: &str, raw: &str, max_view_slices: u32) {
    if raw.is_empty() {
        return;
    }
    push_slice_limited(
        views,
        ViewSlice {
            kind: ViewKind::Raw,
            path: path.into(),
            text: raw.into(),
            decode_chain: DecodeChain::new(["raw"]),
        },
        max_view_slices,
    );
    let norm = canonical_shallow(raw);
    if norm != raw {
        push_slice_limited(
            views,
            ViewSlice {
                kind: ViewKind::Normalized,
                path: path.into(),
                text: norm,
                decode_chain: DecodeChain::new(["raw", "url_decode_uni", "lowercase"]),
            },
            max_view_slices,
        );
    }
}

/// 单层解码展开（lazy decode 树：在已有 views 上追加一层归一化 / b64）。
pub fn expand_one_layer(views: &mut RequestViews, path: &str, raw: &str, opts: &DecodeOptions) {
    if raw.is_empty() || !opts.enabled {
        return;
    }
    let mut shallow = opts.clone();
    shallow.max_decode_depth = 1;
    shallow.max_blobs = opts.max_blobs.min(4);
    shallow.mode = DecodeMode::Full;
    expand_text_recursive(views, path, raw, &shallow);
}

/// 对路径文本做 raw + 有界递归归一化 / base64 展开。
pub fn expand_text_recursive(
    views: &mut RequestViews,
    path: &str,
    raw: &str,
    opts: &DecodeOptions,
) {
    if raw.is_empty() {
        return;
    }

    push_slice_limited(
        views,
        ViewSlice {
            kind: ViewKind::Raw,
            path: path.into(),
            text: raw.into(),
            decode_chain: DecodeChain::new(["raw"]),
        },
        opts.max_view_slices,
    );

    if !opts.enabled {
        return;
    }

    let max_depth = opts.max_decode_depth.max(1);
    let mut seen: HashSet<u64> = HashSet::new();
    seen.insert(fnv1a64(raw.as_bytes()));

    let mut queue: Vec<(String, Vec<String>, u8, usize)> = Vec::new();
    queue.push((raw.to_string(), vec!["raw".into()], 0, 0));

    let mut blobs_used = 0usize;
    let mut generated = 0usize;
    const MAX_GENERATED: usize = 96;

    while let Some((text, chain, depth, seed)) = queue.pop() {
        if depth >= max_depth || generated >= MAX_GENERATED {
            continue;
        }
        if view_limit_reached(views, opts.max_view_slices) {
            break;
        }

        let norm = apply_transforms(&text, NORMALIZE_TRANSFORMS);
        if push_if_new(
            views,
            &mut seen,
            &norm,
            path,
            ViewKind::Normalized,
            {
                let mut c = chain.clone();
                c.extend(
                    [
                        "url_decode_uni",
                        "html_entity_decode",
                        "html_numeric_decode",
                        "js_unescape",
                        "strip_null",
                        "lowercase",
                    ]
                    .map(String::from),
                );
                c
            },
            &mut generated,
            opts.max_view_slices,
        ) {
            let mut next_chain = chain.clone();
            next_chain.push("normalize".into());
            queue.push((norm.clone(), next_chain, depth + 1, seed));
        }

        let url_once = apply_transforms(&text, &[Transform::UrlDecodeUni]);
        if url_once != text && url_once != norm {
            if push_if_new(
                views,
                &mut seen,
                &url_once,
                path,
                ViewKind::Normalized,
                {
                    let mut c = chain.clone();
                    c.push("url_decode_uni".into());
                    c
                },
                &mut generated,
                opts.max_view_slices,
            ) {
                let mut next_chain = chain.clone();
                next_chain.push("url_decode_uni".into());
                queue.push((url_once, next_chain, depth + 1, seed));
            }
        }

        if !opts.base64_expand
            || blobs_used >= opts.max_blobs
            || !text_may_contain_b64_payload(&text)
        {
            continue;
        }

        let remain = opts.max_blobs.saturating_sub(blobs_used);
        let take = remain.min(4);
        let candidates = expand_base64_candidates(&text, take, opts.max_blob_chars);
        for (i, blob) in candidates.into_iter().enumerate() {
            if blobs_used >= opts.max_blobs || generated >= MAX_GENERATED {
                break;
            }
            if view_limit_reached(views, opts.max_view_slices) {
                break;
            }
            blobs_used += 1;
            let decoded = apply_transforms(&blob, NORMALIZE_TRANSFORMS);
            let idx = seed.saturating_add(i).saturating_add(blobs_used);
            let blob_path = format!("{path}#b64[{idx}]");
            let mut blob_chain = chain.clone();
            blob_chain.push("base64_decode".into());
            blob_chain.extend(
                [
                    "url_decode_uni",
                    "html_entity_decode",
                    "html_numeric_decode",
                    "js_unescape",
                    "strip_null",
                    "lowercase",
                ]
                .map(String::from),
            );
            if push_if_new(
                views,
                &mut seen,
                &decoded,
                &blob_path,
                ViewKind::DecodedBlob,
                blob_chain.clone(),
                &mut generated,
                opts.max_view_slices,
            ) {
                queue.push((decoded, blob_chain, depth + 1, idx));
            }
        }
    }
}

fn view_limit_reached(views: &RequestViews, max_view_slices: u32) -> bool {
    max_view_slices > 0 && views.slices.len() as u32 >= max_view_slices
}

fn push_slice_limited(views: &mut RequestViews, slice: ViewSlice, max_view_slices: u32) {
    if view_limit_reached(views, max_view_slices) {
        return;
    }
    views.push_slice(slice);
}

fn push_if_new(
    views: &mut RequestViews,
    seen: &mut HashSet<u64>,
    text: &str,
    path: &str,
    kind: ViewKind,
    chain: Vec<String>,
    generated: &mut usize,
    max_view_slices: u32,
) -> bool {
    if text.is_empty() || view_limit_reached(views, max_view_slices) {
        return false;
    }
    let h = fnv1a64(text.as_bytes());
    if !seen.insert(h) {
        return false;
    }
    views.push_slice(ViewSlice {
        kind,
        path: path.into(),
        text: text.into(),
        decode_chain: DecodeChain { steps: chain },
    });
    *generated += 1;
    true
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{DecodeMode, DecodeOptions};

    #[test]
    fn shallow_skips_b64_and_deep_normalize() {
        let mut views = RequestViews::default();
        expand_text_shallow(&mut views, "body", "PGlmcmFtZQ==", 0);
        assert!(views.slices.iter().any(|s| s.kind == ViewKind::Raw));
        assert!(
            !views.slices.iter().any(|s| s.kind == ViewKind::DecodedBlob),
            "shallow must not b64-expand"
        );
    }

    #[test]
    fn double_url_and_b64_nested() {
        let mut views = RequestViews::default();
        let opts = DecodeOptions {
            enabled: true,
            base64_expand: true,
            max_blobs: 16,
            max_blob_chars: 4096,
            max_decode_depth: 4,
            mode: DecodeMode::Full,
            max_view_slices: 0,
        };
        expand_text_recursive(&mut views, "query", "q=%253Cscript%253E", &opts);
        let hay: String = views.slices.iter().map(|s| s.text.as_str()).collect();
        assert!(
            hay.to_ascii_lowercase().contains("<script")
                || hay.to_ascii_lowercase().contains("%3cscript"),
            "expected nested url decode, got {hay}"
        );
    }
}
