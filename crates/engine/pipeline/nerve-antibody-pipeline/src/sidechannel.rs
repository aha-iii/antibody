//! Header 侧信道：Referer / Cookie / UA / 可注入自定义头 → 可匹配视图。

use crate::decode::{DecodeOptions, DecodePipeline};
use crate::views::RequestViews;

/// 将关键 Header 展开进 [`RequestViews`]，供 query/uri/body 规则与语义共用。
pub fn expand_sidechannel_headers(
    views: &mut RequestViews,
    headers: &[(String, String)],
    opts: &DecodeOptions,
) {
    for (k, v) in headers {
        if v.is_empty() {
            continue;
        }
        if k.eq_ignore_ascii_case("referer") || k.eq_ignore_ascii_case("referrer") {
            DecodePipeline::add_text(views, "header.Referer", v, opts);
            if let Some(q) = extract_url_query(v) {
                DecodePipeline::add_text(views, "header.Referer.query", &q, opts);
            }
            if let Some(path) = extract_url_path(v) {
                DecodePipeline::add_text(views, "header.Referer.path", &path, opts);
            }
        } else if k.eq_ignore_ascii_case("cookie") {
            DecodePipeline::add_text(views, "header.Cookie", v, opts);
            for (name, val) in split_cookie_pairs(v).into_iter().take(64) {
                if val.len() >= 3 {
                    DecodePipeline::add_text(
                        views,
                        &format!("header.Cookie.{name}"),
                        &val,
                        opts,
                    );
                }
            }
        } else if k.eq_ignore_ascii_case("user-agent") {
            DecodePipeline::add_text(views, "header.User-Agent", v, opts);
        } else if k.eq_ignore_ascii_case("origin") {
            DecodePipeline::add_text(views, "header.Origin", v, opts);
        } else if k.eq_ignore_ascii_case("host") {
            // Host 内 CRLF / 缓存投毒常见
            DecodePipeline::add_text(views, "header.Host", v, opts);
        } else if k.eq_ignore_ascii_case("authorization") {
            DecodePipeline::add_text(views, "header.Authorization", v, opts);
        } else if k.eq_ignore_ascii_case("x-nerve-test")
            || k.eq_ignore_ascii_case("x-forwarded-for")
            || k.eq_ignore_ascii_case("x-forwarded-host")
            || k.eq_ignore_ascii_case("x-forwarded-proto")
            || k.eq_ignore_ascii_case("x-forwarded-scheme")
            || k.eq_ignore_ascii_case("x-forwarded-port")
            || k.eq_ignore_ascii_case("x-forwarded-prefix")
            || k.eq_ignore_ascii_case("x-real-ip")
            || k.eq_ignore_ascii_case("x-original-url")
            || k.eq_ignore_ascii_case("x-rewrite-url")
            || k.eq_ignore_ascii_case("x-http-method-override")
            || k.eq_ignore_ascii_case("x-method-override")
            || k.eq_ignore_ascii_case("x-host")
            || k.eq_ignore_ascii_case("x-amz-website-redirect-location")
            || k.eq_ignore_ascii_case("x-forwarded-path")
            || k.eq_ignore_ascii_case("x-custom-ip-authorization")
            || k.eq_ignore_ascii_case("x-edge-location")
            || k.eq_ignore_ascii_case("x-account-id")
            || k.eq_ignore_ascii_case("x-tenant-id")
            || k.eq_ignore_ascii_case("x-user-id")
            || k.eq_ignore_ascii_case("x-original-user")
            || k.eq_ignore_ascii_case("x-original-user-id")
            || k.eq_ignore_ascii_case("accept-language")
            || k.eq_ignore_ascii_case("accept-encoding")
            || k.eq_ignore_ascii_case("translate")
        {
            // 可注入自定义头 / 转发头 / 缓存投毒未键控头：解码后对 uri|query|body 规则可见
            DecodePipeline::add_text(views, &format!("header.{k}"), v, opts);
        }
    }
}

fn extract_url_query(url: &str) -> Option<String> {
    let rest = url.split_once('?')?.1;
    let q = rest.split('#').next()?.trim();
    if q.is_empty() {
        None
    } else {
        Some(q.to_string())
    }
}

fn extract_url_path(url: &str) -> Option<String> {
    // http://host/path?x → /path ；或相对 /path?x
    let without_frag = url.split('#').next()?.trim();
    let path_part = if let Some(rest) = without_frag
        .strip_prefix("http://")
        .or_else(|| without_frag.strip_prefix("https://"))
    {
        rest.split_once('/')?.1
    } else if without_frag.starts_with('/') {
        without_frag.trim_start_matches('/')
    } else {
        return None;
    };
    let path = path_part.split('?').next()?.trim();
    if path.is_empty() {
        None
    } else {
        Some(format!("/{path}"))
    }
}

fn split_cookie_pairs(cookie: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in cookie.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((n, v)) = part.split_once('=') {
            out.push((n.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PipelineConfig;

    #[test]
    fn referer_query_becomes_view() {
        let mut views = RequestViews::default();
        let opts = DecodeOptions::default();
        expand_sidechannel_headers(
            &mut views,
            &[(
                "Referer".into(),
                "http://h/vulnerabilities/xss_r/?name=%3Cscript%3E".into(),
            )],
            &opts,
        );
        assert!(views
            .slices
            .iter()
            .any(|s| s.path == "header.Referer.query" && s.text.contains("script")));
        let _ = PipelineConfig::default();
    }

    #[test]
    fn user_agent_and_x_nerve_test_become_views() {
        let mut views = RequestViews::default();
        let opts = DecodeOptions::default();
        expand_sidechannel_headers(
            &mut views,
            &[
                (
                    "User-Agent".into(),
                    "<script>alert(1)</script>".into(),
                ),
                (
                    "X-Nerve-Test".into(),
                    "PGlmcmFtZQ==".into(), // <iframe
                ),
            ],
            &opts,
        );
        assert!(
            views
                .slices
                .iter()
                .any(|s| s.path.to_ascii_lowercase().starts_with("header.user-agent")
                    && s.text.to_ascii_lowercase().contains("<script")),
            "UA should be in views"
        );
        assert!(
            views.slices.iter().any(|s| {
                s.path.to_ascii_lowercase().starts_with("header.x-nerve-test")
                    && s.text.to_ascii_lowercase().contains("iframe")
            }),
            "X-Nerve-Test base64 should expand"
        );
    }
}
