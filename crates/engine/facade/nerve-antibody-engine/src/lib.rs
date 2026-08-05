//! # nerve-waf-native
//!
//! Nerve **自研检测引擎（Native Engine）** 对外稳定 API（facade）。
//!
//! 流水线：`pack 加载` → `按 Low/Medium/High 编译 IR` → `Evaluator::inspect`。
//! 支持热更新（[`Engine::reload`]）与 IR 落盘缓存（[`Engine::load_pack_with_cache`]）。
//!
//! ## 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`engine`] | [`Engine`] 主体 |
//! | [`health`] | 健康/就绪快照 |
//! | [`error`] | 统一错误 |

mod engine;
mod error;
mod health;
mod pool;
mod shadow;

pub use engine::Engine;
pub use error::NativeError;
pub use health::NativeHealth;
pub use shadow::{ShadowConfig, ShadowFeedback, ShadowRecord, ShadowRuntime};
pub use nerve_antibody_dsl::NativeLevel;
pub use nerve_antibody_metrics::{self, EngineMetrics, MetricsSnapshot};
pub use nerve_antibody_runtime::{NativeHit, NativeRequest, MatchedRule};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn demo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/demo")
    }

    #[test]
    fn baseline_pack_loads_and_blocks_xss() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline pack");
        assert_eq!(eng.pack_id(), "baseline");
        assert!(eng.health().rule_count >= 100);
        let h = eng.health();
        assert_eq!(h.threshold_low, 40);
        assert_eq!(h.threshold_medium, 36);
        assert_eq!(h.threshold_high, 32);
        assert!(h.semantic_enabled);
        assert_eq!(h.inspect_mode, "auto");
        assert!(h.semantic_signature_count >= 6, "semantic pack signatures");
        assert!(h.signals_enabled);
        assert!(h.signals_feature_count >= 4, "declared signal features");
        assert!(h.signals_fingerprint_count >= 2, "declared signal fingerprints");
        assert!(h.rules_low < h.rules_medium);
        assert!(h.rules_medium <= h.rules_high);
        let hit = eng
            .inspect(
                &NativeRequest {
                    method: "GET".into(),
                    uri: "/x".into(),
                    query: "q=<script>alert(1)</script>".into(),
                    ..Default::default()
                },
                NativeLevel::Medium,
            )
            .unwrap()
            .expect("xss hit");
        assert_eq!(hit.action, "block");
        assert_eq!(hit.block_threshold, 36);
    }

    #[test]
    fn baseline_blocks_xss_payload_in_referer() {
        use std::collections::HashMap;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline pack");
        let mut headers = HashMap::new();
        headers.insert(
            "Referer".into(),
            "http://h/vulnerabilities/xss_r/?name=<script>alert(1)</script>".into(),
        );
        let hit = eng
            .inspect(
                &NativeRequest {
                    method: "GET".into(),
                    uri: "/vulnerabilities/xss_r/".into(),
                    query: "name=".into(),
                    headers,
                    ..Default::default()
                },
                NativeLevel::Medium,
            )
            .unwrap()
            .expect("referer xss should block");
        assert_eq!(hit.action, "block");
        assert!(
            hit.param_path
                .as_deref()
                .map(|p| p.to_ascii_lowercase().contains("referer"))
                .unwrap_or(true)
                || hit.evidence.to_ascii_lowercase().contains("referer")
                || hit.matched.iter().any(|m| m.rule_id.contains("xss")),
            "evidence={:?} path={:?}",
            hit.evidence,
            hit.param_path
        );
    }

    #[test]
    fn baseline_allow_adobe_cat_and_level_thresholds() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline");
        let fp = NativeRequest {
            method: "GET".into(),
            uri: "/activityi;src=1;type=global;cat=wac-v0;ord=1".into(),
            ..Default::default()
        };
        for level in [NativeLevel::Low, NativeLevel::Medium, NativeLevel::High] {
            let hit = eng.inspect(&fp, level).unwrap();
            if let Some(h) = hit {
                assert_ne!(h.action, "block", "adobe cat= should not block at {level:?}");
            }
        }
        let atk = NativeRequest {
            method: "GET".into(),
            uri: "/x".into(),
            query: "id=1'+and+''%3D'".into(),
            ..Default::default()
        };
        let mid = eng.inspect(&atk, NativeLevel::Medium).unwrap().expect("sqli");
        assert_eq!(mid.action, "block");
        assert_eq!(mid.block_threshold, 36);
        let high = eng.inspect(&atk, NativeLevel::High).unwrap().expect("sqli");
        assert_eq!(high.block_threshold, 32);
    }

    #[test]
    fn baseline_clean_static_request_no_budget_exhaustion() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline");
        let ev = eng.evaluator_for(NativeLevel::High);
        let clean = NativeRequest {
            method: "GET".into(),
            uri: "/static/app.js".into(),
            query: "v=1.2.3".into(),
            ..Default::default()
        };
        let hit = ev.inspect(&clean);
        assert!(
            hit.as_ref().map(|h| h.action.as_str()) != Some("block"),
            "clean static should not block"
        );
        if let Some(h) = hit {
            assert!(
                h.budget_exhausted.is_none(),
                "clean traffic should not exhaust inspect budget: {:?}",
                h.budget_exhausted
            );
        }
    }

    #[test]
    fn community_crs_pack_loads_and_blocks_sqli() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/community-crs");
        let eng = Engine::load_pack(&root).expect("community-crs pack");
        assert_eq!(eng.pack_id(), "community-crs");
        assert!(
            eng.health().rule_count >= 100,
            "count={}",
            eng.health().rule_count
        );
        let hit = eng
            .inspect(
                &NativeRequest {
                    method: "GET".into(),
                    uri: "/x".into(),
                    query: "q=1 union select null--".into(),
                    ..Default::default()
                },
                NativeLevel::Medium,
            )
            .unwrap();
        assert!(hit.is_some(), "translated CRS should catch SQLi sample");
    }

    #[test]
    fn demo_pack_blocks_xss() {
        let eng = Engine::load_pack(demo_root()).unwrap();
        assert!(eng.health().ready);
        let hit = eng
            .inspect(
                &NativeRequest {
                    method: "GET".into(),
                    uri: "/search?q=<script>alert(1)</script>".into(),
                    ..Default::default()
                },
                NativeLevel::Medium,
            )
            .unwrap()
            .expect("hit");
        assert_eq!(hit.action, "block");
        assert!(!hit.matched.is_empty());
    }

    #[test]
    fn high_level_enables_strict_rule() {
        let eng = Engine::load_pack(demo_root()).unwrap();
        let req = NativeRequest {
            uri: "/api?id=1' or 1=1--".into(),
            ..Default::default()
        };
        if let Some(low) = eng.inspect(&req, NativeLevel::Low).unwrap() {
            assert!(
                !low.matched.iter().any(|m| m.rule_id == "sqli-or"),
                "high-only rule must not fire at Low: {:?}",
                low.matched
            );
        }
        let high = eng
            .inspect(&req, NativeLevel::High)
            .unwrap()
            .expect("sqli-or at High");
        assert!(high.matched.iter().any(|m| m.rule_id == "sqli-or"));
    }

    #[test]
    fn reload_works() {
        let eng = Engine::load_pack(demo_root()).unwrap();
        eng.reload(None).unwrap();
        assert_eq!(eng.pack_id(), "demo");
    }

    #[test]
    fn cache_roundtrip() {
        let dir = std::env::temp_dir().join("nerve-antibody-cache-test");
        let _ = std::fs::create_dir_all(&dir);
        let eng = Engine::load_pack_with_cache(demo_root(), Some(dir.clone())).unwrap();
        assert!(eng.health().ready);
        let eng2 = Engine::load_pack_with_cache(demo_root(), Some(dir)).unwrap();
        assert_eq!(eng2.pack_version(), eng.pack_version());
    }

    #[test]
    fn jwt_oversized_allows_normal_bearer_token() {
        use std::collections::HashMap;
        let eng = Engine::load_pack(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline"),
        )
        .expect("baseline");
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".into(),
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig".into(),
        );
        let hit = eng.inspect(
            &NativeRequest {
                method: "GET".into(),
                uri: "/api/msg/sms/template/getTemplateList".into(),
                headers,
                ..Default::default()
            },
            NativeLevel::Low,
        );
        if let Ok(Some(h)) = hit {
            assert!(
                !h.matched.iter().any(|m| m.rule_id == "jwt-oversized"),
                "normal JWT should not hit jwt-oversized: {:?}",
                h.matched
            );
        }
    }

    #[test]
    fn jwt_oversized_blocks_huge_payload_segment() {
        use std::collections::HashMap;
        let eng = Engine::load_pack(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline"),
        )
        .expect("baseline");
        let huge_payload = "A".repeat(4100);
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".into(),
            format!(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{huge_payload}.sig"
            ),
        );
        let hit = eng
            .inspect(
                &NativeRequest {
                    method: "GET".into(),
                    uri: "/api/x".into(),
                    headers,
                    ..Default::default()
                },
                NativeLevel::Low,
            )
            .unwrap()
            .expect("oversized jwt");
        assert!(
            hit.matched.iter().any(|m| m.rule_id == "jwt-oversized"),
            "matched={:?}",
            hit.matched
        );
    }

    #[test]
    fn openapi_auth_signature_query_not_blocked() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline");
        let q = "tenantCode=copycrmplatformproduct1&mchOrderNo=M1651467414021009409&tenant=saascrmtesttenant1&appid=1663840148522&reqid=f3af43c0-4eb2-4edd-995a-707cac934e41&timestamp=1785293775435&sign=B7735E0215C0A341794FBC971FE825B75C81AE1DA6FE59F43DD9D0A5057295FE";
        for level in [NativeLevel::Medium, NativeLevel::High] {
            let hit = eng
                .inspect(
                    &NativeRequest {
                        method: "POST".into(),
                        uri: "/api/auth-center/auth".into(),
                        query: q.into(),
                        body: q.into(),
                        content_type: Some("application/x-www-form-urlencoded".into()),
                        ..Default::default()
                    },
                    level,
                )
                .expect("inspect");
            if let Some(h) = &hit {
                panic!(
                    "openapi auth FP at {level:?}: rule_id={} action={} evidence={}",
                    h.rule_id, h.action, h.evidence
                );
            }
        }
    }

    #[test]
    fn openapi_sms_json_routes_fast_not_deep() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline");
        let body = r#"{"tenantCode":"test","tenantName":"平台测试","templateCode":"TCY_CODE_000001","phoneNumber":"13800138000"}"#;
        let req = NativeRequest {
            method: "POST".into(),
            uri: "/open/api/msg/sms/v1/send".into(),
            query: String::new(),
            body: body.into(),
            content_type: Some("application/json".into()),
            ..Default::default()
        };
        let ev = eng.evaluator_for(NativeLevel::Medium);
        let plan = ev.plan_inspect(&req);
        assert_eq!(
            plan.path,
            nerve_antibody_metrics::InspectPath::Fast,
            "clean JSON API should use fast path"
        );
        assert!(plan.inline_fast_lane);
        assert!(plan.api_positive_lane);
    }

    #[test]
    fn openapi_sms_json_inspect_fast_latency() {
        use std::time::{Duration, Instant};

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline");
        let body = r#"{"tenantCode":"test","tenantName":"平台测试","templateCode":"TCY_CODE_000001","phoneNumber":"13800138000"}"#;
        let req = NativeRequest {
            method: "POST".into(),
            uri: "/open/api/msg/sms/v1/send".into(),
            query: String::new(),
            body: body.into(),
            content_type: Some("application/json".into()),
            ..Default::default()
        };
        // 预热 Pack / 线程池
        for _ in 0..3 {
            let _ = eng.inspect(&req, NativeLevel::Medium);
        }
        let mut samples = Vec::with_capacity(10);
        for _ in 0..10 {
            let t0 = Instant::now();
            let _ = eng.inspect(&req, NativeLevel::Medium).expect("inspect");
            samples.push(t0.elapsed());
        }
        samples.sort();
        let p50 = samples[samples.len() / 2];
        assert!(
            p50 < Duration::from_millis(80),
            "JSON API fast inspect p50={:?} (samples={:?})",
            p50,
            samples
        );
    }
}
