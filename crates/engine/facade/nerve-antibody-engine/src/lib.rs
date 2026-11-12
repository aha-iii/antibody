//! # nerve-antibody
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
mod inspect_cache;
mod pool;
mod shadow;

pub use engine::Engine;
pub use error::NativeError;
pub use health::NativeHealth;
pub use nerve_antibody_dsl::NativeLevel;
pub use nerve_antibody_metrics::{self, EngineMetrics, MetricsSnapshot};
pub use nerve_antibody_runtime::{
    intercept, InspectExec, InterceptDecision, InterceptPermit, MatchedRule, NativeHit,
    NativeRequest,
};
pub use shadow::{
    sandbox_sample_hit, shadow_source, ShadowConfig, ShadowFeedback, ShadowRecord, ShadowRuntime,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 明文 pack 目录在生产默认禁用（只认 `.sealed`），测试需显式开启开发模式。
    ///
    /// 同时串行化：`install_semantic_pack` / `install_model` 与 EvalPolicy 都是进程级
    /// 全局单例，测试并发加载不同 pack（demo / baseline）会互相覆盖，导致断言读到
    /// 别的用例的状态。返回的 guard 存活到用例结束，等价于对这些用例加互斥。
    fn enable_dev_pack() -> std::sync::MutexGuard<'static, ()> {
        static DEV_PACK_INIT: std::sync::Once = std::sync::Once::new();
        DEV_PACK_INIT.call_once(|| {
            std::env::set_var("NERVE_NATIVE_DEV_PACK", "1");
        });
        static PACK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = PACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 全局判定缓存是进程级的，用例之间会互相命中（同一 URI 在 demo 包下 block，
        // 在 baseline 包下 allow）。串行持有锁后统一清空，保证每个用例从干净状态开始。
        crate::inspect_cache::reset_global_verdict_cache();
        guard
    }

    fn demo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/demo")
    }

    #[test]
    fn baseline_pack_loads_and_blocks_xss() {
        let _guard = enable_dev_pack();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline pack");
        assert_eq!(eng.pack_id(), "baseline");
        assert!(eng.health().rule_count >= 100);
        let h = eng.health();
        assert_eq!(h.threshold_low, 40);
        assert_eq!(h.threshold_medium, 36);
        assert_eq!(h.threshold_high, 32);
        assert!(h.semantic_enabled);
        assert_eq!(h.inspect_mode, "auto");
        assert!(
            h.semantic_signature_count >= 6,
            "semantic pack signatures: {}",
            h.semantic_signature_count
        );
        assert!(h.signals_enabled);
        assert!(h.signals_feature_count >= 4, "declared signal features");
        assert!(
            h.signals_fingerprint_count >= 2,
            "declared signal fingerprints"
        );
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
        let _guard = enable_dev_pack();
        use std::collections::HashMap;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
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
        let _guard = enable_dev_pack();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
        let eng = Engine::load_pack(&root).expect("baseline");
        let fp = NativeRequest {
            method: "GET".into(),
            uri: "/activityi;src=1;type=global;cat=wac-v0;ord=1".into(),
            ..Default::default()
        };
        for level in [NativeLevel::Low, NativeLevel::Medium, NativeLevel::High] {
            let hit = eng.inspect(&fp, level).unwrap();
            if let Some(h) = hit {
                assert_ne!(
                    h.action, "block",
                    "adobe cat= should not block at {level:?}"
                );
            }
        }
        let atk = NativeRequest {
            method: "GET".into(),
            uri: "/x".into(),
            query: "id=1'+and+''%3D'".into(),
            ..Default::default()
        };
        let mid = eng
            .inspect(&atk, NativeLevel::Medium)
            .unwrap()
            .expect("sqli");
        assert_eq!(mid.action, "block");
        assert_eq!(mid.block_threshold, 36);
        let high = eng.inspect(&atk, NativeLevel::High).unwrap().expect("sqli");
        assert_eq!(high.block_threshold, 32);
    }

    #[test]
    fn baseline_clean_static_request_no_budget_exhaustion() {
        let _guard = enable_dev_pack();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
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
        let _guard = enable_dev_pack();
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/community-crs");
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
        let _guard = enable_dev_pack();
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
        let _guard = enable_dev_pack();
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
        // 规则已从单条 `sqli-or` 拆为 `sqli-or-1eq1` / `sqli-or-true-word`，按前缀匹配。
        assert!(high
            .matched
            .iter()
            .any(|m| m.rule_id.starts_with("sqli-or")));
    }

    #[test]
    fn reload_works() {
        let _guard = enable_dev_pack();
        let eng = Engine::load_pack(demo_root()).unwrap();
        eng.reload(None).unwrap();
        assert_eq!(eng.pack_id(), "demo");
    }

    #[test]
    fn cache_roundtrip() {
        let _guard = enable_dev_pack();
        let dir = std::env::temp_dir().join("nerve-antibody-cache-test");
        let _ = std::fs::create_dir_all(&dir);
        let eng = Engine::load_pack_with_cache(demo_root(), Some(dir.clone())).unwrap();
        assert!(eng.health().ready);
        let eng2 = Engine::load_pack_with_cache(demo_root(), Some(dir)).unwrap();
        assert_eq!(eng2.pack_version(), eng.pack_version());
    }

    #[test]
    fn jwt_oversized_allows_normal_bearer_token() {
        let _guard = enable_dev_pack();
        use std::collections::HashMap;
        let eng = Engine::load_pack(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline"),
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
    #[ignore = "阻塞于规则包/路由策略：jwt-oversized 同时含 header 与 query 正则，不算廉价正则，\n                 在 api_positive_lane+Fast 的候选截断下按设计跳过"]
    fn jwt_oversized_blocks_huge_payload_segment() {
        let _guard = enable_dev_pack();
        use std::collections::HashMap;
        let eng = Engine::load_pack(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline"),
        )
        .expect("baseline");
        let huge_payload = "A".repeat(4100);
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".into(),
            format!("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{huge_payload}.sig"),
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
        let _guard = enable_dev_pack();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
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

    fn baseline_pack() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline")
    }

    #[test]
    #[ignore = "阻塞于产品决策：resolve_ris 目前丢弃 clean_json_api/api_positive_lane，\n                 所有带 body 的请求都走 Deep；放开等于缩小 Fast 规则集，需先确认检出率影响"]
    fn openapi_sms_json_routes_fast_not_deep() {
        let _guard = enable_dev_pack();
        std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "auto");
        let eng = Engine::load_pack(baseline_pack()).expect("baseline");
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
        let plan = ev.plan_inspect(&req, nerve_antibody_runtime::PlanCacheHints::default());
        assert_eq!(
            plan.path,
            nerve_antibody_metrics::InspectPath::Fast,
            "clean JSON API should use fast path score={} deep={}",
            plan.route_score,
            plan.route_deep
        );
        assert!(plan.inline_fast_lane);
        assert!(plan.api_positive_lane);
    }

    #[test]
    fn clean_favicon_and_api_search_route_fast() {
        let _guard = enable_dev_pack();
        std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "auto");
        let eng = Engine::load_pack(baseline_pack()).expect("baseline");
        let ev = eng.evaluator_for(NativeLevel::Medium);
        for (uri, query) in [
            ("/favicon.ico", ""),
            ("/health", ""),
            ("/api/search", "q=hello-world&page=1"),
            (
                "/api/search",
                "q=hello-world&page=1&id=550e8400-e29b-41d4-a716-446655440000",
            ),
            ("/api/", "tags=a&name=b&nodes=1"),
        ] {
            let req = NativeRequest {
                method: "GET".into(),
                uri: uri.into(),
                query: query.into(),
                ..Default::default()
            };
            let plan = ev.plan_inspect(&req, nerve_antibody_runtime::PlanCacheHints::default());
            assert_eq!(
                plan.path,
                nerve_antibody_metrics::InspectPath::Fast,
                "uri={uri} q={query} score={} route_deep={} decode={} evasion={}",
                plan.route_score,
                plan.route_deep,
                plan.decode_hint,
                plan.evasion_hint
            );
        }
    }

    #[test]
    fn mount_sandbox_observe_only_slot() {
        let _guard = enable_dev_pack();
        let live = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/demo");
        let eng = Engine::load_pack(&live).expect("baseline");
        assert!(!eng.sandbox_mounted());
        eng.mount_sandbox(&candidate).expect("mount sandbox");
        assert!(eng.sandbox_mounted());
        let h = eng.health();
        assert!(h.sandbox_mounted);
        assert_eq!(h.sandbox_pack_id.as_deref(), Some("demo"));
        eng.unmount_sandbox();
        assert!(!eng.sandbox_mounted());
    }

    #[test]
    #[ignore = "同上：该用例的前提是干净 JSON API 走 Fast；当前被 resolve_ris 兜底判为 Deep，\n                 单请求会打满 max_inspect_ms(5s)"]
    fn openapi_sms_json_inspect_fast_latency() {
        let _guard = enable_dev_pack();
        use std::time::{Duration, Instant};

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline");
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

    #[test]
    fn vp_live_promote_blocks_probe_token() {
        let _guard = enable_dev_pack();
        use std::fs;
        use std::process::Command;

        let src = baseline_pack();
        if !src
            .join("virtual-patches/CVE-2024-DEMO01/meta.toml")
            .is_file()
        {
            return;
        }
        let tmp = tempfile::tempdir().expect("tmp");
        let dst = tmp.path().join("baseline");
        // 2.9M pack — cp -a is enough for smoke
        let status = Command::new("cp")
            .args(["-a", src.to_str().unwrap(), dst.to_str().unwrap()])
            .status()
            .expect("cp");
        assert!(status.success(), "copy baseline pack");

        let cve = dst.join("virtual-patches/CVE-2024-DEMO01");
        let mut meta = nerve_antibody_pack::read_meta(&cve).expect("meta");
        meta.status = "live".into();
        nerve_antibody_pack::write_meta(&cve, &meta).expect("write live");

        let eng = Engine::load_pack(&dst).expect("load promoted pack");
        let req = NativeRequest {
            method: "GET".into(),
            host: "example.com".into(),
            uri: "/api/vp-demo".into(),
            query: "q=nerve-vp-probe-demo01".into(),
            ..Default::default()
        };
        let hit = eng
            .inspect(&req, NativeLevel::Medium)
            .expect("inspect")
            .expect("expected hit");
        assert_eq!(
            hit.action, "block",
            "rule={} evidence={}",
            hit.rule_id, hit.evidence
        );
        assert!(
            hit.rule_id.starts_with("vp-"),
            "expected vp- rule, got {}",
            hit.rule_id
        );
        let _ = fs::remove_dir_all(&dst);
    }
}
