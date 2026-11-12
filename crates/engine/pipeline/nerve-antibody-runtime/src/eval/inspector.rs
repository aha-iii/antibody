use super::candidates::{collect_contains_groups, is_cheap_regex_rule, rule_ready_at_layer};
use super::fields::{field_texts, FieldCache};
use super::hints::{
    adaptive_contribute_effective, build_features, decode_attack_hint, is_benign_simple_request,
    is_cache_deception_probe_uri, is_static_asset_uri, payload_evasion_hint,
    raw_encoded_attack_markers, resolve_ris, suspicious_for_deep_scan,
};
use super::policy::{EvalPolicy, InspectExec, InspectMode, InspectPlan, PlanCacheHints};
use super::rules::eval_when;
use super::tail::{apply_rule_match, eval_tail_rules, should_stop_rules, try_parallel_tail_eval};
use crate::decode_cache::{payload_hash, DeepViewCacheKey};
use crate::fusion::{fuse, FusionEvidence};
use crate::route_gate;
use crate::structure_anchor::{classify_structure, StructureClass};
use crate::types::{MatchedRule, ModelHitDto, NativeHit, NativeRequest, SemanticSignalDto};
use nerve_antibody_adaptive::{self as adaptive, AdaptiveInput, FeatureSnapshot};
use nerve_antibody_compiler::{active_fields, cluster_candidate_seed, Program};
use nerve_antibody_dsl::{FieldScope, MatchField, RuleAction, Transform};
use nerve_antibody_metrics::{
    global as metrics_global, InspectPath, InspectStages, InspectTimer, RisZone,
};
use nerve_antibody_pipeline::{
    build_views, build_views_shallow, build_views_unbudgeted, expand_all_fields_one_layer,
    InspectBudget, PipelineConfig, RequestViews,
};
use nerve_antibody_semantic::{self as semantic, SemanticInput};
use nerve_antibody_signals::{self, RequestSignals};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// 绑定某一强度档 Program 的求值器。
#[derive(Clone)]
pub struct Evaluator {
    program: Program,
    observe_only: bool,
    policy: EvalPolicy,
}

impl Evaluator {
    pub fn from_program(program: Program) -> Self {
        Self {
            program,
            observe_only: false,
            policy: EvalPolicy::default(),
        }
    }

    pub fn with_observe_only(mut self, v: bool) -> Self {
        self.observe_only = v;
        self
    }

    pub fn with_policy(mut self, policy: EvalPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub fn pipeline_config(&self) -> &PipelineConfig {
        &self.policy.pipeline
    }

    /// 规划 inspect 路径与预览视图（供双 worker 池与单次执行共用）。
    pub fn plan_inspect(&self, req: &NativeRequest, hints: PlanCacheHints) -> InspectPlan {
        let t_ris = Instant::now();
        let mode = InspectMode::resolve(&self.policy.inspect_mode);
        let pipe_base = self.policy.pipeline.for_level(self.program.level);
        let static_asset = is_static_asset_uri(&req.uri);
        let cache_deception_probe = is_cache_deception_probe_uri(&req.uri);
        let pipe_route = pipe_base.for_route_preview();
        let views_preview = build_views_unbudgeted(
            &req.method,
            &req.uri,
            &req.query,
            &req.body,
            &req.headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
            req.content_type(),
            req.response_body.as_deref(),
            &pipe_route,
        );
        let decode_hint_preview = decode_attack_hint(&views_preview);
        let evasion_hint_preview = payload_evasion_hint(req, &views_preview);
        let mut headers_map: HashMap<String, String> = req
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if let Some(ct) = req.content_type.as_deref() {
            if !ct.is_empty()
                && !headers_map
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("content-type"))
            {
                headers_map.insert("content-type".into(), ct.to_string());
            }
        }
        let route_signals = nerve_antibody_signals::compute_signals_with_pack(
            &req.method,
            &req.uri,
            &req.query,
            &req.body,
            &headers_map,
            self.policy.signal_pack.as_deref(),
        );
        let has_response = req
            .response_body
            .as_ref()
            .map(|b| !b.is_empty())
            .unwrap_or(false);
        let encoded_hard = raw_encoded_attack_markers(req);
        let hard_deep = cache_deception_probe
            || has_response
            || (self.policy.route_gate.hard_decode_hint
                && (decode_hint_preview || evasion_hint_preview))
            || encoded_hard;
        let route_decision = route_gate::decide_deep(
            &self.policy.route_gate,
            req,
            &views_preview,
            decode_hint_preview,
            evasion_hint_preview,
            cache_deception_probe,
            has_response,
        );
        let l1 = self
            .policy
            .ris_l1
            .as_ref()
            .map(|p| p.probe(req, &route_signals))
            .unwrap_or_default();
        let bloom_clear = hints.bloom_clear || l1.bloom_clear;
        let negative_hit = hints.negative_hit || l1.negative_hit;
        let structure_known = hints.structure_known || l1.structure_known;
        let struct_class = classify_structure(req);
        let structure_clean = matches!(struct_class, StructureClass::Clean)
            && !hard_deep
            && !encoded_hard
            && !decode_hint_preview
            && !evasion_hint_preview
            && !route_decision.features.attack_shape;
        let structure_anomaly = matches!(struct_class, StructureClass::Anomaly);
        // 硬触发时不得用 Bloom/负缓存/结构记忆压成 clean
        let bloom_clear = bloom_clear && !hard_deep && !encoded_hard;
        let negative_hit = negative_hit && !hard_deep && !encoded_hard;
        let structure_known = structure_known && !hard_deep && !encoded_hard && !structure_anomaly;
        let suspicious = suspicious_for_deep_scan(req, &views_preview) || encoded_hard;
        let (path, ris_zone) = resolve_ris(
            mode,
            static_asset,
            cache_deception_probe,
            hard_deep,
            has_response,
            decode_hint_preview,
            evasion_hint_preview,
            suspicious,
            route_decision.clean_json_api,
            route_decision.api_positive_lane,
            is_benign_simple_request(req),
            bloom_clear,
            negative_hit,
            structure_clean,
            structure_known,
            structure_anomaly,
            route_decision.score,
            self.policy.route_gate.gray_threshold,
            self.policy.route_gate.deep_threshold,
        );
        let prefilter_hay = views_preview.haystack_for_prefilter(64 * 1024);
        // Fast 仅绑在明确干净通道；可疑流量即使 lane 标记也不得缩规则集
        let structure_lane = structure_clean || structure_known;
        let inline_fast_lane =
            (route_decision.clean_json_api || route_decision.api_positive_lane || structure_lane)
                && path == InspectPath::Fast
                && !suspicious
                && ris_zone == RisZone::Clean;
        let api_positive_lane = (route_decision.api_positive_lane || structure_lane)
            && path == InspectPath::Fast
            && !suspicious
            && ris_zone == RisZone::Clean;
        InspectPlan {
            path,
            ris_zone,
            ris_us: t_ris.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            views_preview,
            decode_hint: decode_hint_preview,
            evasion_hint: evasion_hint_preview,
            route_deep: route_decision.route_deep || path == InspectPath::Deep,
            route_score: route_decision.score,
            inline_fast_lane,
            api_positive_lane,
            route_signals,
            prefilter_hay,
        }
    }

    /// 预览 inspect 路径（供双 worker 池路由）。
    pub fn preview_inspect_path(&self, req: &NativeRequest) -> InspectPath {
        self.plan_inspect(req, PlanCacheHints::default()).path
    }

    /// 扫描候选规则 + 语义 + 自适应，融合后决定 block / observe。
    pub fn inspect(&self, req: &NativeRequest) -> Option<NativeHit> {
        self.inspect_exec(req).hit
    }

    /// 同 [`inspect`]，额外返回 RIS / Fast / Deep 路径耗时。
    pub fn inspect_exec(&self, req: &NativeRequest) -> InspectExec {
        let plan = self.plan_inspect(req, PlanCacheHints::default());
        self.inspect_plan_exec(req, plan)
    }

    /// 按已规划路径执行 inspect（不再重复 route preview）。
    pub fn inspect_plan(&self, req: &NativeRequest, plan: InspectPlan) -> Option<NativeHit> {
        self.inspect_plan_exec(req, plan).hit
    }

    /// 同 [`inspect_plan`]，额外返回路径与分段耗时（无命中时也有）。
    pub fn inspect_plan_exec(&self, req: &NativeRequest, plan: InspectPlan) -> InspectExec {
        let mode = InspectMode::resolve(&self.policy.inspect_mode);
        let pipe_base = self.policy.pipeline.for_level(self.program.level);
        metrics_global().record_route_gate(plan.route_deep, plan.route_score);
        metrics_global().record_ris_zone(plan.ris_zone);
        let inspect_path = plan.path;
        let views_preview = &plan.views_preview;
        let ris_us = plan.ris_us;
        let route_score = plan.route_score;
        let route_deep = plan.route_deep;
        let inline_fast_lane = plan.inline_fast_lane;
        let api_positive_lane = plan.api_positive_lane;
        let ris_zone = plan.ris_zone;

        let mut pipe = pipe_base.clone();
        if inspect_path == InspectPath::Fast {
            pipe = pipe.for_fast_path();
            if let Some(fast_ms) = self.policy.fast_max_inspect_ms {
                let cap = if pipe.max_inspect_ms > 0 {
                    fast_ms.min(pipe.max_inspect_ms)
                } else {
                    fast_ms
                };
                pipe.max_inspect_ms = cap;
            }
        }

        let timer = InspectTimer::start(inspect_path);
        let force_full = Self::force_full_decode();
        let use_lazy = self.policy.lazy_decode
            && !force_full
            && mode != InspectMode::Deep
            && inspect_path == InspectPath::Deep
            && pipe.decode_enabled;
        let mut hit = if use_lazy {
            self.inspect_lazy_incremental(req, &pipe, inspect_path, mode, plan.api_positive_lane)
        } else {
            self.inspect_with_path(
                req,
                &pipe,
                inspect_path,
                mode,
                u8::MAX,
                if inspect_path == InspectPath::Fast {
                    Some(views_preview)
                } else {
                    None
                },
                plan.api_positive_lane,
                None,
                Some(&plan.route_signals),
                Some(&plan.prefilter_hay),
            )
        };
        let mut blocked = hit
            .as_ref()
            .map(|h| h.action == "block" || h.action == "challenge")
            .unwrap_or(false);
        let mut budget_ex = hit
            .as_ref()
            .and_then(|h| h.budget_exhausted.as_ref())
            .is_some();
        let first_us = timer.finish(metrics_global(), budget_ex, blocked);

        let mut fast_us = 0u64;
        let mut deep_us = 0u64;
        let mut final_path = inspect_path;
        match inspect_path {
            InspectPath::Fast => fast_us = first_us,
            InspectPath::Deep => deep_us = first_us,
        }

        // auto + Fast 未硬拦：可疑/编码/近阈路由分 → 升 deep（避免无解码漏检）
        if mode == InspectMode::Auto
            && inspect_path == InspectPath::Fast
            && !blocked
            && Self::should_escalate_fast_to_deep(req, &plan, views_preview)
        {
            metrics_global().record_fast_pool_escalate();
            let deep_timer = InspectTimer::start(InspectPath::Deep);
            let deep_pipe = pipe_base;
            let use_lazy_deep = self.policy.lazy_decode && !force_full && deep_pipe.decode_enabled;
            hit = if use_lazy_deep {
                self.inspect_lazy_incremental(req, &deep_pipe, InspectPath::Deep, mode, false)
            } else {
                self.inspect_with_path(
                    req,
                    &deep_pipe,
                    InspectPath::Deep,
                    mode,
                    u8::MAX,
                    None,
                    false,
                    None,
                    Some(&plan.route_signals),
                    Some(&plan.prefilter_hay),
                )
            };
            blocked = hit
                .as_ref()
                .map(|h| h.action == "block" || h.action == "challenge")
                .unwrap_or(false);
            budget_ex = hit
                .as_ref()
                .and_then(|h| h.budget_exhausted.as_ref())
                .is_some();
            deep_us = deep_timer.finish(metrics_global(), budget_ex, blocked);
            final_path = InspectPath::Deep;
        }

        // RIS L5：高置信 clean Fast 放行 → 回写 Bloom / 负缓存
        if !blocked
            && plan.path == InspectPath::Fast
            && plan.ris_zone == RisZone::Clean
            && (plan.inline_fast_lane || plan.api_positive_lane || is_benign_simple_request(req))
        {
            if let Some(l1) = self.policy.ris_l1.as_ref() {
                l1.remember_clear(req, &plan.route_signals);
            }
        }

        InspectExec {
            hit,
            path: final_path,
            ris_zone,
            ris_us,
            fast_us,
            deep_us,
            route_score,
            route_deep: route_deep || final_path == InspectPath::Deep,
            inline_fast_lane,
            api_positive_lane,
        }
    }

    fn should_escalate_fast_to_deep(
        req: &NativeRequest,
        plan: &InspectPlan,
        _views: &RequestViews,
    ) -> bool {
        // Nerve RIS：仅 gray 区 escalate；clean 不升检；hot 已走 Deep。
        // gray 未硬拦 → 一律升 Deep（分数已过灰阈，不能再靠启发式二次筛掉）。
        if plan.ris_zone != RisZone::Gray {
            return false;
        }
        if plan.api_positive_lane || plan.inline_fast_lane {
            return false;
        }
        if is_static_asset_uri(&req.uri) && !is_cache_deception_probe_uri(&req.uri) {
            return false;
        }
        true
    }

    /// 按需 lazy decode：浅层 → 匹配 → 增量展开 → 再匹配，decode 与 regex 共用 budget。
    fn inspect_lazy_incremental(
        &self,
        req: &NativeRequest,
        pipe: &PipelineConfig,
        inspect_path: InspectPath,
        mode: InspectMode,
        api_positive_lane: bool,
    ) -> Option<NativeHit> {
        let headers_vec: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut budget = InspectBudget::new(
            pipe.max_inspect_ms,
            pipe.max_regex_evals,
            pipe.max_view_slices,
        );
        let mut views = build_views_shallow(
            &req.method,
            &req.uri,
            &req.query,
            &req.body,
            &headers_vec,
            req.content_type(),
            req.response_body.as_deref(),
            pipe,
            Some(&mut budget),
        )
        .unwrap_or_default();

        let max_layers = pipe.max_decode_depth.max(1);
        let mut last_hit: Option<NativeHit> = None;
        for layer in 0..=max_layers {
            if let Some(hit) = self.inspect_with_path(
                req,
                pipe,
                inspect_path,
                mode,
                layer,
                Some(&views),
                api_positive_lane,
                Some(&mut budget),
                None,
                None,
            ) {
                if matches!(hit.action.as_str(), "block" | "challenge") {
                    return Some(hit);
                }
                last_hit = Some(hit);
            }
            if layer >= max_layers || budget.is_exhausted() {
                break;
            }
            let _ = expand_all_fields_one_layer(&mut views, pipe, &mut budget);
        }
        last_hit
    }

    fn force_full_decode() -> bool {
        std::env::var("NERVE_NATIVE_FORCE_FULL_DECODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn inspect_with_path(
        &self,
        req: &NativeRequest,
        pipe: &PipelineConfig,
        inspect_path: InspectPath,
        mode: InspectMode,
        decode_layer: u8,
        reuse_views: Option<&RequestViews>,
        api_positive_lane: bool,
        reuse_budget: Option<&mut InspectBudget>,
        cached_signals: Option<&RequestSignals>,
        cached_prefilter_hay: Option<&str>,
    ) -> Option<NativeHit> {
        let mut stages = InspectStages::default();
        let effective = pipe.clone();
        let t0 = Instant::now();
        let headers_vec: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut local_budget = InspectBudget::new(
            effective.max_inspect_ms,
            effective.max_regex_evals,
            effective.max_view_slices,
        );
        let budget: &mut InspectBudget = match reuse_budget {
            Some(b) => b,
            None => &mut local_budget,
        };

        let owned_views;
        let views: &RequestViews = if let Some(v) = reuse_views {
            v
        } else {
            let deep_key = (inspect_path == InspectPath::Deep).then(|| {
                let sig = cached_signals.cloned().unwrap_or_else(|| {
                    nerve_antibody_signals::compute_signals_with_pack(
                        &req.method,
                        &req.uri,
                        &req.query,
                        &req.body,
                        &req.headers,
                        self.policy.signal_pack.as_deref(),
                    )
                });
                DeepViewCacheKey {
                    path_fp: sig.path_fingerprint,
                    payload_hash: payload_hash(&req.query, &req.body),
                    max_depth: effective.max_decode_depth,
                }
            });
            owned_views = if let (Some(ref key), Some(ref cache)) =
                (deep_key.as_ref(), self.policy.deep_view_cache.as_ref())
            {
                if let Some(cached) = cache.lookup(key) {
                    cached
                } else {
                    let built = build_views_unbudgeted(
                        &req.method,
                        &req.uri,
                        &req.query,
                        &req.body,
                        &headers_vec,
                        req.content_type(),
                        req.response_body.as_deref(),
                        &effective,
                    );
                    cache.store(key, &built);
                    built
                }
            } else {
                build_views(
                    &req.method,
                    &req.uri,
                    &req.query,
                    &req.body,
                    &headers_vec,
                    req.content_type(),
                    req.response_body.as_deref(),
                    &effective,
                )
            };
            &owned_views
        };
        stages.decode_us = t0.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

        let t_aho = Instant::now();
        let mut cache = FieldCache::new(effective.max_field_chars);
        let signals = if let Some(s) = cached_signals {
            s.clone()
        } else {
            nerve_antibody_signals::compute_signals_with_pack(
                &req.method,
                &req.uri,
                &req.query,
                &req.body,
                &req.headers,
                self.policy.signal_pack.as_deref(),
            )
        };
        let (candidates, aho_seed) = self.candidate_rule_indices(
            req,
            views,
            &signals,
            &mut cache,
            mode,
            inspect_path,
            api_positive_lane,
            decode_layer,
            cached_prefilter_hay,
        );
        stages.aho_us = t_aho.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

        let t_regex = Instant::now();
        let static_asset = is_static_asset_uri(&req.uri);
        let cache_deception_probe = is_cache_deception_probe_uri(&req.uri);
        let decode_hint_early = decode_attack_hint(&views);
        let evasion_hint_early = payload_evasion_hint(req, &views);

        let mut matched = Vec::new();
        let mut rule_score = 0u32;
        let mut allow_score = 0u32;
        let mut wants_block = false;
        let mut budget_reason: Option<String> = None;
        let threshold = self.program.block_threshold;
        let max_field_chars = effective.max_field_chars;

        // allow → Aho → tail；head 串行保序，Deep tail 可并行评估再按序合并
        for &ri in candidates.iter().take(aho_seed) {
            match self.eval_one_rule(ri, req, &views, &signals, &mut cache, budget) {
                Ok(Some(m)) => apply_rule_match(
                    &m,
                    &mut matched,
                    &mut rule_score,
                    &mut allow_score,
                    &mut wants_block,
                ),
                Ok(None) => {}
                Err(reason) => {
                    budget_reason = Some(reason);
                    break;
                }
            }
            if should_stop_rules(
                wants_block,
                rule_score,
                allow_score,
                threshold,
                inspect_path,
            ) {
                break;
            }
        }

        let skip_tail =
            static_asset && !cache_deception_probe && !wants_block && matched.is_empty();

        if !skip_tail && aho_seed < candidates.len() && budget_reason.is_none() {
            if !try_parallel_tail_eval(
                self,
                &candidates[aho_seed..],
                aho_seed,
                req,
                &views,
                &signals,
                max_field_chars,
                budget,
                static_asset,
                cache_deception_probe,
                &mut matched,
                &mut rule_score,
                &mut allow_score,
                &mut wants_block,
                &mut budget_reason,
                threshold,
                inspect_path,
            ) {
                eval_tail_rules(
                    self,
                    &candidates[aho_seed..],
                    aho_seed,
                    req,
                    &views,
                    &signals,
                    &mut cache,
                    budget,
                    static_asset,
                    cache_deception_probe,
                    &mut matched,
                    &mut rule_score,
                    &mut allow_score,
                    &mut wants_block,
                    &mut budget_reason,
                    threshold,
                    inspect_path,
                );
            }
        }
        stages.regex_us = t_regex.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

        let l1_eet = rule_score.saturating_sub(allow_score);
        // 单条 block 规则自身已达阈 → 硬拦，不被高分 allow（如 score=200）冲掉。
        let solo_block = matched
            .iter()
            .any(|m| m.action == "block" && m.score >= threshold);
        let hard_block = solo_block || (wants_block && l1_eet >= threshold);
        // allow 已把 L1 净分压到阈下：跳过语义/自适应，避免 stored metadata 等白样本被 L2/L3 误拦
        let allow_immueity = allow_score > 0 && !hard_block;

        let t_sem = Instant::now();
        let sem_hay = views.haystack_for_soft_signals(12 * 1024);
        let sem_report = if self.policy.semantic_enabled
            && !hard_block
            && !allow_immueity
            && inspect_path == InspectPath::Deep
        {
            semantic::analyze(SemanticInput {
                method: &req.method,
                uri: &req.uri,
                query: &req.query,
                body: &req.body,
                extra: &sem_hay,
                level: self.program.level,
            })
        } else {
            Default::default()
        };
        stages.semantic_us = t_sem.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

        let features = if hard_block {
            FeatureSnapshot::default()
        } else {
            build_features(req, &views, &matched, &sem_report)
        };
        let l1_hit = !matched.is_empty();
        let adaptive_contribute =
            adaptive_contribute_effective(self.policy.adaptive_contribute, inspect_path, l1_hit);
        let model_out =
            if self.policy.adaptive_enabled && !hard_block && inspect_path == InspectPath::Deep {
                Some(adaptive::score(AdaptiveInput {
                    level: self.program.level,
                    features: &features,
                    contribute: adaptive_contribute,
                    level_weight: pipe.adaptive_level_weight,
                    score_cap: pipe.adaptive_score_cap,
                }))
            } else {
                None
            };

        let semantic_score = sem_report.score;
        let model_score = model_out
            .as_ref()
            .filter(|m| m.contributed)
            .map(|m| m.model_score)
            .unwrap_or(0);
        let model_p = model_out.as_ref().map(|m| m.p).unwrap_or(0.0);
        let model_contributed = model_out.as_ref().map(|m| m.contributed).unwrap_or(false);

        let decode_hint = if hard_block { false } else { decode_hint_early };
        let evasion_hint = if hard_block {
            false
        } else {
            evasion_hint_early
        };
        let has_signal = !matched.is_empty()
            || semantic_score > 0
            || sem_report.veto
            || model_out
                .as_ref()
                .map(|m| m.model_score > 0)
                .unwrap_or(false)
            || decode_hint
            || evasion_hint;

        if !has_signal {
            metrics_global().record_stages(&stages);
            #[cfg(feature = "inspect-trace")]
            nerve_inspect_trace::record_native_stages(&nerve_inspect_trace::NativeInspectStages {
                decode_us: stages.decode_us,
                aho_us: stages.aho_us,
                regex_us: stages.regex_us,
                semantic_us: stages.semantic_us,
                fusion_us: stages.fusion_us,
            });
            return None;
        }

        let attack_kw = features.sql_keyword_hits
            + features.xss_keyword_hits
            + features.path_keyword_hits
            + features.rce_keyword_hits;
        // allow 命中不算弱 L1，避免「放行规则 + 模型」被误定罪
        let any_attack_rule = matched.iter().any(|m| m.action != "allow");
        let t_fusion = Instant::now();
        let (total, fusion_action) = fuse(&FusionEvidence {
            wants_block: hard_block,
            any_rule_hit: any_attack_rule,
            rule_score,
            allow_score,
            semantic_score,
            semantic_block_eligible: sem_report.block_eligible,
            semantic_veto: sem_report.veto,
            model_score,
            model_p,
            model_contributed,
            attack_kw_hits: attack_kw,
            decode_depth: views.max_decode_depth(),
            decode_attack_hint: decode_hint,
            evasion_hint,
            static_asset,
            cache_deception_probe,
            threshold,
            level: self.program.level,
            observe_only: self.observe_only,
            min_independent_signals: self.policy.fusion_min_independent,
        });
        stages.fusion_us = t_fusion.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        metrics_global().record_stages(&stages);
        #[cfg(feature = "inspect-trace")]
        nerve_inspect_trace::record_native_stages(&nerve_inspect_trace::NativeInspectStages {
            decode_us: stages.decode_us,
            aho_us: stages.aho_us,
            regex_us: stages.regex_us,
            semantic_us: stages.semantic_us,
            fusion_us: stages.fusion_us,
        });
        let action = fusion_action.as_str();
        metrics_global().record_action(action);

        let primary = matched
            .iter()
            .find(|m| m.action == "block")
            .or_else(|| matched.first());

        let (rule_id, rule_name, severity, evidence, param_path, decode_chain) =
            if let Some(p) = primary {
                (
                    p.rule_id.clone(),
                    p.rule_name.clone(),
                    p.severity.clone(),
                    p.evidence.clone(),
                    p.param_path.clone(),
                    p.decode_chain.clone(),
                )
            } else if let Some(s) = sem_report.signals.first() {
                (
                    s.id.clone(),
                    format!("semantic:{}", s.id),
                    "high".into(),
                    s.evidence.clone(),
                    None,
                    None,
                )
            } else if decode_hint {
                (
                    "decode.attack_hint".into(),
                    "decoded attack-shaped payload".into(),
                    "medium".into(),
                    "decode_attack_hint".into(),
                    None,
                    None,
                )
            } else if evasion_hint {
                (
                    "evasion.payload_hint".into(),
                    "encoding evasion hint".into(),
                    "medium".into(),
                    "evasion_hint".into(),
                    None,
                    None,
                )
            } else {
                (
                    "adaptive".into(),
                    "adaptive model".into(),
                    "medium".into(),
                    "model".into(),
                    None,
                    None,
                )
            };

        Some(NativeHit {
            total_score: total,
            block_threshold: threshold,
            action: action.into(),
            matched,
            rule_id,
            rule_name,
            severity,
            evidence,
            level: self.program.level.as_str().into(),
            rule_score,
            allow_score,
            semantic_score,
            model_score,
            semantic_signals: sem_report
                .signals
                .iter()
                .map(|s| SemanticSignalDto {
                    kind: format!("{:?}", s.kind).to_ascii_lowercase(),
                    id: s.id.clone(),
                    confidence: s.confidence,
                    score_delta: s.score_delta,
                    veto: s.veto,
                    block_eligible: s.block_eligible,
                    evidence: s.evidence.clone(),
                })
                .collect(),
            model: model_out.map(|m| ModelHitDto {
                p: m.p,
                model_score: m.model_score,
                contributed: m.contributed,
                version: m.version,
                top_features: m.top_features,
            }),
            param_path,
            decode_chain,
            budget_exhausted: budget_reason,
            inspect_path: inspect_path.as_str().into(),
        })
    }

    fn candidate_rule_indices(
        &self,
        req: &NativeRequest,
        views: &RequestViews,
        signals: &RequestSignals,
        cache: &mut FieldCache,
        mode: InspectMode,
        inspect_path: InspectPath,
        api_positive_lane: bool,
        decode_layer: u8,
        cached_prefilter_hay: Option<&str>,
    ) -> (Vec<usize>, usize) {
        let e = self.program.rules.len();
        if e == 0 {
            return (Vec::new(), 0);
        }
        let mut aho: HashSet<usize> = HashSet::new();

        let has_response = req
            .response_body
            .as_ref()
            .map(|b| !b.is_empty())
            .unwrap_or(false);
        let active = active_fields(&req.method, &req.uri, &req.query, &req.body, has_response);
        let cluster_seed = cluster_candidate_seed(
            &self.program.field_clusters,
            &self.program.rule_fields,
            &active,
        );

        let mut groups: HashMap<(MatchField, Option<String>, Vec<Transform>), ()> = HashMap::new();
        let rules_to_scan: Vec<usize> = if cluster_seed.is_empty() {
            (0..e).collect()
        } else {
            let mut s: Vec<usize> = cluster_seed.iter().copied().collect();
            for (ri, rule) in self.program.rules.iter().enumerate() {
                if rule.meta.action.is_allow() {
                    s.push(ri);
                }
            }
            s.sort_unstable();
            s.dedup();
            s
        };
        for &ri in &rules_to_scan {
            collect_contains_groups(&self.program.rules[ri].when, &mut groups);
        }

        // 管线展开 haystack（覆盖编码绕过）
        let pipe_hay = cached_prefilter_hay
            .map(|s| s.to_string())
            .unwrap_or_else(|| views.haystack_for_prefilter(64 * 1024));
        for dict_idx in self.program.matcher.find_all(&pipe_hay) {
            if let Some(rules) = self.program.dict_to_rules.get(dict_idx) {
                for &ri in rules {
                    aho.insert(ri);
                }
            }
        }

        for (field, header_name, transforms) in groups.keys() {
            let texts = field_texts(
                req,
                views,
                *field,
                header_name.as_deref(),
                FieldScope::All,
                transforms,
                cache,
            );
            for (hay, _, _) in texts {
                for dict_idx in self.program.matcher.find_all(&hay) {
                    if let Some(rules) = self.program.dict_to_rules.get(dict_idx) {
                        for &ri in rules {
                            aho.insert(ri);
                        }
                    }
                }
            }
        }

        let mut allow_set: HashSet<usize> = HashSet::new();
        for (ri, rule) in self.program.rules.iter().enumerate() {
            if rule.meta.action.is_allow() {
                allow_set.insert(ri);
            }
        }

        let static_asset = is_static_asset_uri(&req.uri);
        let suspicious = suspicious_for_deep_scan(req, views);
        let force_deep = matches!(mode, InspectMode::Deep) || inspect_path == InspectPath::Deep;
        let full_regex = force_deep;
        let deep_regex =
            force_deep || (!static_asset && suspicious) || is_cache_deception_probe_uri(&req.uri);

        let mut rest: HashSet<usize> = aho.iter().copied().collect();
        let use_cluster = !cluster_seed.is_empty();
        for &ri in &self.program.regex_rules {
            if use_cluster
                && !cluster_seed.contains(&ri)
                && !aho.contains(&ri)
                && !allow_set.contains(&ri)
            {
                continue;
            }
            if rest.contains(&ri) || allow_set.contains(&ri) {
                continue;
            }
            let when = &self.program.rules[ri].when;
            if deep_regex || is_cheap_regex_rule(when) {
                rest.insert(ri);
            }
        }

        for &ri in &self.program.signal_rules {
            rest.insert(ri);
        }

        let rest_v: Vec<usize> = rest
            .into_iter()
            .filter(|ri| !allow_set.contains(ri))
            .collect();

        if rest_v.is_empty()
            && suspicious
            && aho.is_empty()
            && !full_regex
            && !api_positive_lane
            && decode_attack_hint(views)
        {
            let mut fallback: Vec<usize> = cluster_seed.iter().copied().collect();
            for &ri in &self.program.regex_rules {
                if is_cheap_regex_rule(&self.program.rules[ri].when) {
                    fallback.push(ri);
                }
            }
            fallback.sort_unstable();
            fallback.dedup();
            if !fallback.is_empty() {
                return (fallback, 0);
            }
        }

        // 执行序：allow → Aho 命中 → 其余；强 L1 过阈后早退，避免高并发下 budget 超时漏检
        let mut allow_v: Vec<usize> = allow_set.iter().copied().collect();
        allow_v.sort_unstable();
        let mut aho_v: Vec<usize> = aho
            .iter()
            .copied()
            .filter(|ri| !allow_set.contains(ri))
            .filter(|ri| rule_ready_at_layer(&self.program, *ri, decode_layer, &allow_set))
            .collect();
        aho_v.sort_unstable();
        if api_positive_lane && inspect_path == InspectPath::Fast {
            let mut ordered = allow_v;
            ordered.extend(aho_v);
            let aho_seed = ordered.len();
            return (ordered, aho_seed);
        }
        let aho_set: HashSet<usize> = aho_v.iter().copied().collect();
        let mut tail_v: Vec<usize> = rest_v
            .into_iter()
            .filter(|ri| !aho_set.contains(ri))
            .filter(|ri| rule_ready_at_layer(&self.program, *ri, decode_layer, &allow_set))
            .collect();
        tail_v.sort_unstable();
        let mut ordered = allow_v;
        ordered.extend(aho_v);
        let aho_seed = ordered.len();
        ordered.extend(tail_v);
        (ordered, aho_seed)
    }

    pub(super) fn eval_one_rule(
        &self,
        ri: usize,
        req: &NativeRequest,
        views: &RequestViews,
        signals: &RequestSignals,
        cache: &mut FieldCache,
        budget: &mut InspectBudget,
    ) -> Result<Option<MatchedRule>, String> {
        if budget.check_time().is_err() {
            return Err(budget.reason().unwrap_or("max_inspect_ms").to_string());
        }
        let rule = &self.program.rules[ri];
        match eval_when(&rule.when, req, views, signals, cache, budget) {
            Ok(Some(hit)) => {
                let action = match rule.meta.action {
                    RuleAction::Block => "block",
                    RuleAction::Allow => "allow",
                    RuleAction::Observe | RuleAction::Log => "observe",
                };
                metrics_global().record_rule_hit(&rule.meta.id);
                Ok(Some(MatchedRule {
                    rule_id: rule.meta.id.clone(),
                    rule_name: rule.meta.name.clone(),
                    severity: rule.meta.severity.clone(),
                    score: rule.meta.score,
                    action: action.into(),
                    evidence: hit.evidence,
                    param_path: hit.param_path,
                    decode_chain: hit.decode_chain,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.reason.to_string()),
        }
    }
}
