//! Map WAF inspect verdict to Nerve Packet Journey hops (see docs/PACKET-JOURNEY-STANDARD.md §5.2).

use crate::{InspectHit, InspectPhase, InspectVerdict, WafAction};
use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const WAF_PIPELINE_ID: &str = "waf-inspect-pipeline";
pub const WAF_PIPELINE_NAME: &str = "WAF 规则匹配链路";

#[derive(Debug, Clone)]
pub struct WafJourneyContext {
    pub trace_id: Option<String>,
    pub journey_id: Option<String>,
    pub session_id: Option<String>,
    pub parent_journey_id: Option<String>,
    pub site_id: String,
    pub src_ip: String,
    pub dst_host: String,
    pub dst_port: u16,
    pub method: String,
    pub uri: String,
    pub pod: Option<String>,
    pub namespace: Option<String>,
    pub source_detail: String,
}

#[derive(Serialize)]
struct HopBlock {
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn hop_action(wa: WafAction) -> &'static str {
    match wa {
        WafAction::Block | WafAction::Challenge => "deny",
        WafAction::Log => "inspect",
        WafAction::Allow => "pass",
    }
}

fn hop_event(wa: WafAction, blocked: bool) -> &'static str {
    if blocked {
        match wa {
            WafAction::Challenge => "waf_challenge",
            _ => "waf_block",
        }
    } else if wa == WafAction::Log {
        "waf_inspect"
    } else {
        "waf_pass"
    }
}

fn phase_label(phase: InspectPhase) -> &'static str {
    match phase {
        InspectPhase::PreAccess => "前置策略",
        InspectPhase::RequestHeaders => "请求头检测",
        InspectPhase::RequestBody => "请求体/参数",
        InspectPhase::RequestUpload => "文件上传",
        InspectPhase::ResponseHeaders => "响应头",
        InspectPhase::ResponseBody => "响应体",
        InspectPhase::Script => "自定义脚本",
        InspectPhase::Logging => "审计",
    }
}

fn phase_pass_summary(phase: InspectPhase) -> String {
    match phase {
        InspectPhase::PreAccess => "CC / Geo / Bot / 威胁情报前置检测通过".into(),
        InspectPhase::RequestHeaders => "请求头规则检测通过".into(),
        InspectPhase::RequestBody => "CRS / 语义 / 自定义规则检测通过".into(),
        InspectPhase::RequestUpload => "上传文件规则检测通过".into(),
        InspectPhase::ResponseHeaders => "响应头规则检测通过".into(),
        InspectPhase::ResponseBody => "响应体敏感内容检测通过".into(),
        InspectPhase::Script => "Lua / 插件脚本检测通过".into(),
        InspectPhase::Logging => "审计阶段".into(),
    }
}

fn hit_summary(hit: &InspectHit) -> String {
    let action_word = match hit.action {
        WafAction::Block => "拦截",
        WafAction::Challenge => "挑战验证",
        WafAction::Log => "记录",
        WafAction::Allow => "放行",
    };
    format!(
        "{} · 规则 #{} {} 命中{}；类别 {}；字段 {}；样本 {}",
        hit.rule_name,
        hit.rule_id,
        hit.severity,
        action_word,
        hit.category,
        hit.matched_field,
        truncate(&hit.payload_sample, 120)
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

fn base_metadata(
    ctx: &WafJourneyContext,
    extra: HashMap<String, String>,
) -> HashMap<String, String> {
    let mut m = extra;
    m.insert("hop_layer".into(), "security".into());
    m.insert("site_id".into(), ctx.site_id.clone());
    if let Some(j) = &ctx.journey_id {
        if !j.is_empty() {
            m.insert("journey_id".into(), j.clone());
        }
    }
    if let Some(s) = &ctx.session_id {
        if !s.is_empty() {
            m.insert("session_id".into(), s.clone());
        }
    }
    if let Some(p) = &ctx.parent_journey_id {
        if !p.is_empty() {
            m.insert("parent_journey_id".into(), p.clone());
        }
    }
    if !ctx.method.is_empty() {
        m.insert("http_method".into(), ctx.method.clone());
    }
    if !ctx.uri.is_empty() {
        m.insert("http_path".into(), ctx.uri.clone());
    }
    if !ctx.dst_host.is_empty() {
        m.insert("host".into(), ctx.dst_host.clone());
    }
    m
}

// Internal hop builder; parameters mirror the journey schema 1:1.
#[allow(clippy::too_many_arguments)]
fn build_hop(
    ctx: &WafJourneyContext,
    step_order: u32,
    step_id: &str,
    step_name: &str,
    event: &str,
    action: &str,
    summary: &str,
    transform: &str,
    block: Option<HopBlock>,
    extra_meta: HashMap<String, String>,
) -> Value {
    let mut meta = base_metadata(ctx, extra_meta);
    meta.insert("transform".into(), transform.into());
    meta.insert(
        "location".into(),
        format!(
            "WAF · {}{}",
            ctx.namespace
                .as_deref()
                .map(|n| format!("{n}/"))
                .unwrap_or_default(),
            ctx.pod.as_deref().unwrap_or("sidecar")
        ),
    );
    let time = Utc::now().to_rfc3339();
    let journey_id = ctx
        .journey_id
        .clone()
        .or_else(|| ctx.session_id.clone())
        .or_else(|| ctx.trace_id.clone());
    json!({
        "trace_id": ctx.trace_id,
        "journey_id": journey_id,
        "session_id": ctx.session_id,
        "hop_layer": "security",
        "station": "waf",
        "workflow_id": WAF_PIPELINE_ID,
        "workflow_name": WAF_PIPELINE_NAME,
        "step_id": step_id,
        "step_name": step_name,
        "step_order": step_order,
        "event": event,
        "action": action,
        "summary": summary,
        "block": block,
        "time": time,
        "five_tuple": {
            "src_ip": ctx.src_ip,
            "dst_ip": ctx.dst_host,
            "dst_port": ctx.dst_port,
            "protocol": "tcp"
        },
        "workload": {
            "pod": ctx.pod,
            "namespace": ctx.namespace,
        },
        "source": "nerve-waf",
        "source_detail": ctx.source_detail,
        "metadata": meta,
    })
}

fn hit_block(hit: &InspectHit) -> Option<HopBlock> {
    if hit.action != WafAction::Block && hit.action != WafAction::Challenge {
        return None;
    }
    let reason = if hit.action == WafAction::Challenge {
        "waf_challenge"
    } else {
        "waf_block"
    };
    Some(HopBlock {
        reason,
        rule_id: Some(hit.rule_id.clone()),
        rule_name: Some(hit.rule_name.clone()),
        detail: Some(format!(
            "category={} severity={} field={} sample={}",
            hit.category,
            hit.severity,
            hit.matched_field,
            truncate(&hit.payload_sample, 200)
        )),
    })
}

fn hit_metadata(hit: &InspectHit) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("category".into(), hit.category.clone());
    m.insert("rule_id".into(), hit.rule_id.clone());
    m.insert("rule_name".into(), hit.rule_name.clone());
    m.insert("severity".into(), hit.severity.clone());
    m.insert("matched_field".into(), hit.matched_field.clone());
    m.insert("inspect_phase".into(), hit.phase.as_str().into());
    if let Some(p) = &hit.plugin_name {
        m.insert("plugin_name".into(), p.clone());
    }
    if let Some(score) = hit.semantic_score {
        m.insert("semantic_score".into(), score.to_string());
    }
    m
}

/// Build security-layer hop list from pipeline results (rule-match chain; dynamic steps).
pub fn build_waf_journey_hops(ctx: &WafJourneyContext, verdict: &InspectVerdict) -> Vec<Value> {
    let hit = verdict.hits.first();
    let hit_phase = hit.map(|h| h.phase);
    let blocked = matches!(verdict.action, WafAction::Block | WafAction::Challenge);

    let mut hops = Vec::new();
    let phases = &verdict.phases;

    if phases.is_empty() {
        if let Some(h) = hit {
            hops.push(build_hop(
                ctx,
                1,
                h.phase.as_str(),
                phase_label(h.phase),
                hop_event(h.action, true),
                hop_action(h.action),
                &hit_summary(h),
                if blocked { "waf_block" } else { "waf_inspect" },
                hit_block(h),
                hit_metadata(h),
            ));
        } else {
            hops.push(build_hop(
                ctx,
                1,
                "waf_pass",
                "WAF 检测",
                "waf_pass",
                "pass",
                "WAF 全链路检测完成，未发现攻击特征",
                "waf_pass",
                None,
                HashMap::new(),
            ));
        }
        return hops;
    }

    for (idx, phase) in phases.iter().enumerate() {
        let order = (idx + 1) as u32;
        if Some(*phase) == hit_phase {
            if let Some(h) = hit {
                let transform = if blocked { "waf_block" } else { "waf_inspect" };
                hops.push(build_hop(
                    ctx,
                    order,
                    h.phase.as_str(),
                    phase_label(h.phase),
                    hop_event(h.action, blocked),
                    hop_action(h.action),
                    &hit_summary(h),
                    transform,
                    hit_block(h),
                    hit_metadata(h),
                ));
            }
        } else {
            hops.push(build_hop(
                ctx,
                order,
                phase.as_str(),
                phase_label(*phase),
                "waf_phase_pass",
                "pass",
                &phase_pass_summary(*phase),
                "forward",
                None,
                HashMap::from([("inspect_phase".into(), phase.as_str().into())]),
            ));
        }
    }

    hops
}
