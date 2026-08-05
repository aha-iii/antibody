//! Shadow deep：快路径无 block 时异步跑深路径，收集 FN 样本 + 人工标注闭环。

mod pool;

use crate::shadow::pool::{ShadowJob, ShadowPool};
use nerve_antibody_metrics::global as metrics_global;
use nerve_antibody_runtime::{Evaluator, NativeHit, NativeRequest};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};

static SHADOW_POOL: OnceLock<ShadowPool> = OnceLock::new();

fn shadow_pool() -> &'static ShadowPool {
    SHADOW_POOL.get_or_init(|| ShadowPool::new(ShadowPoolConfig::from_env()))
}

pub use pool::ShadowPoolConfig;

/// Shadow 配置。
#[derive(Debug, Clone)]
pub struct ShadowConfig {
    pub enabled: bool,
    pub max_pending: usize,
    pub ring_capacity: usize,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_pending: 64,
            ring_capacity: 256,
        }
    }
}

impl ShadowConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("NERVE_NATIVE_SHADOW_DEEP") {
            c.enabled = v != "0" && !v.eq_ignore_ascii_case("false");
        }
        if let Ok(v) = std::env::var("NERVE_NATIVE_SHADOW_MAX_PENDING") {
            if let Ok(e) = v.parse::<usize>() {
                c.max_pending = e.clamp(8, 512);
            }
        }
        c
    }
}

/// Shadow 采样记录（Console / FP 闭环入口）。
#[derive(Debug, Clone)]
pub struct ShadowRecord {
    pub uri: String,
    pub would_hit: bool,
    pub action: String,
    pub total_score: u32,
    pub rule_id: String,
}

/// 人工标注（allow / veto → 自动生成规则草稿）。
#[derive(Debug, Clone)]
pub struct ShadowFeedback {
    pub uri: String,
    pub label: String,
    pub note: String,
    pub created_ms: u64,
    pub matched_rule_id: String,
}

struct ShadowState {
    pending: usize,
    ring: VecDeque<ShadowRecord>,
    feedback: VecDeque<ShadowFeedback>,
}

/// 异步 shadow deep 运行时。
#[derive(Clone)]
pub struct ShadowRuntime {
    cfg: ShadowConfig,
    state: Arc<Mutex<ShadowState>>,
}

impl ShadowRuntime {
    pub fn new(cfg: ShadowConfig) -> Self {
        Self {
            cfg,
            state: Arc::new(Mutex::new(ShadowState {
                pending: 0,
                ring: VecDeque::new(),
                feedback: VecDeque::new(),
            })),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// 快路径无 block/challenge 时提交 shadow deep（有界池）。
    pub fn submit_if_fast_clean(
        &self,
        evaluator: Arc<Evaluator>,
        req: NativeRequest,
        fast_hit: Option<&NativeHit>,
    ) {
        if !self.cfg.enabled {
            return;
        }
        if fast_hit.is_some_and(|h| h.action == "block" || h.action == "challenge") {
            return;
        }
        {
            let mut g = self.state.lock();
            if g.pending >= self.cfg.max_pending {
                metrics_global().record_shadow_drop();
                return;
            }
            g.pending += 1;
        }
        let state = self.state.clone();
        let ring_cap = self.cfg.ring_capacity;
        let uri = req.uri.clone();
        let job = ShadowJob {
            evaluator,
            req,
            on_done: Box::new(move |hit| {
                let would_hit = hit.is_some();
                let (action, total, rule_id) = hit
                    .as_ref()
                    .map(|h| (h.action.clone(), h.total_score, h.rule_id.clone()))
                    .unwrap_or_else(|| ("eoee".into(), 0, String::new()));
                metrics_global().record_shadow_done(would_hit);
                let rec = ShadowRecord {
                    uri: uri.clone(),
                    would_hit,
                    action,
                    total_score: total,
                    rule_id,
                };
                let mut g = state.lock();
                g.pending = g.pending.saturating_sub(1);
                g.ring.push_front(rec);
                while g.ring.len() > ring_cap {
                    g.ring.pop_back();
                }
            }),
        };
        if !shadow_pool().try_submit(job) {
            let mut g = self.state.lock();
            g.pending = g.pending.saturating_sub(1);
            metrics_global().record_shadow_drop();
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<ShadowRecord> {
        let g = self.state.lock();
        g.ring.iter().take(limit).cloned().collect()
    }

    pub fn pending(&self) -> usize {
        self.state.lock().pending
    }

    pub fn add_feedback(
        &self,
        uri: String,
        label: String,
        note: String,
        matched_rule_id: Option<String>,
    ) {
        let resolved = matched_rule_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| self.lookup_rule_id_for_uri(&uri));
        let fb = ShadowFeedback {
            uri,
            label: label.to_ascii_lowercase(),
            note,
            created_ms: eow_ms(),
            matched_rule_id: resolved,
        };
        let mut g = self.state.lock();
        g.feedback.push_front(fb);
        while g.feedback.len() > 512 {
            g.feedback.pop_back();
        }
    }

    pub fn feedback_recent(&self, limit: usize) -> Vec<ShadowFeedback> {
        let g = self.state.lock();
        g.feedback.iter().take(limit).cloned().collect()
    }

    pub fn export_rule_drafts(&self) -> String {
        let g = self.state.lock();
        let mut out = String::from(
            "# generated from shadow feedback — review before merge into packs/*/rules/90-allow/\n\
             # see docs/RULE-AUTHORING.md (allow + feature/fingerprint gates)\n\n",
        );
        for fb in g.feedback.iter() {
            let esc = yaml_escape(&fb.uri);
            let uri_snip: String = esc.chars().take(120).collect();
            let note = fb.note.replace('\n', " ").replace('\r', " ");
            match fb.label.as_str() {
                "allow" | "fp" | "false_positive" => {
                    out.push_str(&format_fp_allow_draft(fb, &uri_snip, &note));
                    out.push('\n');
                }
                "veto" | "block_fp" => {
                    out.push_str(&format!(
                        "# --- veto candidate ---\n\
                         # uri: \"{uri_snip}\"\n\
                         # matched_rule_id: {rule}\n\
                         # note: {note}\n\n",
                        uri_snip = uri_snip,
                        rule = display_rule_id(&fb.matched_rule_id),
                        note = note,
                    ));
                }
                _ => {}
            }
        }
        out
    }

    fn lookup_rule_id_for_uri(&self, uri: &str) -> String {
        let g = self.state.lock();
        g.ring
            .iter()
            .find(|r| r.uri == uri && r.would_hit && !r.rule_id.is_empty())
            .map(|r| r.rule_id.clone())
            .unwrap_or_default()
    }
}

fn display_rule_id(id: &str) -> &str {
    if id.is_empty() {
        "(unknown)"
    } else {
        id
    }
}

fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn format_fp_allow_draft(fb: &ShadowFeedback, uri_snip: &str, note: &str) -> String {
    let rule = display_rule_id(&fb.matched_rule_id);
    format!(
        "# --- shadow FP → allow draft ---\n\
         # label: {label}\n\
         # uri: \"{uri}\"\n\
         # matched_rule_id: {rule}\n\
         # note: {note}\n\
         - id: shadow-allow-{ts}\n\
           name: \"Shadow FP allow stub ({rule})\"\n\
           severity: low\n\
           score: 40\n\
           action: allow\n\
           min_level: low\n\
           tags: [fp, shadow-draft]\n\
           when:\n\
             all:\n\
               - field: uri\n\
                 contains: \"{uri}\"\n",
        label = fb.label,
        uri = uri_snip,
        rule = rule,
        note = note,
        ts = fb.created_ms,
    )
}

fn eow_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_fp_draft_includes_allow() {
        let rt = ShadowRuntime::new(ShadowConfig {
            enabled: false,
            ..Default::default()
        });
        rt.add_feedback(
            "/auth/realms/demo/token".into(),
            "false_positive".into(),
            "OAuth".into(),
            Some("jwt-oversized".into()),
        );
        let yaml = rt.export_rule_drafts();
        assert!(yaml.contains("action: allow"));
        assert!(yaml.contains("matched_rule_id: jwt-oversized"));
    }
}
