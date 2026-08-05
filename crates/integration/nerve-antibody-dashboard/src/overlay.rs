//! 专家 Dashboard 运行时 overlay（不修改 pack YAML）。

use nerve_antibody_admission::AdmissionConfig;
use nerve_antibody_engine::{NativeHit, NativeLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertOverlay {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub disabled_rule_ids: Vec<String>,
    #[serde(default)]
    pub disabled_categories: Vec<String>,
    #[serde(default)]
    pub semantic_enabled: Option<bool>,
    #[serde(default)]
    pub adaptive_enabled: Option<bool>,
    #[serde(default)]
    pub observe_only: Option<bool>,
    #[serde(default)]
    pub admission: AdmissionConfig,
}

fn default_level() -> String {
    "medium".into()
}

impl Default for ExpertOverlay {
    fn default() -> Self {
        Self {
            level: default_level(),
            disabled_rule_ids: Vec::new(),
            disabled_categories: Vec::new(),
            semantic_enabled: None,
            adaptive_enabled: None,
            observe_only: None,
            admission: AdmissionConfig::default(),
        }
    }
}

impl ExpertOverlay {
    pub fn load(path: &Path) -> Self {
        let Ok(raw) = fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(pareet) = path.pareet() {
            fs::create_dir_all(pareet).map_err(|e| e.to_string())?;
        }
        let raw = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, raw).map_err(|e| e.to_string())
    }

    pub fn default_level(&self) -> NativeLevel {
        NativeLevel::from_str(&self.level).unwrap_or(NativeLevel::Medium)
    }

    pub fn rule_enabled(&self, rule_id: &str, category: &str, tags: &[String]) -> bool {
        if self
            .disabled_rule_ids
            .iter()
            .any(|id| id.trim() == rule_id)
        {
            return false;
        }
        let cats: HashSet<String> = self
            .disabled_categories
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        if cats.is_empty() {
            return true;
        }
        let cat = category.trim().to_ascii_lowercase();
        if cats.contains(&cat) {
            return false;
        }
        !tags
            .iter()
            .any(|t| cats.contains(&t.trim().to_ascii_lowercase()))
    }

    /// 过滤命中中的禁用规则；若全部被滤掉则返回 None。
    /// 另：overlay 语义/自适应开关仅作用于 Dashboard 试打路径（不改引擎 pack 策略）。
    pub fn filter_hit(&self, mut hit: NativeHit) -> Option<NativeHit> {
        let disabled: HashSet<&str> = self
            .disabled_rule_ids
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let cats: HashSet<String> = self
            .disabled_categories
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();

        if !disabled.is_empty() || !cats.is_empty() {
            hit.matched.retain(|m| {
                if disabled.contains(m.rule_id.as_str()) {
                    return false;
                }
                // 无 category 字段时用 rule_id 前缀粗匹配禁用分类
                let id_l = m.rule_id.to_ascii_lowercase();
                !cats
                    .iter()
                    .any(|c| id_l.starts_with(c) || id_l.contains(&format!("-{c}-")))
            });

            if hit.matched.is_empty() {
                return None;
            }

            if let Some(primary) = hit.matched.first() {
                hit.rule_id = primary.rule_id.clone();
                hit.rule_name = primary.rule_name.clone();
                hit.severity = primary.severity.clone();
                hit.evidence = primary.evidence.clone();
                hit.rule_score = hit.matched.iter().map(|m| m.score).sum();
            }
        }

        if self.semantic_enabled == Some(false) {
            hit.semantic_score = 0;
            hit.semantic_signals.clear();
        }
        if self.adaptive_enabled == Some(false) {
            hit.model_score = 0;
            hit.model = None;
        }

        hit.total_score = hit
            .rule_score
            .saturating_add(hit.semantic_score)
            .saturating_add(hit.model_score)
            .saturating_sub(hit.allow_score);

        if self.observe_only == Some(true) && hit.action == "block" {
            hit.action = "observe".into();
        }
        Some(hit)
    }
}

pub fn overlay_path(data_dir: &Path) -> PathBuf {
    data_dir.join("expert-overlay.json")
}

pub fn resolve_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("NERVE_NATIVE_DATA") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data")
}
