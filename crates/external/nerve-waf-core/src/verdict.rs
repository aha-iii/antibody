use crate::{InspectPhase, InspectTimingReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Log,
    Block,
    Challenge,
}

impl WafAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Log => "log",
            Self::Block => "block",
            Self::Challenge => "challenge",
        }
    }

    pub fn from_l7_action(s: &str) -> Self {
        match s {
            "block" => Self::Block,
            "challenge" => Self::Challenge,
            "log" | "detect" => Self::Log,
            _ => Self::Allow,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectHit {
    pub phase: InspectPhase,
    pub action: WafAction,
    pub category: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub matched_field: String,
    pub payload_sample: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engines: Option<Vec<String>>,
    /// Pipeline segment: semantic / expert / core / custom / pre_access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection_stage: Option<String>,
    /// Rule set: libinjection / expert-crs / l7-json / custom:{id} …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_set: Option<String>,
}

impl InspectHit {
    pub fn with_protection_origin(mut self, stage: &str, rule_set: &str) -> Self {
        self.protection_stage = Some(stage.into());
        if self.rule_set.as_deref().unwrap_or("").is_empty() {
            self.rule_set = Some(rule_set.into());
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectVerdict {
    pub allowed: bool,
    pub action: WafAction,
    #[serde(default)]
    pub hits: Vec<InspectHit>,
    #[serde(default)]
    pub phases: Vec<InspectPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<InspectTimingReport>,
}

impl InspectVerdict {
    pub fn pass() -> Self {
        Self {
            allowed: true,
            action: WafAction::Allow,
            hits: Vec::new(),
            phases: Vec::new(),
            timing: None,
        }
    }

    pub fn from_hit(hit: InspectHit) -> Self {
        let allowed = hit.action != WafAction::Block;
        let action = hit.action;
        Self {
            allowed,
            action,
            hits: vec![hit],
            phases: Vec::new(),
            timing: None,
        }
    }
}
