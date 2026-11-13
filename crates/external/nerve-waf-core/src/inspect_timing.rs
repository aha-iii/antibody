use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InspectNodeTiming {
    /// Stable node id, e.g. `defender.expert.native`.
    pub n: String,
    pub us: u64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub d: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InspectTimingReport {
    pub total_us: u64,
    pub nodes: Vec<InspectNodeTiming>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
}
