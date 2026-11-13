use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::InspectPhase;

/// Single HTTP inspect transaction context (simplified ModSecurity Transaction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafTransaction {
    pub method: String,
    pub host: String,
    pub uri: String,
    pub headers: String,
    pub body: String,
    pub src_ip: String,
    pub user_agent: String,
    #[serde(default = "default_site")]
    pub site_id: String,
    #[serde(default)]
    pub phases_run: Vec<InspectPhase>,
    pub started_at: DateTime<Utc>,
}

fn default_site() -> String {
    "default".into()
}

impl WafTransaction {
    pub fn new(
        method: impl Into<String>,
        host: impl Into<String>,
        uri: impl Into<String>,
        headers: impl Into<String>,
        body: impl Into<String>,
        src_ip: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            host: host.into(),
            uri: uri.into(),
            headers: headers.into(),
            body: body.into(),
            src_ip: src_ip.into(),
            user_agent: user_agent.into(),
            site_id: default_site(),
            phases_run: Vec::new(),
            started_at: Utc::now(),
        }
    }

    pub fn mark_phase(&mut self, phase: InspectPhase) {
        if !self.phases_run.contains(&phase) {
            self.phases_run.push(phase);
        }
    }
}
