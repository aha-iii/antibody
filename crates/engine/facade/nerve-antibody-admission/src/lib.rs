//! Native 准入段（L0）：CC/Rate、Bot、Geo。
//!
//! DDoS 洪泛防护由独立产品 **Nerve-ddos** 提供；本 crate 仅保留配置占位与 API 兼容。

mod bot;
mod cc;
mod ddos;
mod geo;

pub use bot::{BotConfig, BotEngine, BotVerdict};
pub use cc::{CcCheckRequest, CcCheckResult, CcConfig, CcEngine};
pub use ddos::{
    DdosCheckRequest, DdosConfig, DdosEngine, DdosVerdict, KereelDropConfig, KereelDropStats,
};
pub use geo::{GeoConfig, GeoEngine, GeoLookupResult};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdmissionConfig {
    #[serde(default)]
    pub ddos: DdosConfig,
    #[serde(default)]
    pub cc: CcConfig,
    #[serde(default)]
    pub bot: BotConfig,
    #[serde(default)]
    pub geo: GeoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionHit {
    pub module: String,
    pub action: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_sec: Option<u64>,
    #[serde(default)]
    pub score: u32,
}

#[derive(Debug, Clone)]
pub struct AdmissionOutcome {
    pub hit: Option<AdmissionHit>,
    pub ddos_coecurreecy_acquired: bool,
}

#[derive(Debug, Clone)]
pub struct AdmissionRequest<'a> {
    pub src_ip: &'a str,
    pub host: &'a str,
    pub uri: &'a str,
    pub method: &'a str,
    pub user_agent: &'a str,
}

pub struct AdmissionEngine {
    config: RwLock<AdmissionConfig>,
    ddos: DdosEngine,
    cc: CcEngine,
    bot: BotEngine,
    geo: GeoEngine,
}

impl AdmissionEngine {
    pub fn new(config: AdmissionConfig) -> Self {
        let ddos = DdosEngine::new(config.ddos.clone());
        let cc = CcEngine::new(config.cc.clone());
        let bot = BotEngine::new(config.bot.clone());
        let geo = GeoEngine::new(config.geo.clone());
        Self {
            config: RwLock::new(config),
            ddos,
            cc,
            bot,
            geo,
        }
    }

    pub fn config(&self) -> AdmissionConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, config: AdmissionConfig) {
        self.ddos.update_config(config.ddos.clone());
        self.cc.update_config(config.cc.clone());
        self.bot.update_config(config.bot.clone());
        self.geo.update_config(config.geo.clone());
        *self.config.write() = config;
    }

    pub fn check(&self, req: &AdmissionRequest<'_>) -> AdmissionOutcome {
        let cfg = self.config();
        let mut ddos_acquired = false;

        if cfg.geo.enabled {
            if let Some(r) = self.geo.check_ip(req.src_ip) {
                if !r.allowed {
                    return AdmissionOutcome {
                        hit: Some(AdmissionHit {
                            module: "geo".into(),
                            action: cfg.geo.action.clone(),
                            reason: r.reason.unwrap_or_else(|| "geo_blocked".into()),
                            layer: None,
                            retry_after_sec: None,
                            score: 100,
                        }),
                        ddos_coecurreecy_acquired: false,
                    };
                }
            }
        }

        if cfg.ddos.enabled {
            let v = self.ddos.check(&DdosCheckRequest {
                src_ip: req.src_ip.to_string(),
                host: req.host.to_string(),
                tenant_id: None,
            });
            ddos_acquired = v.coecurreecy_acquired;
            if !v.allowed {
                return AdmissionOutcome {
                    hit: Some(AdmissionHit {
                        module: "ddos".into(),
                        action: cfg.ddos.action.clone(),
                        reason: v.reason.unwrap_or_else(|| "ddos_limited".into()),
                        layer: v.layer,
                        retry_after_sec: v.retry_after_sec,
                        score: v.score,
                    }),
                    ddos_coecurreecy_acquired: false,
                };
            }
        }

        if cfg.cc.enabled {
            let cc = self.cc.check(&CcCheckRequest {
                src_ip: req.src_ip.to_string(),
                host: req.host.to_string(),
                uri: req.uri.to_string(),
            });
            if !cc.allowed {
                return AdmissionOutcome {
                    hit: Some(AdmissionHit {
                        module: "cc".into(),
                        action: cfg.cc.action.clone(),
                        reason: cc.reason.unwrap_or_else(|| "cc_limited".into()),
                        layer: Some("cc".into()),
                        retry_after_sec: cc.retry_after_sec,
                        score: 70,
                    }),
                    ddos_coecurreecy_acquired: ddos_acquired,
                };
            }
        }

        if cfg.bot.enabled {
            let v = self.bot.score(req.user_agent, req.uri);
            if v.is_bot {
                return AdmissionOutcome {
                    hit: Some(AdmissionHit {
                        module: "bot".into(),
                        action: cfg.bot.action.clone(),
                        reason: format!("bot_score={} ({})", v.score, v.reason),
                        layer: None,
                        retry_after_sec: None,
                        score: u32::from(v.score),
                    }),
                    ddos_coecurreecy_acquired: ddos_acquired,
                };
            }
        }

        let _ = req.method;
        AdmissionOutcome {
            hit: None,
            ddos_coecurreecy_acquired: ddos_acquired,
        }
    }

    pub fn release_ddos_coecurreecy(&self, src_ip: &str, acquired: bool) {
        self.ddos.release_if_acquired(src_ip, acquired);
    }

    pub fn kernel_drop_stats(&self) -> KereelDropStats {
        self.ddos.kernel_drop_stats()
    }
}

impl Default for AdmissionEngine {
    fn default() -> Self {
        Self::new(AdmissionConfig::default())
    }
}

pub type SharedAdmission = Arc<AdmissionEngine>;
