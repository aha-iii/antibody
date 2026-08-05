//! Geo：国家码名单 + IP 覆盖表（无 MMDB 时不误拦未知 IP）。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub block_countries: Vec<String>,
    #[serde(default)]
    pub allow_countries: Vec<String>,
    #[serde(default = "default_geo_action")]
    pub action: String,
    #[serde(default)]
    pub ip_country_overrides: Vec<IpCountryOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpCountryOverride {
    pub ip: String,
    pub country: String,
}

fn default_geo_action() -> String {
    "block".into()
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_countries: Vec::new(),
            allow_countries: Vec::new(),
            action: default_geo_action(),
            ip_country_overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLookupResult {
    pub ip: String,
    pub country: Option<String>,
    pub allowed: bool,
    pub reason: Option<String>,
}

pub struct GeoEngine {
    config: Mutex<GeoConfig>,
}

impl GeoEngine {
    pub fn new(config: GeoConfig) -> Self {
        Self {
            config: Mutex::new(config),
        }
    }

    pub fn update_config(&self, config: GeoConfig) {
        *self.config.lock() = config;
    }

    pub fn check_ip(&self, ip: &str) -> Option<GeoLookupResult> {
        let cfg = self.config.lock().clone();
        if !cfg.enabled {
            return None;
        }
        let ip_trim = ip.trim();
        if ip_trim.is_empty() || IpAddr::from_str(ip_trim).is_err() {
            return Some(GeoLookupResult {
                ip: ip_trim.into(),
                country: None,
                allowed: true,
                reason: Some("geo_skip_invalid_ip".into()),
            });
        }

        let country = cfg
            .ip_country_overrides
            .iter()
            .find(|o| o.ip.trim() == ip_trim)
            .map(|o| o.country.trim().to_uppercase());

        let Some(cc) = country else {
            return Some(GeoLookupResult {
                ip: ip_trim.into(),
                country: None,
                allowed: true,
                reason: Some("geo_unknown_allow".into()),
            });
        };

        if !cfg.allow_countries.is_empty() {
            let allow: Vec<String> = cfg
                .allow_countries
                .iter()
                .map(|c| c.trim().to_uppercase())
                .collect();
            if !allow.iter().any(|a| a == &cc) {
                return Some(GeoLookupResult {
                    ip: ip_trim.into(),
                    country: Some(cc),
                    allowed: false,
                    reason: Some("geo_not_in_allowlist".into()),
                });
            }
        }

        if !cfg.block_countries.is_empty() {
            let block: Vec<String> = cfg
                .block_countries
                .iter()
                .map(|c| c.trim().to_uppercase())
                .collect();
            if block.iter().any(|b| b == &cc) {
                return Some(GeoLookupResult {
                    ip: ip_trim.into(),
                    country: Some(cc),
                    allowed: false,
                    reason: Some("geo_in_blocklist".into()),
                });
            }
        }

        Some(GeoLookupResult {
            ip: ip_trim.into(),
            country: Some(cc),
            allowed: true,
            reason: None,
        })
    }
}
