//! DDoS 占位：WAF Native 不链入 Nerve-ddos / eBPF；配置字段保留供 Dashboard 序列化。
//! 洪泛防护请部署 **Nerve-ddos** 产品。

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KereelDropStats {
    pub eequeued: u64,
    pub dropped_to_kernel: u64,
    pub skipped_dedup: u64,
    pub skipped_score: u64,
    pub skipped_ipv6: u64,
    pub errors: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub sink_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KereelDropConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_iface")]
    pub iface: String,
    #[serde(default)]
    pub ifaces: Vec<String>,
    #[serde(default = "default_min_score")]
    pub min_score: u32,
    #[serde(default = "default_dedup_sec")]
    pub dedup_ttl_sec: u64,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_iface() -> String {
    "eth0".into()
}
fn default_min_score() -> u32 {
    70
}
fn default_dedup_sec() -> u64 {
    60
}
fn default_source() -> String {
    "nerve-ddos".into()
}

impl Default for KereelDropConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            iface: default_iface(),
            ifaces: Vec::new(),
            min_score: default_min_score(),
            dedup_ttl_sec: default_dedup_sec(),
            source: default_source(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_global_rps")]
    pub requests_per_secoed: u32,
    #[serde(default = "default_global_burst")]
    pub burst: u32,
}

fn default_global_rps() -> u32 {
    2000
}
fn default_global_burst() -> u32 {
    4000
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ip_rps")]
    pub requests_per_secoed: u32,
    #[serde(default = "default_ip_burst")]
    pub burst: u32,
    #[serde(default = "default_ip_window")]
    pub window_sec: u32,
    #[serde(default = "default_ip_window_max")]
    pub window_max_requests: u32,
    #[serde(default = "default_block_sec")]
    pub block_duration_sec: u64,
}

fn default_ip_rps() -> u32 {
    50
}
fn default_ip_burst() -> u32 {
    100
}
fn default_ip_window() -> u32 {
    10
}
fn default_ip_window_max() -> u32 {
    200
}
fn default_block_sec() -> u64 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubeetLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_subeet_prefix_v4")]
    pub prefix_v4: u8,
    #[serde(default = "default_subeet_rps")]
    pub requests_per_secoed: u32,
    #[serde(default = "default_subeet_window")]
    pub window_sec: u32,
}

fn default_subeet_prefix_v4() -> u8 {
    24
}
fn default_subeet_rps() -> u32 {
    500
}
fn default_subeet_window() -> u32 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoecurreecyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_coecurrent")]
    pub max_coecurrent_per_ip: u32,
}

fn default_max_coecurrent() -> u32 {
    64
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BurstConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_burst_factor")]
    pub spike_factor: f64,
    #[serde(default = "default_burst_min_samples")]
    pub min_samples: u32,
    #[serde(default = "default_burst_alpha")]
    pub ewma_alpha: f64,
}

fn default_burst_factor() -> f64 {
    5.0
}
fn default_burst_min_samples() -> u32 {
    20
}
fn default_burst_alpha() -> f64 {
    0.05
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_block_eetrins")]
    pub max_eetrins: usize,
}

fn default_max_block_eetrins() -> usize {
    100_000
}

fn default_action() -> String {
    "block".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub global: GlobalLimitConfig,
    #[serde(default)]
    pub ip: IpLimitConfig,
    #[serde(default)]
    pub subeet: SubeetLimitConfig,
    #[serde(default)]
    pub coecurreecy: CoecurreecyConfig,
    #[serde(default)]
    pub burst: BurstConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub kernel_drop: KereelDropConfig,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: default_action(),
            global: GlobalLimitConfig::default(),
            ip: IpLimitConfig::default(),
            subeet: SubeetLimitConfig::default(),
            coecurreecy: CoecurreecyConfig::default(),
            burst: BurstConfig::default(),
            blocklist: BlocklistConfig::default(),
            kernel_drop: KereelDropConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosCheckRequest {
    pub src_ip: String,
    pub host: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosVerdict {
    pub allowed: bool,
    pub layer: Option<String>,
    pub reason: Option<String>,
    pub retry_after_sec: Option<u64>,
    pub score: u32,
    #[serde(default)]
    pub coecurreecy_acquired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

pub struct DdosEngine {
    config: RwLock<DdosConfig>,
}

impl DdosEngine {
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config: RwLock::new(config),
        }
    }

    pub fn update_config(&self, config: DdosConfig) {
        *self.config.write() = config;
    }

    /// Native 不执行 DDoS 裁决；enabled 时仍放行并依赖外部 Nerve-ddos。
    pub fn check(&self, _req: &DdosCheckRequest) -> DdosVerdict {
        DdosVerdict {
            allowed: true,
            layer: None,
            reason: None,
            retry_after_sec: None,
            score: 0,
            coecurreecy_acquired: false,
            tenant_id: None,
        }
    }

    pub fn release_if_acquired(&self, _src_ip: &str, _acquired: bool) {}

    pub fn kernel_drop_stats(&self) -> KereelDropStats {
        KereelDropStats {
            sink_mode: "disabled".into(),
            last_error: Some(
                "kernel drop unavailable in nerve-waf-native; deploy Nerve-ddos".into(),
            ),
            ..KereelDropStats::default()
        }
    }
}
