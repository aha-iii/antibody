//! Native Engine 在线 License：激活后下发 pack 解密密钥（内存驻留，不落盘）。

mod error;

pub use error::LicenseError;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PRODUCT: &str = "nerve-antibody";

static SESSION: OnceLock<RwLock<Option<LicenseSession>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<LicenseSession>> {
    SESSION.get_or_init(|| RwLock::new(None))
}

/// 激活后的 License 会话。
#[derive(Debug, Clone)]
pub struct LicenseSession {
    pub license_id: String,
    pub pack_id: String,
    pub expires_at_ms: u64,
    pack_key: [u8; 32],
    pub machine_id: String,
}

/// 对外 License 状态（health / 运维）。
#[derive(Debug, Clone, Serialize)]
pub struct LicenseStatus {
    pub active: bool,
    pub license_id: String,
    pub pack_id: String,
    pub expires_at_ms: u64,
    pub machine_id: String,
    pub mode: String,
}

impl LicenseSession {
    pub fn pack_key(&self) -> [u8; 32] {
        self.pack_key
    }

    pub fn is_expired(&self) -> bool {
        now_ms() >= self.expires_at_ms
    }
}

/// 确保 License 已激活且未过期；返回 pack 解密密钥。
pub fn ensure_pack_key() -> Result<[u8; 32], LicenseError> {
    if license_dev_mode() {
        return dev_pack_key();
    }
    {
        let g = slot().read();
        if let Some(s) = g.as_ref() {
            if !s.is_expired() {
                return Ok(s.pack_key());
            }
        }
    }
    let session = activate_online()?;
    {
        let mut g = slot().write();
        *g = Some(session.clone());
    }
    Ok(session.pack_key())
}

/// 强制重新激活（reload pack 前可调用）。
pub fn refresh_license() -> Result<(), LicenseError> {
    if license_dev_mode() {
        return Ok(());
    }
    let session = activate_online()?;
    let mut g = slot().write();
    *g = Some(session);
    Ok(())
}

pub fn license_status() -> LicenseStatus {
    if license_dev_mode() {
        return LicenseStatus {
            active: true,
            license_id: "dev".into(),
            pack_id: "dev".into(),
            expires_at_ms: now_ms().saturating_add(86400_000 * 365),
            machine_id: machine_id(),
            mode: "dev".into(),
        };
    }
    let g = slot().read();
    if let Some(s) = g.as_ref() {
        return LicenseStatus {
            active: !s.is_expired(),
            license_id: s.license_id.clone(),
            pack_id: s.pack_id.clone(),
            expires_at_ms: s.expires_at_ms,
            machine_id: s.machine_id.clone(),
            mode: "online".into(),
        };
    }
    LicenseStatus {
        active: false,
        license_id: String::new(),
        pack_id: String::new(),
        expires_at_ms: 0,
        machine_id: machine_id(),
        mode: "online".into(),
    }
}

fn license_dev_mode() -> bool {
    matches!(
        std::env::var("NERVE_LICENSE_DEV").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn dev_pack_key() -> Result<[u8; 32], LicenseError> {
    let b64 = std::env::var("NERVE_LICENSE_PACK_KEY_B64").map_err(|_| {
        LicenseError::Config(
            "NERVE_LICENSE_DEV=1 requires NERVE_LICENSE_PACK_KEY_B64 (32-byte key)".into(),
        )
    })?;
    decode_key_b64(&b64)
}

#[derive(Serialize)]
struct ActivateRequest<'a> {
    license_key: &'a str,
    product: &'a str,
    machine_id: &'a str,
}

#[derive(Deserialize)]
struct ActivateResponse {
    status: String,
    #[serde(default)]
    license_id: String,
    #[serde(default)]
    pack_id: String,
    pack_key_b64: String,
    expires_at_ms: u64,
    #[serde(default)]
    message: String,
}

fn activate_online() -> Result<LicenseSession, LicenseError> {
    let license_key = std::env::var("NERVE_LICENSE_KEY").map_err(|_| {
        LicenseError::Config("NERVE_LICENSE_KEY is required for sealed pack".into())
    })?;
    if license_key.trim().is_empty() {
        return Err(LicenseError::Config("NERVE_LICENSE_KEY is empty".into()));
    }
    let url = std::env::var("NERVE_LICENSE_URL").unwrap_or_else(|_| {
        "https://license.nerve.local/v1/activate".into()
    });
    let machine_id = machine_id();
    let req = ActivateRequest {
        license_key: license_key.trim(),
        product: PRODUCT,
        machine_id: &machine_id,
    };
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(15))
        .send_json(req)
        .map_err(|e| LicenseError::Network(e.to_string()))?;
    if resp.status() != 200 {
        return Err(LicenseError::Rejected(format!(
            "license server HTTP {}",
            resp.status()
        )));
    }
    let body: ActivateResponse = resp
        .into_json()
        .map_err(|e| LicenseError::Network(format!("invalid license response: {e}")))?;
    if body.status != "ok" {
        return Err(LicenseError::Rejected(if body.message.is_empty() {
            "license activation rejected".into()
        } else {
            body.message
        }));
    }
    let pack_key = decode_key_b64(&body.pack_key_b64)?;
    Ok(LicenseSession {
        license_id: body.license_id,
        pack_id: body.pack_id,
        expires_at_ms: body.expires_at_ms,
        pack_key,
        machine_id,
    })
}

fn decode_key_b64(b64: &str) -> Result<[u8; 32], LicenseError> {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        b64.trim(),
    )
    .map_err(|e| LicenseError::Config(format!("invalid pack_key_b64: {e}")))?;
    if bytes.len() != 32 {
        return Err(LicenseError::Config(format!(
            "pack_key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// 稳定机器指纹（hostname + machine-id）。
pub fn machine_id() -> String {
    let mut h = Sha256::new();
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(v) = std::env::var(key) {
            h.update(v.as_bytes());
            break;
        }
    }
    if let Ok(mid) = std::fs::read_to_string("/etc/machine-id") {
        h.update(mid.trim().as_bytes());
    } else if let Ok(mid) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        h.update(mid.trim().as_bytes());
    }
    hex::encode(h.finalize())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
