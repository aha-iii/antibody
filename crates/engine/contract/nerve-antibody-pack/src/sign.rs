//! 内容哈希与签名校验。

use crate::error::PackError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

/// 对 `pack.toml` 原文 + 各规则文件字节做 SHA256，得到内容哈希（hex）。
pub(crate) fn hash_pack(manifest: &str, rules: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    h.update(manifest.as_bytes());
    for b in rules {
        h.update(b);
    }
    hex::encode(h.finalize())
}

/// 校验包根目录 `SIGNATURE` 文件。
///
/// 支持格式：
/// - `UNSIGNED-DEV` / `dev`：开发模式跳过
/// - `sha256:<hex>`：与内容哈希比对（仅完整性）
/// - `hmac-sha256:<hex>`：需环境变量 `NERVE_NATIVE_PACK_KEY`
pub(crate) fn verify_signature(
    root: &Path,
    content_hash: &str,
    hmac_key: Option<&str>,
) -> Result<(), PackError> {
    let sig_path = root.join("SIGNATURE");
    if !sig_path.is_file() {
        return Err(PackError::Signature(
            "missing SIGNATURE (use UNSIGNED-DEV for local packs)".into(),
        ));
    }
    let s = fs::read_to_string(&sig_path)?.trim().to_string();
    if s == "dev" || s.starts_with("UNSIGNED") {
        return Ok(());
    }
    if let Some(hex_sum) = s.strip_prefix("sha256:") {
        if hex_sum != content_hash {
            return Err(PackError::Signature("content hash mismatch".into()));
        }
        return Ok(());
    }
    if let Some(mac_hex) = s.strip_prefix("hmac-sha256:") {
        let key = hmac_key.ok_or_else(|| {
            PackError::Signature("NERVE_NATIVE_PACK_KEY required for hmac signature".into())
        })?;
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .map_err(|e| PackError::Signature(e.to_string()))?;
        mac.update(content_hash.as_bytes());
        let expect = hex::decode(mac_hex).map_err(|e| PackError::Signature(e.to_string()))?;
        mac.verify_slice(&expect)
            .map_err(|_| PackError::Signature("hmac verify failed".into()))?;
        return Ok(());
    }
    Err(PackError::Signature(format!(
        "unknown SIGNATURE format (use UNSIGNED-DEV / sha256: / hmac-sha256:): {s}"
    )))
}

/// 运营发版：对内容哈希生成 `hmac-sha256:...` 签名行。
pub fn sign_content_hash(content_hash: &str, key: &str) -> Result<String, PackError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| PackError::Signature(e.to_string()))?;
    mac.update(content_hash.as_bytes());
    Ok(format!(
        "hmac-sha256:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}
