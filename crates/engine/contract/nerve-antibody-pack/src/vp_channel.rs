//! 虚拟补丁更新源：`channel.json` 指针 + 本地已装版本。
//!
//! `track` = 发版轨道（stable / urgent），不是 CVE 渠道商。

use crate::error::PackError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// 更新源根上的版本指针。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelManifest {
    pub pack_id: String,
    /// 发版轨道：`stable` | `urgent`（兼容旧字段名 `channel`）。
    #[serde(alias = "channel")]
    pub track: String,
    pub latest: ChannelLatest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLatest {
    pub version: String,
    #[serde(default)]
    pub content_hash: String,
    /// 相对更新源根的目录，或绝对/ file URL；内含 `virtual-patches/` 或 `intel.json`。
    #[serde(alias = "artifact_url")]
    pub artifact_path: String,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub cve_added: Vec<String>,
}

/// 节点本地已拉取版本。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelLocalState {
    pub pack_id: String,
    pub track: String,
    pub installed_version: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCheckResult {
    pub channel_url: String,
    pub track: String,
    pub remote_version: String,
    pub local_version: String,
    pub update_available: bool,
    pub cve_added: Vec<String>,
    pub artifact_path: String,
    pub published_at: Option<String>,
}

pub fn channel_state_path(packs_root: &Path) -> PathBuf {
    packs_root.join(".vp-channel-state.json")
}

pub fn load_channel_manifest(path: &Path) -> Result<ChannelManifest, PackError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw).map_err(|e| PackError::Msg(format!("channel.json: {e}")))?)
}

pub fn load_channel_local_state(packs_root: &Path) -> ChannelLocalState {
    let p = channel_state_path(packs_root);
    fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_channel_local_state(
    packs_root: &Path,
    state: &ChannelLocalState,
) -> Result<(), PackError> {
    let p = channel_state_path(packs_root);
    let raw = serde_json::to_string_pretty(state)
        .map_err(|e| PackError::Msg(format!("serialize channel state: {e}")))?;
    fs::write(p, raw)?;
    Ok(())
}

/// 解析 `NERVE_VP_CHANNEL_URL`：目录、`…/channel.json`、或 `file://`。
pub fn resolve_channel_root(url_or_path: &str) -> Result<PathBuf, PackError> {
    let s = url_or_path.trim();
    if s.is_empty() {
        return Err(PackError::Msg(
            "NERVE_VP_CHANNEL_URL empty; set to a local update-source directory".into(),
        ));
    }
    let path = if let Some(rest) = s.strip_prefix("file://") {
        PathBuf::from(rest)
    } else {
        PathBuf::from(s)
    };
    if path.is_file() && path.file_name().and_then(|n| n.to_str()) == Some("channel.json") {
        return path
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| PackError::Msg("invalid channel.json path".into()));
    }
    if path.is_dir() {
        return Ok(path);
    }
    Err(PackError::Msg(format!(
        "channel root not found (need local dir for P1): {}",
        path.display()
    )))
}

pub fn check_channel(
    channel_url: &str,
    packs_root: &Path,
) -> Result<ChannelCheckResult, PackError> {
    let root = resolve_channel_root(channel_url)?;
    let manifest = load_channel_manifest(&root.join("channel.json"))?;
    let local = load_channel_local_state(packs_root);
    let local_version = if local.pack_id == manifest.pack_id {
        local.installed_version
    } else {
        String::new()
    };
    let update_available = local_version != manifest.latest.version;
    let artifact = resolve_artifact_path(&root, &manifest.latest.artifact_path)?;
    Ok(ChannelCheckResult {
        channel_url: root.display().to_string(),
        track: manifest.track,
        remote_version: manifest.latest.version,
        local_version,
        update_available,
        cve_added: manifest.latest.cve_added,
        artifact_path: artifact.display().to_string(),
        published_at: manifest.latest.published_at,
    })
}

pub fn resolve_artifact_path(channel_root: &Path, artifact: &str) -> Result<PathBuf, PackError> {
    let a = artifact.trim();
    if a.is_empty() {
        return Err(PackError::Msg("artifact_path empty".into()));
    }
    if let Some(rest) = a.strip_prefix("file://") {
        return Ok(PathBuf::from(rest));
    }
    let p = PathBuf::from(a);
    if p.is_absolute() {
        return Ok(p);
    }
    Ok(channel_root.join(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn check_detects_update() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("src");
        fs::create_dir_all(root.join("bundle")).unwrap();
        let mut f = fs::File::create(root.join("channel.json")).unwrap();
        write!(
            f,
            r#"{{"pack_id":"vp-feed","track":"urgent","latest":{{"version":"1.0.1","artifact_path":"bundle/","cve_added":["CVE-2024-X"]}}}}"#
        )
        .unwrap();
        let packs = tmp.path().join("packs");
        fs::create_dir_all(&packs).unwrap();
        let r = check_channel(root.to_str().unwrap(), &packs).unwrap();
        assert!(r.update_available);
        assert_eq!(r.remote_version, "1.0.1");
    }
}
