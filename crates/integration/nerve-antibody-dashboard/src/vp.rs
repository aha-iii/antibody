//! 虚拟补丁（CVE）API：列表 / 沙箱 / 晋升 / 回滚 / 导入 / channel / 情报 ingest。

use crate::{ApiError, AppState};
use axum::extract::State;
use axum::Json;
use nerve_antibody_pack::{
    apply_feed_artifact, check_channel, find_cve_dir, list_virtual_patches,
    load_channel_manifest, materialize_intel_item, materialize_sandbox_pack, read_meta,
    resolve_artifact_path, resolve_channel_root, save_channel_local_state, write_meta,
    ChannelCheckResult, ChannelLocalState, IntelItem, VpEntry,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use tracing::info;

fn pack_dir(st: &AppState, pack_name: &str) -> Result<PathBuf, ApiError> {
    let name = pack_name.trim();
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err(ApiError::bad("invalid pack name"));
    }
    let dir = st.packs_root.join(name);
    if !dir.join("pack.toml").is_file() {
        return Err(ApiError::bad(format!("pack not found: {name}")));
    }
    Ok(dir)
}

async fn current_pack_dir(st: &AppState) -> Result<PathBuf, ApiError> {
    let name = st.current_pack.read().await.clone();
    pack_dir(st, &name)
}

/// `NERVE_VP_CHANNEL_URL`，未设则用仓库内 `packs/vp-channel-demo`。
fn resolve_channel_url(st: &AppState) -> Result<String, ApiError> {
    if let Ok(u) = std::env::var("NERVE_VP_CHANNEL_URL") {
        let t = u.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    let demo = st.packs_root.join("vp-channel-demo");
    if demo.join("channel.json").is_file() {
        return Ok(demo.display().to_string());
    }
    Err(ApiError::bad(
        "set NERVE_VP_CHANNEL_URL to a local update-source directory (with channel.json)",
    ))
}

async fn mount_sandbox_for(st: &AppState, root: &FsPath, cve: &str) -> Result<(), ApiError> {
    let staging = st.packs_root.join(".vp-staging");
    fs::create_dir_all(&staging).map_err(|e| ApiError::bad(e.to_string()))?;
    let sand = materialize_sandbox_pack(root, cve, &staging)
        .map_err(|e| ApiError::bad(e.to_string()))?;
    info!(path = %sand.display(), cve, "auto-mount VP sandbox");
    st.engine
        .mount_sandbox(&sand)
        .map_err(|e| ApiError::bad(e.to_string()))?;
    if let Some(dir) = find_cve_dir(root, cve).map_err(|e| ApiError::bad(e.to_string()))? {
        let mut meta = read_meta(&dir).map_err(|e| ApiError::bad(e.to_string()))?;
        if meta.status.eq_ignore_ascii_case("draft") {
            meta.status = "sandbox".into();
            write_meta(&dir, &meta).map_err(|e| ApiError::bad(e.to_string()))?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
pub struct VpListOut {
    pub pack: String,
    pub items: Vec<VpEntryDto>,
}

#[derive(Serialize)]
pub struct VpEntryDto {
    pub cve_id: String,
    pub path: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub default_action: String,
    pub rule_count: usize,
    pub sample_count: usize,
}

impl From<VpEntry> for VpEntryDto {
    fn from(e: VpEntry) -> Self {
        Self {
            cve_id: e.cve_id,
            path: e.path,
            title: e.title,
            severity: e.severity,
            status: e.status,
            default_action: e.default_action,
            rule_count: e.rule_count,
            sample_count: e.sample_count,
        }
    }
}

pub async fn api_vp_list(
    State(st): State<Arc<AppState>>,
) -> Result<Json<VpListOut>, ApiError> {
    let pack = st.current_pack.read().await.clone();
    let root = current_pack_dir(&st).await?;
    let items = list_virtual_patches(&root)
        .map_err(|e| ApiError::bad(e.to_string()))?
        .into_iter()
        .map(VpEntryDto::from)
        .collect();
    Ok(Json(VpListOut { pack, items }))
}

#[derive(Serialize)]
pub struct VpStatusOut {
    pub pack: String,
    pub pack_version: String,
    pub rule_count: usize,
    pub sandbox_mounted: bool,
    pub sandbox_pack_id: Option<String>,
    pub vp_live_count: usize,
    pub vp_total: usize,
}

pub async fn api_vp_status(
    State(st): State<Arc<AppState>>,
) -> Result<Json<VpStatusOut>, ApiError> {
    let pack = st.current_pack.read().await.clone();
    let root = current_pack_dir(&st).await?;
    let items = list_virtual_patches(&root).map_err(|e| ApiError::bad(e.to_string()))?;
    let vp_live_count = items
        .iter()
        .filter(|e| e.status.eq_ignore_ascii_case("live"))
        .count();
    let h = st.engine.health();
    Ok(Json(VpStatusOut {
        pack,
        pack_version: h.pack_version,
        rule_count: h.rule_count,
        sandbox_mounted: h.sandbox_mounted,
        sandbox_pack_id: h.sandbox_pack_id,
        vp_live_count,
        vp_total: items.len(),
    }))
}

#[derive(Deserialize)]
pub struct VpCveBody {
    pub cve_id: String,
}

pub async fn api_vp_sandbox(
    State(st): State<Arc<AppState>>,
    Json(body): Json<VpCveBody>,
) -> Result<Json<VpStatusOut>, ApiError> {
    let cve = body.cve_id.trim();
    if cve.is_empty() {
        return Err(ApiError::bad("cve_id required"));
    }
    let root = current_pack_dir(&st).await?;
    mount_sandbox_for(&st, &root, cve).await?;
    api_vp_status(State(st)).await
}

pub async fn api_vp_promote(
    State(st): State<Arc<AppState>>,
    Json(body): Json<VpCveBody>,
) -> Result<Json<VpStatusOut>, ApiError> {
    let cve = body.cve_id.trim();
    if cve.is_empty() {
        return Err(ApiError::bad("cve_id required"));
    }
    let pack_name = st.current_pack.read().await.clone();
    let root = pack_dir(&st, &pack_name)?;
    let dir = find_cve_dir(&root, cve)
        .map_err(|e| ApiError::bad(e.to_string()))?
        .ok_or_else(|| ApiError::bad(format!("CVE not found: {cve}")))?;
    let mut meta = read_meta(&dir).map_err(|e| ApiError::bad(e.to_string()))?;
    meta.status = "live".into();
    write_meta(&dir, &meta).map_err(|e| ApiError::bad(e.to_string()))?;
    info!(cve, pack = %pack_name, "VP promote → live + reload");
    st.engine
        .reload(Some(root.as_path()))
        .map_err(|e| ApiError::bad(e.to_string()))?;
    st.engine.unmount_sandbox();
    api_vp_status(State(st)).await
}

pub async fn api_vp_rollback(
    State(st): State<Arc<AppState>>,
    Json(body): Json<VpCveBody>,
) -> Result<Json<VpStatusOut>, ApiError> {
    let cve = body.cve_id.trim();
    if cve.is_empty() {
        return Err(ApiError::bad("cve_id required"));
    }
    let pack_name = st.current_pack.read().await.clone();
    let root = pack_dir(&st, &pack_name)?;
    let dir = find_cve_dir(&root, cve)
        .map_err(|e| ApiError::bad(e.to_string()))?
        .ok_or_else(|| ApiError::bad(format!("CVE not found: {cve}")))?;
    let mut meta = read_meta(&dir).map_err(|e| ApiError::bad(e.to_string()))?;
    meta.status = "retired".into();
    write_meta(&dir, &meta).map_err(|e| ApiError::bad(e.to_string()))?;
    info!(cve, pack = %pack_name, "VP rollback → retired + reload");
    st.engine
        .reload(Some(root.as_path()))
        .map_err(|e| ApiError::bad(e.to_string()))?;
    api_vp_status(State(st)).await
}

#[derive(Deserialize)]
pub struct VpImportBody {
    /// 源目录：含 CVE-*/meta.toml 的 virtual-patches 根，或单个 CVE 目录 / intel.json。
    pub source_path: String,
}

/// 离线导入：拷进当前 pack；强制 status=sandbox（不自动 live）。
pub async fn api_vp_import(
    State(st): State<Arc<AppState>>,
    Json(body): Json<VpImportBody>,
) -> Result<Json<VpListOut>, ApiError> {
    let src = PathBuf::from(body.source_path.trim());
    if !src.exists() {
        return Err(ApiError::bad(format!("source not found: {}", src.display())));
    }
    let pack_name = st.current_pack.read().await.clone();
    let root = pack_dir(&st, &pack_name)?;
    let imported = apply_feed_artifact(&root, &src).map_err(|e| ApiError::bad(e.to_string()))?;
    info!(?imported, "VP import → sandbox");
    if let Some(cve) = imported.first() {
        let _ = mount_sandbox_for(&st, &root, cve).await;
    }
    api_vp_list(State(st)).await
}

pub async fn api_vp_updates_check(
    State(st): State<Arc<AppState>>,
) -> Result<Json<ChannelCheckResult>, ApiError> {
    let url = resolve_channel_url(&st)?;
    let r = check_channel(&url, &st.packs_root).map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(r))
}

#[derive(Serialize)]
pub struct VpFetchOut {
    pub check: ChannelCheckResult,
    pub imported: Vec<String>,
    pub sandbox_cve: Option<String>,
    pub promoted_live: bool,
}

/// 拉取更新源 artifact → 落盘 sandbox → 自动挂沙箱；**永不自动 promote live**。
pub async fn api_vp_updates_fetch(
    State(st): State<Arc<AppState>>,
) -> Result<Json<VpFetchOut>, ApiError> {
    let url = resolve_channel_url(&st)?;
    let check = check_channel(&url, &st.packs_root).map_err(|e| ApiError::bad(e.to_string()))?;
    let channel_root = resolve_channel_root(&url).map_err(|e| ApiError::bad(e.to_string()))?;
    let artifact = PathBuf::from(&check.artifact_path);
    let artifact = if artifact.exists() {
        artifact
    } else {
        resolve_artifact_path(&channel_root, &check.artifact_path)
            .map_err(|e| ApiError::bad(e.to_string()))?
    };
    let root = current_pack_dir(&st).await?;
    let imported =
        apply_feed_artifact(&root, &artifact).map_err(|e| ApiError::bad(e.to_string()))?;
    info!(
        version = %check.remote_version,
        ?imported,
        "VP fetch applied (sandbox only)"
    );

    let sandbox_cve = imported.first().cloned();
    if let Some(ref cve) = sandbox_cve {
        mount_sandbox_for(&st, &root, cve).await?;
    }

    let mut state = ChannelLocalState {
        pack_id: "vp-feed".into(),
        track: check.track.clone(),
        installed_version: check.remote_version.clone(),
        updated_at: check.published_at.clone(),
    };
    if let Ok(m) = load_channel_manifest(&channel_root.join("channel.json")) {
        state.pack_id = m.pack_id;
    }
    save_channel_local_state(&st.packs_root, &state).map_err(|e| ApiError::bad(e.to_string()))?;

    Ok(Json(VpFetchOut {
        check,
        imported,
        sandbox_cve,
        promoted_live: false,
    }))
}

/// 单条情报 → sandbox CVE（模板规则）。
pub async fn api_vp_ingest(
    State(st): State<Arc<AppState>>,
    Json(item): Json<IntelItem>,
) -> Result<Json<VpListOut>, ApiError> {
    let root = current_pack_dir(&st).await?;
    let dir =
        materialize_intel_item(&root, &item).map_err(|e| ApiError::bad(e.to_string()))?;
    info!(path = %dir.display(), cve = %item.cve_id, "intel ingest → sandbox");
    let _ = mount_sandbox_for(&st, &root, &item.cve_id).await;
    api_vp_list(State(st)).await
}

/// 探测请求是否命中（便于 UI 冒烟）。
#[derive(Deserialize)]
pub struct VpProbeBody {
    #[serde(default = "default_probe_q")]
    pub query: String,
}

fn default_probe_q() -> String {
    "q=nerve-vp-probe-demo01".into()
}

#[derive(Serialize)]
pub struct VpProbeOut {
    pub action: String,
    pub rule_id: String,
    pub inspect_path: String,
}

pub async fn api_vp_probe(
    State(st): State<Arc<AppState>>,
    Json(body): Json<VpProbeBody>,
) -> Result<Json<VpProbeOut>, ApiError> {
    use nerve_antibody_engine::{NativeLevel, NativeRequest};
    let req = NativeRequest {
        method: "GET".into(),
        host: "example.com".into(),
        uri: "/api/vp-demo".into(),
        query: body.query,
        headers: Default::default(),
        body: "".into(),
        ..Default::default()
    };
    let hit = st
        .engine
        .inspect(&req, NativeLevel::Medium)
        .map_err(|e| ApiError::bad(e.to_string()))?;
    Ok(Json(VpProbeOut {
        action: hit
            .as_ref()
            .map(|h| h.action.clone())
            .unwrap_or_else(|| "pass".into()),
        rule_id: hit
            .as_ref()
            .map(|h| h.rule_id.clone())
            .unwrap_or_default(),
        inspect_path: hit
            .as_ref()
            .map(|h| h.inspect_path.clone())
            .unwrap_or_default(),
    }))
}
