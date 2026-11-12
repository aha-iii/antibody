//! 规则包加载与验签：读 `pack.toml` + `rules/**/*.yaml` + `SIGNATURE`，
//! 以及可选 `virtual-patches/`（仅 status=live 合入热路径），
//! 计算内容哈希，供引擎热更新与发版校验。
//!
//! ## 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`manifest`] | `pack.toml` 结构 |
//! | [`pack`] | [`NativePack`] 加载入口 |
//! | [`virtual_patch`] | CVE 虚拟补丁目录 |
//! | [`sign`] | SHA256 / HMAC 验签与签名生成 |
//! | [`error`] | 包错误 |

mod error;
mod manifest;
mod pack;
mod sealed;
mod sign;
mod version;
mod virtual_patch;
mod vp_channel;
mod vp_ingest;

pub use error::PackError;
pub use manifest::{
    AdaptivePolicy, EdgePipelinePolicy, FastPathPolicy, InspectPolicy, LevelProfile, LevelsPolicy,
    PackManifest, PackPolicy, PipelineByLevel, PipelineLevelBudget, PipelinePolicy,
    RouteGatePolicy, RoutePreviewPolicy, SemanticPolicy, SignalsPolicy, ThresholdByLevel,
};
pub use pack::{NativePack, PackLoadResult};
pub use sealed::{dev_plain_pack_allowed, is_sealed_path, seal_pack_dir, SealedExtractGuard};
pub use sign::sign_content_hash;
pub use version::{parse_semver, version_satisfies};
pub use virtual_patch::{
    find_cve_dir, list_virtual_patches, load_vp_rules_with_status, materialize_sandbox_pack,
    read_meta, virtual_patches_root, write_meta, VpEntry, VpMeta,
};
pub use vp_channel::{
    check_channel, load_channel_local_state, load_channel_manifest, resolve_artifact_path,
    resolve_channel_root, save_channel_local_state, ChannelCheckResult, ChannelLocalState,
    ChannelManifest,
};
pub use vp_ingest::{
    apply_feed_artifact, load_intel_bundle, materialize_intel_item, IntelBundle, IntelItem,
};

/// 当前引擎 crate 版本（供 `min_engine` 校验）。
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn load_demo_unsigned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/demo");
        if !root.join("pack.toml").is_file() {
            return;
        }
        let pack = NativePack::load(&root).unwrap();
        assert_eq!(pack.id(), "demo");
        assert!(!pack.content_hash.is_empty());
    }
}
