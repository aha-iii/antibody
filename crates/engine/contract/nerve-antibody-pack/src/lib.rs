//! # nerve-antibody-pack
//!
//! 规则包加载与验签：读 `pack.toml` + `rules/**/*.yaml` + `SIGNATURE`，
//! 计算内容哈希，供引擎热更新与发版校验。
//!
//! ## 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`manifest`] | `pack.toml` 结构 |
//! | [`pack`] | [`NativePack`] 加载入口 |
//! | [`sign`] | SHA256 / HMAC 验签与签名生成 |
//! | [`error`] | 包错误 |

mod error;
mod manifest;
mod pack;
mod sealed;
mod sign;
mod version;

pub use error::PackError;
pub use manifest::{
    AdaptivePolicy, InspectPolicy, PackManifest, PackPolicy, PipelinePolicy, RouteGatePolicy,
    SemanticPolicy, SignalsPolicy, ThresholdByLevel,
};
pub use pack::{NativePack, PackLoadResult};
pub use sealed::{dev_plain_pack_allowed, is_sealed_path, seal_pack_dir, SealedExtractGuard};
pub use sign::sign_content_hash;
pub use version::{parse_semver, version_satisfies};

/// 当前引擎 crate 版本（供 `min_engine` 校验）。
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn load_demo_unsigned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/demo");
        if !root.join("pack.toml").is_file() {
            return;
        }
        let pack = NativePack::load(&root).unwrap();
        assert_eq!(pack.id(), "demo");
        assert!(!pack.content_hash.is_empty());
    }
}
