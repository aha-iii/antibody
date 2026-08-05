//! 规则包加载入口。

use crate::error::PackError;
use crate::manifest::PackManifest;
use crate::sealed::{dev_plain_pack_allowed, extract_sealed, is_sealed_path, SealedExtractGuard};
use crate::sign::{hash_pack, verify_signature};
use nerve_antibody_dsl::{load_rule_file, NativeRule};
use std::fs;
use std::path::{Path, PathBuf};

/// 自动加载结果：明文目录或 sealed 解密后的临时目录。
pub struct PackLoadResult {
    pub pack: NativePack,
    /// sealed 解密临时目录；Drop 后自动清理。
    pub guard: Option<SealedExtractGuard>,
}

/// 已加载的规则包（内存态）。
#[derive(Debug, Clone)]
pub struct NativePack {
    /// 包根目录绝对/相对路径。
    pub root: PathBuf,
    /// 解析后的清单。
    pub manifest: PackManifest,
    /// 全部规则（未按强度过滤）。
    pub rules: Vec<NativeRule>,
    /// 内容哈希 hex（验签与 health 展示）。
    pub content_hash: String,
}

impl NativePack {
    /// 自动识别路径：生产环境优先 `.sealed` + 在线 License；开发可设 `NERVE_NATIVE_DEV_PACK=1` 加载明文目录。
    pub fn load_auto(path: impl AsRef<Path>) -> Result<PackLoadResult, PackError> {
        let path = path.as_ref();
        if is_sealed_path(path) {
            // refresh 失败时仍尝试 ensure（可用未过期缓存）
            let _ = nerve_antibody_license::refresh_license();
            let key = nerve_antibody_license::ensure_pack_key()
                .map_err(|e| PackError::License(e.to_string()))?;
            let guard = extract_sealed(path, &key)?;
            let pack = Self::load(&guard.root)?;
            return Ok(PackLoadResult {
                pack,
                guard: Some(guard),
            });
        }
        if path.is_dir() {
            if dev_plain_pack_allowed() {
                let pack = Self::load(path)?;
                return Ok(PackLoadResult {
                    pack,
                    guard: None,
                });
            }
            return Err(PackError::Msg(
                "plain pack directory disabled; use .sealed file or set NERVE_NATIVE_DEV_PACK=1 for development"
                    .into(),
            ));
        }
        Err(PackError::Msg(format!(
            "pack path not found: {}",
            path.display()
        )))
    }

    /// 从目录加载；HMAC 密钥读环境变量 `NERVE_NATIVE_PACK_KEY`（可空）。
    pub fn load(root: impl AsRef<Path>) -> Result<Self, PackError> {
        Self::load_with_key(root, std::env::var("NERVE_NATIVE_PACK_KEY").ok())
    }

    /// 显式传入 HMAC 密钥（测试 / 发版工具）。
    ///
    /// 目录结构要求：
    /// ```text
    /// pack.toml
    /// SIGNATURE
    /// rules/**/*.yaml   # 支持分类子目录，如 rules/01-sqli/<id>.yaml
    /// ```
    pub fn load_with_key(
        root: impl AsRef<Path>,
        hmac_key: Option<String>,
    ) -> Result<Self, PackError> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = root.join("pack.toml");
        if !manifest_path.is_file() {
            return Err(PackError::Msg(format!(
                "pack.toml not found: {}",
                manifest_path.display()
            )));
        }
        let manifest_raw = fs::read_to_string(&manifest_path)?;
        let manifest: PackManifest = toml::from_str(&manifest_raw)?;

        if !crate::version_satisfies(crate::ENGINE_VERSION, &manifest.min_engine) {
            return Err(PackError::Msg(format!(
                "pack `{}` requires min_engine >= {}, current engine is {}",
                manifest.id, manifest.min_engine, crate::ENGINE_VERSION
            )));
        }

        let rules_dir = root.join("rules");
        let mut rules = Vec::new();
        let mut rule_blobs: Vec<Vec<u8>> = Vec::new();
        if rules_dir.is_dir() {
            let mut files = Vec::new();
            collect_yaml_files(&rules_dir, &mut files)?;
            // 排序保证哈希与加载顺序稳定
            files.sort();
            for f in files {
                rule_blobs.push(fs::read(&f)?);
                rules.extend(
                    load_rule_file(&f)
                        .map_err(|e| PackError::Msg(format!("{}: {e}", f.display())))?,
                );
            }
        }
        if rules.is_empty() {
            return Err(PackError::Msg("pack has no rules".into()));
        }

        let content_hash = hash_pack(&manifest_raw, &rule_blobs);
        verify_signature(&root, &content_hash, hmac_key.as_deref())?;

        Ok(Self {
            root,
            manifest,
            rules,
            content_hash,
        })
    }

    /// 包版本。
    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// 包 ID。
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    /// 默认拦截评分阈值（兼容旧调用）。
    pub fn block_threshold(&self) -> u32 {
        self.manifest.policy.block_threshold
    }

    /// 按强度档取拦截阈值。
    pub fn threshold_for_level(&self, level: nerve_antibody_dsl::NativeLevel) -> u32 {
        self.manifest.policy.threshold_for(level.as_str())
    }

    /// 是否整包观察模式。
    pub fn observe_only(&self) -> bool {
        self.manifest.policy.observe_only
    }

    /// 包策略引用。
    pub fn policy(&self) -> &crate::manifest::PackPolicy {
        &self.manifest.policy
    }
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x == "yaml" || x == "yml")
        .unwrap_or(false)
}

/// 递归收集 `rules/` 下全部 yaml（含子目录）。
fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let p = ent.path();
        if p.is_dir() {
            collect_yaml_files(&p, out)?;
        } else if is_yaml(&p) {
            out.push(p);
        }
    }
    Ok(())
}
