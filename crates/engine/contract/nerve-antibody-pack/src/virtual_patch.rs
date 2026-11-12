//! 虚拟补丁（CVE）目录扫描与 live 规则合并。

use crate::error::PackError;
use nerve_antibody_dsl::{load_rule_file, NativeRule};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// CVE 目录下 `meta.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpMeta {
    pub cve_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default = "default_action")]
    pub default_action: String,
    #[serde(default)]
    pub ttl_days: Option<u32>,
    #[serde(default)]
    pub min_engine: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub related_products: Vec<String>,
}

fn default_severity() -> String {
    "high".into()
}
fn default_status() -> String {
    "draft".into()
}
fn default_action() -> String {
    "block".into()
}

/// 列表用条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpEntry {
    pub cve_id: String,
    pub path: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub default_action: String,
    pub rule_count: usize,
    pub sample_count: usize,
    pub dir: PathBuf,
}

/// `virtual-patches` 根目录（若存在）。
pub fn virtual_patches_root(pack_root: &Path) -> PathBuf {
    pack_root.join("virtual-patches")
}

/// 扫描 pack 下全部 CVE 条目。
pub fn list_virtual_patches(pack_root: &Path) -> Result<Vec<VpEntry>, PackError> {
    let root = virtual_patches_root(pack_root);
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in fs::read_dir(&root)? {
        let ent = ent?;
        let p = ent.path();
        if !p.is_dir() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name == "index.toml" {
            continue;
        }
        let meta_path = p.join("meta.toml");
        if !meta_path.is_file() {
            continue;
        }
        let meta: VpMeta = toml::from_str(&fs::read_to_string(&meta_path)?)?;
        let mut rule_files = Vec::new();
        let rules_dir = p.join("rules");
        if rules_dir.is_dir() {
            collect_yaml(&rules_dir, &mut rule_files)?;
        }
        let mut sample_files = Vec::new();
        let samples_dir = p.join("samples");
        if samples_dir.is_dir() {
            collect_yaml(&samples_dir, &mut sample_files)?;
        }
        out.push(VpEntry {
            cve_id: meta.cve_id,
            path: name,
            title: meta.title,
            severity: meta.severity,
            status: meta.status,
            default_action: meta.default_action,
            rule_count: rule_files.len(),
            sample_count: sample_files.len(),
            dir: p,
        });
    }
    out.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
    Ok(out)
}

/// 加载指定 status 集合的 VP 规则（用于 live merge）。
pub fn load_vp_rules_with_status(
    pack_root: &Path,
    allowed_status: &[&str],
) -> Result<Vec<NativeRule>, PackError> {
    let entries = list_virtual_patches(pack_root)?;
    let mut rules = Vec::new();
    for e in entries {
        if !allowed_status
            .iter()
            .any(|s| e.status.eq_ignore_ascii_case(s))
        {
            continue;
        }
        let rules_dir = e.dir.join("rules");
        if !rules_dir.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        collect_yaml(&rules_dir, &mut files)?;
        files.sort();
        for f in files {
            let loaded = load_rule_file(&f)
                .map_err(|err| PackError::Msg(format!("{}: {err}", f.display())))?;
            for r in &loaded {
                if !r.id.starts_with("vp-") {
                    return Err(PackError::Msg(format!(
                        "virtual-patch rule id must start with vp-: {}",
                        r.id
                    )));
                }
            }
            rules.extend(loaded);
        }
    }
    Ok(rules)
}

/// 读取单条 meta。
pub fn read_meta(cve_dir: &Path) -> Result<VpMeta, PackError> {
    let p = cve_dir.join("meta.toml");
    let raw = fs::read_to_string(&p)?;
    Ok(toml::from_str(&raw)?)
}

/// 写回 meta（P0：显式字段，避免依赖 toml serialize feature）。
pub fn write_meta(cve_dir: &Path, meta: &VpMeta) -> Result<(), PackError> {
    let p = cve_dir.join("meta.toml");
    let mut raw = String::new();
    raw.push_str(&format!("cve_id = {:?}\n", meta.cve_id));
    raw.push_str(&format!("title = {:?}\n", meta.title));
    if !meta.description.is_empty() {
        raw.push_str(&format!("description = {:?}\n", meta.description));
    }
    raw.push_str(&format!("severity = {:?}\n", meta.severity));
    raw.push_str(&format!("status = {:?}\n", meta.status));
    raw.push_str(&format!("default_action = {:?}\n", meta.default_action));
    if let Some(d) = meta.ttl_days {
        raw.push_str(&format!("ttl_days = {d}\n"));
    }
    if let Some(ref v) = meta.min_engine {
        raw.push_str(&format!("min_engine = {v:?}\n"));
    }
    if let Some(ref v) = meta.source {
        raw.push_str(&format!("source = {v:?}\n"));
    }
    fs::write(p, raw)?;
    Ok(())
}

/// 查找 CVE 目录（按 cve_id 或目录名）。
pub fn find_cve_dir(pack_root: &Path, cve_id: &str) -> Result<Option<PathBuf>, PackError> {
    let entries = list_virtual_patches(pack_root)?;
    Ok(entries
        .into_iter()
        .find(|e| e.cve_id.eq_ignore_ascii_case(cve_id) || e.path.eq_ignore_ascii_case(cve_id))
        .map(|e| e.dir))
}

/// 为沙箱生成仅含指定 CVE 规则的临时 pack 目录。
pub fn materialize_sandbox_pack(
    pack_root: &Path,
    cve_id: &str,
    staging_root: &Path,
) -> Result<PathBuf, PackError> {
    let cve_dir = find_cve_dir(pack_root, cve_id)?
        .ok_or_else(|| PackError::Msg(format!("CVE not found: {cve_id}")))?;
    let meta = read_meta(&cve_dir)?;
    let out = staging_root.join(format!("sandbox-{}", meta.cve_id.replace('/', "_")));
    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    fs::create_dir_all(out.join("rules"))?;
    let pack_toml = format!(
        r#"id = "vp-sandbox-{}"
version = "0.0.1"
name = "VP sandbox {}"
min_engine = "0.1.0"

[policy]
block_threshold = 40
observe_only = true
"#,
        meta.cve_id, meta.cve_id
    );
    fs::write(out.join("pack.toml"), pack_toml)?;
    let src_rules = cve_dir.join("rules");
    if src_rules.is_dir() {
        copy_dir_yaml(&src_rules, &out.join("rules"))?;
    }
    Ok(out)
}

fn copy_dir_yaml(src: &Path, dst: &Path) -> Result<(), PackError> {
    fs::create_dir_all(dst)?;
    for ent in fs::read_dir(src)? {
        let ent = ent?;
        let p = ent.path();
        if p.is_dir() {
            copy_dir_yaml(&p, &dst.join(ent.file_name()))?;
        } else if is_yaml(&p) {
            fs::copy(&p, dst.join(ent.file_name()))?;
        }
    }
    Ok(())
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x == "yaml" || x == "yml")
        .unwrap_or(false)
}

fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let p = ent.path();
        if p.is_dir() {
            collect_yaml(&p, out)?;
        } else if is_yaml(&p) {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn baseline() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline")
    }

    #[test]
    fn list_baseline_vp_fixture_if_present() {
        let root = baseline();
        if !virtual_patches_root(&root).is_dir() {
            return;
        }
        let list = list_virtual_patches(&root).unwrap();
        assert!(
            list.iter()
                .any(|e| e.cve_id.contains("DEMO") || e.cve_id.starts_with("CVE-")),
            "expected fixture CVE in virtual-patches"
        );
    }

    #[test]
    fn fixture_sandbox_not_in_live_merge() {
        let root = baseline();
        if !virtual_patches_root(&root).is_dir() {
            return;
        }
        let live = load_vp_rules_with_status(&root, &["live"]).unwrap();
        assert!(
            !live.iter().any(|r| r.id.contains("demo01")),
            "sandbox fixture must not merge as live"
        );
        let sand = load_vp_rules_with_status(&root, &["sandbox"]).unwrap();
        assert!(
            sand.iter()
                .any(|r| r.id.starts_with("vp-") && r.id.contains("demo01")),
            "expected sandbox VP rule"
        );
    }

    #[test]
    fn materialize_sandbox_pack_has_vp_rules() {
        let root = baseline();
        if !virtual_patches_root(&root).is_dir() {
            return;
        }
        let staging = tempfile::tempdir().unwrap();
        let sand = materialize_sandbox_pack(&root, "CVE-2024-DEMO01", staging.path()).unwrap();
        assert!(sand.join("pack.toml").is_file());
        assert!(sand.join("rules").is_dir());
        let mut files = Vec::new();
        collect_yaml(&sand.join("rules"), &mut files).unwrap();
        assert!(!files.is_empty());
    }
}
