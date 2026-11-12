//! 情报条目 → draft/sandbox CVE 目录（contains 模板，不自动 live）。

use crate::error::PackError;
use crate::virtual_patch::{write_meta, VpMeta};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// 归一化情报条目（来自 feed / 人工粘贴 / intel.json）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelItem {
    pub cve_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    /// 利用特征子串（query/uri/body contains）。
    pub match_contains: String,
    #[serde(default = "default_fields")]
    pub fields: Vec<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub description: String,
}

fn default_severity() -> String {
    "high".into()
}

fn default_fields() -> Vec<String> {
    vec!["query".into(), "uri".into(), "body".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelBundle {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub items: Vec<IntelItem>,
}

/// 将情报写成 pack 下 `virtual-patches/CVE-…/`，强制 `status=sandbox`。
pub fn materialize_intel_item(pack_root: &Path, item: &IntelItem) -> Result<PathBuf, PackError> {
    let cve = item.cve_id.trim();
    if cve.is_empty() {
        return Err(PackError::Msg("cve_id required".into()));
    }
    if !cve
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(PackError::Msg(format!("invalid cve_id: {cve}")));
    }
    let token = item.match_contains.trim();
    if token.is_empty() {
        return Err(PackError::Msg("match_contains required".into()));
    }
    if token.len() < 8 {
        return Err(PackError::Msg(
            "match_contains too short (min 8 chars) to reduce false positives".into(),
        ));
    }

    let dest = pack_root.join("virtual-patches").join(cve);
    if dest.exists() {
        fs::remove_dir_all(&dest)?;
    }
    fs::create_dir_all(dest.join("rules"))?;
    fs::create_dir_all(dest.join("samples/positive"))?;
    fs::create_dir_all(dest.join("samples/negative"))?;

    let meta = VpMeta {
        cve_id: cve.into(),
        title: if item.title.is_empty() {
            format!("VP {cve}")
        } else {
            item.title.clone()
        },
        description: item.description.clone(),
        severity: item.severity.clone(),
        status: "sandbox".into(),
        default_action: "block".into(),
        ttl_days: None,
        min_engine: Some("0.1.0".into()),
        content_hash: None,
        published_at: None,
        source: item.source.clone().or_else(|| Some("intel".into())),
        related_products: vec![],
    };
    write_meta(&dest, &meta)?;

    let rule_id = format!("vp-{}-1", cve.to_ascii_lowercase().replace('_', "-"));
    let fields = if item.fields.is_empty() {
        default_fields()
    } else {
        item.fields.clone()
    };
    let mut when = String::from("when:\n  any:\n");
    for f in &fields {
        let field = f.trim();
        if field.is_empty() {
            continue;
        }
        when.push_str(&format!(
            "    - field: {field}\n      contains: {token:?}\n"
        ));
    }
    let rule = format!(
        r#"id: {rule_id}
name: "VP {cve} (intel template)"
severity: {severity}
score: 40
action: block
min_level: low
tags: [virtual-patch, "cve:{cve}", intel-auto]
transforms: [url_decode_uni, lowercase]
{when}"#,
        severity = item.severity,
    );
    fs::write(dest.join("rules").join(format!("{rule_id}.yaml")), rule)?;

    let pos = format!(
        r#"id: sample-{cve}-block
name: positive probe
expect_action: block
min_level: low
request:
  method: GET
  host: example.com
  uri: /api/vp-intel
  query: "q={token}"
  headers: {{}}
  body: ""
"#
    );
    fs::write(
        dest.join("samples/positive")
            .join(format!("sample-{cve}-block.yaml")),
        pos,
    )?;

    let neg = format!(
        r#"id: sample-{cve}-pass
name: negative clean
expect_action: pass
min_level: low
request:
  method: GET
  host: example.com
  uri: /api/vp-intel
  query: "q=hello-world"
  headers: {{}}
  body: ""
"#
    );
    fs::write(
        dest.join("samples/negative")
            .join(format!("sample-{cve}-pass.yaml")),
        neg,
    )?;

    Ok(dest)
}

pub fn load_intel_bundle(path: &Path) -> Result<IntelBundle, PackError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw).map_err(|e| PackError::Msg(format!("intel.json: {e}")))?)
}

/// 从 artifact 目录导入：优先 `intel.json`，否则拷贝 `virtual-patches/`。
/// 所有写入条目强制 sandbox（从不自动 live）。
pub fn apply_feed_artifact(pack_root: &Path, artifact: &Path) -> Result<Vec<String>, PackError> {
    let mut imported = Vec::new();
    let intel_path = if artifact.is_file()
        && artifact
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".json"))
            .unwrap_or(false)
    {
        Some(artifact.to_path_buf())
    } else if artifact.join("intel.json").is_file() {
        Some(artifact.join("intel.json"))
    } else {
        None
    };

    if let Some(ip) = intel_path {
        let bundle = load_intel_bundle(&ip)?;
        for item in &bundle.items {
            materialize_intel_item(pack_root, item)?;
            imported.push(item.cve_id.clone());
        }
        return Ok(imported);
    }

    // 单个 CVE 目录
    if artifact.join("meta.toml").is_file() {
        let name = artifact
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| PackError::Msg("invalid CVE dir name".into()))?
            .to_string();
        let dest = pack_root.join("virtual-patches").join(&name);
        if dest.exists() {
            fs::remove_dir_all(&dest)?;
        }
        copy_dir(artifact, &dest)?;
        let mut meta = crate::virtual_patch::read_meta(&dest)?;
        meta.status = "sandbox".into();
        write_meta(&dest, &meta)?;
        imported.push(meta.cve_id);
        return Ok(imported);
    }

    let vp_root = if artifact.join("virtual-patches").is_dir() {
        artifact.join("virtual-patches")
    } else if artifact.is_dir() {
        artifact.to_path_buf()
    } else {
        return Err(PackError::Msg(format!(
            "artifact has neither intel.json nor virtual-patches: {}",
            artifact.display()
        )));
    };

    for ent in fs::read_dir(&vp_root)? {
        let ent = ent?;
        let p = ent.path();
        if !p.is_dir() || !p.join("meta.toml").is_file() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        let dest = pack_root.join("virtual-patches").join(&name);
        if dest.exists() {
            fs::remove_dir_all(&dest)?;
        }
        copy_dir(&p, &dest)?;
        let mut meta = crate::virtual_patch::read_meta(&dest)?;
        meta.status = "sandbox".into();
        write_meta(&dest, &meta)?;
        imported.push(meta.cve_id);
    }
    if imported.is_empty() {
        return Err(PackError::Msg("no CVE entries in artifact".into()));
    }
    Ok(imported)
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), PackError> {
    fs::create_dir_all(dst)?;
    for ent in fs::read_dir(src)? {
        let ent = ent?;
        let p = ent.path();
        let to = dst.join(ent.file_name());
        if p.is_dir() {
            copy_dir(&p, &to)?;
        } else {
            fs::copy(&p, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_sandbox_not_live() {
        let tmp = tempfile::tempdir().unwrap();
        let pack = tmp.path();
        fs::create_dir_all(pack.join("rules")).unwrap();
        let item = IntelItem {
            cve_id: "CVE-2024-AUTO01".into(),
            title: "auto".into(),
            severity: "critical".into(),
            match_contains: "nerve-vp-auto-token01".into(),
            fields: vec!["query".into()],
            source: Some("test".into()),
            description: String::new(),
        };
        let dir = materialize_intel_item(pack, &item).unwrap();
        let meta = crate::virtual_patch::read_meta(&dir).unwrap();
        assert_eq!(meta.status, "sandbox");
        assert!(dir.join("rules").read_dir().unwrap().next().is_some());
    }

    #[test]
    fn apply_channel_demo_intel_bundle() {
        let demo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/vp-channel-demo/bundle");
        if !demo.join("intel.json").is_file() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let imported = apply_feed_artifact(tmp.path(), &demo).unwrap();
        assert!(imported.iter().any(|c| c.contains("AUTO01")));
        let meta =
            crate::virtual_patch::read_meta(&tmp.path().join("virtual-patches").join(&imported[0]))
                .unwrap();
        assert_eq!(meta.status, "sandbox");
    }
}
