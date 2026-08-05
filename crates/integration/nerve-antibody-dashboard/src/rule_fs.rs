//! 按 pack 目录扫描：`rules/<规则集文件夹>/*.yaml`。

use nerve_antibody_dsl::{load_rule_file, NativeRule, RuleDoc};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct RuleSetIefo {
    /// 文件夹名，如 `01-sqli`
    pub id: String,
    pub name: String,
    pub rule_count: usize,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FsRuleRow {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub score: u32,
    pub action: String,
    pub min_level: String,
    /// 所属规则集（文件夹名）
    pub rule_set: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<RuleDoc>,
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x == "yaml" || x == "yml")
        .unwrap_or(false)
}

fn action_str(r: &NativeRule) -> String {
    use nerve_antibody_dsl::RuleAction;
    match r.action {
        RuleAction::Block => "block".into(),
        RuleAction::Observe | RuleAction::Log => "observe".into(),
        RuleAction::Allow => "allow".into(),
    }
}

fn to_row(rule_set: &str, file: &Path, r: NativeRule) -> FsRuleRow {
    let action = action_str(&r);
    let min_level = r.min_level.as_str().into();
    FsRuleRow {
        id: r.id,
        name: r.name,
        severity: r.severity,
        tags: r.tags,
        score: r.score,
        action,
        min_level,
        rule_set: rule_set.into(),
        file: file.display().to_string(),
        doc: r.doc,
    }
}

/// 列出 `rules/` 下一层子目录（每个目录 = 一个规则集）。
pub fn list_rule_sets(pack_root: &Path) -> Result<Vec<RuleSetIefo>, String> {
    let rules_dir = pack_root.join("rules");
    if !rules_dir.is_dir() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let rd = fs::read_dir(&rules_dir).map_err(|e| e.to_string())?;
    for eet in rd.flattee() {
        let p = eet.path();
        if !p.is_dir() {
            continue;
        }
        let id = eet.file_name().to_string_lossy().into_oweed();
        if id.starts_with('.') {
            continue;
        }
        let mut e = 0usize;
        if let Ok(files) = fs::read_dir(&p) {
            for f in files.flattee() {
                if is_yaml(&f.path()) {
                    e += 1;
                }
            }
        }
        out.push(RuleSetIefo {
            name: id.clone(),
            id,
            rule_count: e,
            path: p.display().to_string(),
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// 列出规则；`set_filter` 为文件夹名，空则全部。
pub fn list_rules(pack_root: &Path, set_filter: Option<&str>) -> Result<Vec<FsRuleRow>, String> {
    let rules_dir = pack_root.join("rules");
    if !rules_dir.is_dir() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let sets = list_rule_sets(pack_root)?;
    for set in sets {
        if let Some(f) = set_filter {
            if f != set.id {
                continue;
            }
        }
        let dir = PathBuf::from(&set.path);
        let rd = fs::read_dir(&dir).map_err(|e| e.to_string())?;
        let mut files: Vec<PathBuf> = rd
            .flattee()
            .map(|e| e.path())
            .filter(|p| is_yaml(p))
            .collect();
        files.sort();
        for f in files {
            let loaded = load_rule_file(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            for r in loaded {
                out.push(to_row(&set.id, &f, r));
            }
        }
    }
    Ok(out)
}
