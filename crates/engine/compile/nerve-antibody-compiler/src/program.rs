//! 可执行 Program 与可落盘 Artifact。

use crate::clusters::build_field_clusters;
use crate::decode_layers::rule_min_decode_layer;
use crate::error::CompileError;
use crate::ir::{
    CondExec, CondIr, PredExec, PredIr, RuleExec, RuleIr, RuleMeta, WhenExec, WhenIr, WhenNodeExec,
    WhenNodeIr,
};
use nerve_antibody_accel::{self, MultiMatcher};
use nerve_antibody_dsl::NativeLevel;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// 可落盘的编译产物（不含 Regex 运行时对象，JSON 友好）。
///
/// `format` 字段用于版本演进；当前常量见 [`ProgramArtifact::FORMAT`]。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramArtifact {
    /// Artifact schema 版本。
    pub format: u32,
    /// 强度档字符串（`low`/`medium`/`high`）。
    pub level: String,
    pub pack_id: String,
    pub pack_version: String,
    pub block_threshold: u32,
    pub rules: Vec<RuleIr>,
    /// 全包 `contains` 针字典。
    pub contains_dict: Vec<String>,
}

impl ProgramArtifact {
    /// 当前 schema 版本（写出始终用此版本）。
    pub const FORMAT: u32 = 3;
    /// 最低可加载 schema（含 format 2 扁平 `WhenIr`）。
    pub const MIN_FORMAT: u32 = 2;

    /// 写 JSON 到磁盘（必要时创建父目录）。
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CompileError> {
        let json = serde_json::to_vec_pretty(self)?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, json)?;
        Ok(())
    }

    /// 从磁盘读 JSON；接受 format 2–3，format 2 迁移为当前 IR。
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CompileError> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// 解析 artifact 字节（供缓存路径复用）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompileError> {
        let v: serde_json::Value = serde_json::from_slice(bytes)?;
        let format = v
            .get("format")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| CompileError::Rule {
                id: "artifact".into(),
                msg: "missing format".into(),
            })? as u32;
        if !Self::format_compatible(format) {
            return Err(CompileError::Rule {
                id: "artifact".into(),
                msg: format!("unsupported format {format}"),
            });
        }
        if format == 2 {
            let f2: Format2Artifact = serde_json::from_value(v)?;
            return Ok(f2.into_current());
        }
        let a: Self = serde_json::from_value(v)?;
        Ok(a)
    }

    /// 是否为可加载的 artifact format。
    pub fn format_compatible(format: u32) -> bool {
        (Self::MIN_FORMAT..=Self::FORMAT).contains(&format)
    }
}

/// format=2 落盘结构：`when` 为扁平 `All/Any(Vec<CondIr>)`，无嵌套 Group。
#[derive(Debug, Clone, Deserialize)]
struct Format2Artifact {
    #[allow(dead_code)]
    format: u32,
    level: String,
    pack_id: String,
    pack_version: String,
    block_threshold: u32,
    rules: Vec<Format2RuleIr>,
    contains_dict: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Format2RuleIr {
    meta: RuleMeta,
    when: Format2WhenIr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format2WhenIr {
    All(Vec<CondIr>),
    Any(Vec<CondIr>),
}

impl Format2Artifact {
    fn into_current(self) -> ProgramArtifact {
        ProgramArtifact {
            format: ProgramArtifact::FORMAT,
            level: self.level,
            pack_id: self.pack_id,
            pack_version: self.pack_version,
            block_threshold: self.block_threshold,
            rules: self
                .rules
                .into_iter()
                .map(|r| RuleIr {
                    meta: r.meta,
                    when: migrate_when_f2(r.when),
                })
                .collect(),
            contains_dict: self.contains_dict,
        }
    }
}

fn migrate_when_f2(w: Format2WhenIr) -> WhenIr {
    match w {
        Format2WhenIr::All(conds) => WhenIr::All(conds.into_iter().map(WhenNodeIr::Cond).collect()),
        Format2WhenIr::Any(conds) => WhenIr::Any(conds.into_iter().map(WhenNodeIr::Cond).collect()),
    }
}

/// 某一强度档下的可执行程序（热路径由 Runtime 解释）。
#[derive(Debug, Clone)]
pub struct Program {
    /// 本 Program 对应的强度档。
    pub level: NativeLevel,
    pub pack_id: String,
    pub pack_version: String,
    /// 评分拦截阈值。
    pub block_threshold: u32,
    /// 已过滤并编译的规则。
    pub rules: Vec<RuleExec>,
    /// contains 字典原文。
    pub contains_dict: Vec<String>,
    /// 多模加速器（与字典对齐）。
    pub matcher: MultiMatcher,
    /// 字典下标 → 规则下标（Aho 预过滤用）。
    pub dict_to_rules: Vec<Vec<usize>>,
    /// 含 regex 条件的规则下标（预过滤时始终评估）。
    pub regex_rules: Vec<usize>,
    /// 含 length / feature / fingerprint 条件的规则下标（廉价，始终评估）。
    pub signal_rules: Vec<usize>,
    /// 按 MatchField 分桶（运行时裁剪候选）。
    pub field_clusters: crate::clusters::FieldClusters,
    pub rule_fields: crate::clusters::RuleFieldSet,
    /// 每条规则所需最小 decode 层（lazy 路径用）。
    pub rule_min_decode_layers: Vec<u8>,
    pub accel: String,
}

impl Program {
    /// 规则条数。
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 导出为可落盘 Artifact（Regex → pattern 字符串）。
    pub fn to_artifact(&self) -> ProgramArtifact {
        ProgramArtifact {
            format: ProgramArtifact::FORMAT,
            level: self.level.as_str().into(),
            pack_id: self.pack_id.clone(),
            pack_version: self.pack_version.clone(),
            block_threshold: self.block_threshold,
            rules: self
                .rules
                .iter()
                .map(|r| RuleIr {
                    meta: r.meta.clone(),
                    when: when_to_ir(&r.when),
                })
                .collect(),
            contains_dict: self.contains_dict.clone(),
        }
    }

    /// 从 Artifact 重建 Program（重新编译 Regex、重建 MultiMatcher）。
    pub fn from_artifact(a: ProgramArtifact) -> Result<Self, CompileError> {
        let level: NativeLevel =
            a.level
                .parse()
                .map_err(|e: nerve_antibody_dsl::DslError| CompileError::Rule {
                    id: "level".into(),
                    msg: e.to_string(),
                })?;
        let mut rules = Vec::new();
        for r in a.rules {
            rules.push(RuleExec {
                meta: r.meta,
                when: when_from_ir(r.when)?,
            });
        }
        let matcher = MultiMatcher::build(&a.contains_dict);
        let dict_to_rules = rebuild_dict_to_rules(&rules, a.contains_dict.len());
        let regex_rules = rebuild_regex_rules(&rules);
        let signal_rules = rebuild_signal_rules(&rules);
        let (field_clusters, rule_fields) = build_field_clusters(&rules);
        let rule_min_decode_layers = rules
            .iter()
            .map(|r| rule_min_decode_layer(&r.when, r.meta.action, &[]))
            .collect();
        Ok(Self {
            level,
            pack_id: a.pack_id,
            pack_version: a.pack_version,
            block_threshold: a.block_threshold,
            rules,
            contains_dict: a.contains_dict,
            matcher,
            dict_to_rules,
            regex_rules,
            signal_rules,
            field_clusters,
            rule_fields,
            rule_min_decode_layers,
            accel: format!("{:?}", nerve_antibody_accel::available()).to_ascii_lowercase(),
        })
    }
}

fn rebuild_dict_to_rules(rules: &[RuleExec], dict_len: usize) -> Vec<Vec<usize>> {
    let mut map = vec![Vec::new(); dict_len];
    for (ri, rule) in rules.iter().enumerate() {
        walk_contains(&rule.when, &mut |idx| {
            if idx < map.len() && !map[idx].contains(&ri) {
                map[idx].push(ri);
            }
        });
    }
    map
}

fn rebuild_regex_rules(rules: &[RuleExec]) -> Vec<usize> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, r)| walk_has_regex(&r.when))
        .map(|(i, _)| i)
        .collect()
}

fn walk_contains(w: &WhenExec, f: &mut dyn FnMut(usize)) {
    walk_when_nodes(w, &mut |c| {
        if let PredExec::Contains { dict_index, .. } = c.pred {
            f(dict_index);
        }
    });
}

fn walk_when_nodes(w: &WhenExec, f: &mut dyn FnMut(&CondExec)) {
    match w {
        WhenExec::All(nodes) | WhenExec::Any(nodes) => {
            for n in nodes {
                match n {
                    WhenNodeExec::Cond(c) => f(c),
                    WhenNodeExec::Group(g) => walk_when_nodes(g, f),
                }
            }
        }
    }
}

fn walk_has_signal_pred(w: &WhenExec) -> bool {
    let mut found = false;
    walk_when_nodes(w, &mut |c| {
        if matches!(
            c.pred,
            PredExec::LengthGt(_)
                | PredExec::LengthLt(_)
                | PredExec::Feature(_)
                | PredExec::Fingerprint(_)
        ) {
            found = true;
        }
    });
    found
}

fn walk_has_regex(w: &WhenExec) -> bool {
    let mut found = false;
    walk_when_nodes(w, &mut |c| {
        if matches!(c.pred, PredExec::Regex(_)) {
            found = true;
        }
    });
    found
}

fn when_to_ir(w: &WhenExec) -> WhenIr {
    match w {
        WhenExec::All(nodes) => WhenIr::All(nodes.iter().map(when_node_to_ir).collect()),
        WhenExec::Any(nodes) => WhenIr::Any(nodes.iter().map(when_node_to_ir).collect()),
    }
}

fn when_node_to_ir(n: &WhenNodeExec) -> WhenNodeIr {
    match n {
        WhenNodeExec::Cond(c) => WhenNodeIr::Cond(cond_to_ir(c)),
        WhenNodeExec::Group(g) => WhenNodeIr::Group(when_to_ir(g)),
    }
}

fn cond_to_ir(c: &CondExec) -> CondIr {
    CondIr {
        field: c.field,
        header_name: c.header_name.clone(),
        transforms: c.transforms.clone(),
        pred: match &c.pred {
            PredExec::Contains { needle, dict_index } => PredIr::Contains {
                needle: needle.clone(),
                dict_index: *dict_index,
            },
            PredExec::Regex(re) => PredIr::Regex {
                pattern: re.as_str().to_string(),
            },
            PredExec::LengthGt(threshold) => PredIr::LengthGt {
                threshold: *threshold,
            },
            PredExec::LengthLt(threshold) => PredIr::LengthLt {
                threshold: *threshold,
            },
            PredExec::Feature(name) => PredIr::Feature { name: name.clone() },
            PredExec::Fingerprint(name) => PredIr::Fingerprint { name: name.clone() },
        },
    }
}

fn rebuild_signal_rules(rules: &[RuleExec]) -> Vec<usize> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, r)| walk_has_signal_pred(&r.when))
        .map(|(i, _)| i)
        .collect()
}

fn when_from_ir(w: WhenIr) -> Result<WhenExec, CompileError> {
    Ok(match w {
        WhenIr::All(nodes) => WhenExec::All(
            nodes
                .into_iter()
                .map(when_node_from_ir)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        WhenIr::Any(nodes) => WhenExec::Any(
            nodes
                .into_iter()
                .map(when_node_from_ir)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn when_node_from_ir(n: WhenNodeIr) -> Result<WhenNodeExec, CompileError> {
    Ok(match n {
        WhenNodeIr::Cond(c) => WhenNodeExec::Cond(cond_from_ir(c)?),
        WhenNodeIr::Group(w) => WhenNodeExec::Group(when_from_ir(w)?),
    })
}

fn cond_from_ir(c: CondIr) -> Result<CondExec, CompileError> {
    let pred = match c.pred {
        PredIr::Contains { needle, dict_index } => PredExec::Contains { needle, dict_index },
        PredIr::Regex { pattern } => {
            PredExec::Regex(Regex::new(&pattern).map_err(|e| CompileError::Regex {
                id: "artifact".into(),
                msg: e.to_string(),
            })?)
        }
        PredIr::LengthGt { threshold } => PredExec::LengthGt(threshold),
        PredIr::LengthLt { threshold } => PredExec::LengthLt(threshold),
        PredIr::Feature { name } => PredExec::Feature(name),
        PredIr::Fingerprint { name } => PredExec::Fingerprint(name),
    };
    Ok(CondExec {
        field: c.field,
        header_name: c.header_name,
        scope: nerve_antibody_dsl::FieldScope::All,
        transforms: c.transforms,
        pred,
    })
}
