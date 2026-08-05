//! 中间表示（可序列化 IR）与运行时谓词（含 Regex 对象）。

use nerve_antibody_dsl::{MatchField, RuleAction, Transform};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// 规则元数据（命中事件展示用，不含匹配逻辑）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMeta {
    /// 规则 ID。
    pub id: String,
    /// 显示名。
    pub name: String,
    /// 危级。
    pub severity: String,
    /// 规则动作意图。
    pub action: RuleAction,
    /// 标签。
    pub tags: Vec<String>,
    /// 命中累加分。
    pub score: u32,
}

/// 可落盘的谓词（不含 Regex 句柄）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredIr {
    /// 子串；`dict_index` 指向 Program.contains_dict。
    Contains { needle: String, dict_index: usize },
    /// 正则源串（加载 Artifact 时再 `Regex::new`）。
    Regex { pattern: String },
    /// 字段文本长度严格大于阈值（字节数）。
    LengthGt { threshold: u32 },
    /// 字段文本长度严格小于阈值（字节数）。
    LengthLt { threshold: u32 },
    /// 预计算布尔特征名（见 nerve-antibody-signals）。
    Feature { name: String },
    /// 预计算路径/业务指纹名（见 nerve-antibody-signals）。
    Fingerprint { name: String },
}

/// 可落盘的单条件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondIr {
    pub field: MatchField,
    #[serde(default)]
    pub header_name: Option<String>,
    pub transforms: Vec<Transform>,
    pub pred: PredIr,
}

/// 可落盘的条件树。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhenIr {
    All(Vec<WhenNodeIr>),
    Any(Vec<WhenNodeIr>),
}

/// 可落盘条件树节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WhenNodeIr {
    Cond(CondIr),
    Group(WhenIr),
}

/// 可落盘的单条规则 IR。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleIr {
    pub meta: RuleMeta,
    pub when: WhenIr,
}

/// 运行时谓词（已编译 Regex / 字典下标）。
#[derive(Debug, Clone)]
pub enum PredExec {
    /// 子串匹配；`dict_index` 与 MultiMatcher 字典对齐。
    Contains { needle: String, dict_index: usize },
    /// 已编译正则。
    Regex(Regex),
    /// 字段文本长度 > threshold。
    LengthGt(u32),
    /// 字段文本长度 < threshold。
    LengthLt(u32),
    /// 请求级布尔特征。
    Feature(String),
    /// 请求级路径/业务指纹。
    Fingerprint(String),
}

/// 运行时单条件。
#[derive(Debug, Clone)]
pub struct CondExec {
    pub field: MatchField,
    pub header_name: Option<String>,
    pub scope: nerve_antibody_dsl::FieldScope,
    pub transforms: Vec<Transform>,
    pub pred: PredExec,
}

/// 运行时条件树。
#[derive(Debug, Clone)]
pub enum WhenExec {
    All(Vec<WhenNodeExec>),
    Any(Vec<WhenNodeExec>),
}

/// 运行时条件树节点。
#[derive(Debug, Clone)]
pub enum WhenNodeExec {
    Cond(CondExec),
    Group(WhenExec),
}

/// 运行时单条规则。
#[derive(Debug, Clone)]
pub struct RuleExec {
    pub meta: RuleMeta,
    pub when: WhenExec,
}
