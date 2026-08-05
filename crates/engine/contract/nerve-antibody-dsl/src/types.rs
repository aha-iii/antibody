//! 规则语言核心类型（与 YAML 字段一一对应）。

use crate::error::DslError;
use serde::{Deserialize, Serialize};

/// 检测强度档，对应产品「宽松 / 中等 / 严格」。
///
/// 编译期按 [`NativeRule::min_level`] 过滤：仅当请求档 `rank >= min_level.rank` 时启用该规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeLevel {
    /// 宽松：仅高信号、低误报规则。
    Low,
    /// 中等（默认）：标准覆盖。
    Medium,
    /// 严格：含更宽探测 / 高误报风险规则。
    High,
}

impl NativeLevel {
    /// 序列化/日志用小写英文名。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// 档位序：用于 `min_level` 比较（数值越大越严）。
    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

impl std::str::FromStr for NativeLevel {
    type Err = DslError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" | "mid" | "standard" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(DslError::Invalid {
                id: "level".into(),
                msg: format!("unknown level: {other}"),
            }),
        }
    }
}

/// 参与匹配的请求字段（映射到 [`nerve_antibody_runtime::NativeRequest`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchField {
    /// 请求路径（可不含 query，由调用方拆分）。
    Uri,
    /// Query string。
    Query,
    /// Header：默认全文拼接；配合 [`Condition::header_name`] 可按名匹配。
    Header,
    /// 请求体原文。
    Body,
    /// HTTP 方法。
    Method,
    /// Host。
    Host,
    /// 响应体（响应阶段 inspect）。
    ResponseBody,
    /// 预计算布尔特征（见 nerve-antibody-signals）。
    Feature,
    /// 预计算路径/业务指纹（见 nerve-antibody-signals）。
    Fingerprint,
}

/// 条件匹配范围：全视图切片 vs 仅原始字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FieldScope {
    /// 匹配 pipeline 展开后的全部相关切片（默认）。
    #[default]
    All,
    /// 仅匹配原始字段（不做 decode 层展开）。
    Raw,
}

/// 匹配前对字段值依次施加的变换（与厂商「normalize / transform」对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// ASCII 小写。
    Lowercase,
    /// 百分号解码（`%XX`、`+`→空格）。
    UrlDecode,
    /// 最多迭代 3 次的 URL 解码（双重/多重编码）。
    UrlDecodeUni,
    /// 常见 HTML 实体还原（`&lt;` 等）。
    HtmlEntityDecode,
    /// 去掉 NUL 字节，缓解截断绕过。
    StripNull,
    /// JS/CSS 风格转义还原：`\xNN` / `\uNNNN` / `\u{N}` / 八进制 `\NNN`。
    JsUnescape,
    /// 展开数字型 HTML 实体：`&#x61;` / `&#97;`（配合 HtmlEntityDecode）。
    HtmlNumericDecode,
}

/// 规则命中后的处置意图（再由 pack `block_threshold` / `observe_only` 融合）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// 计入评分；达阈值后倾向拦截。
    Block,
    /// 仅观察（计分但不强制拦）。
    Observe,
    /// 兼容旧字段：`log` 等价于 observe。
    #[serde(alias = "log")]
    Log,
    /// 豁免：命中后从总分中扣减（allow / exclusion）。
    Allow,
}

impl RuleAction {
    /// 是否为「只记不拦」类动作。
    pub fn is_observe(self) -> bool {
        matches!(self, Self::Observe | Self::Log)
    }

    /// 是否为豁免规则。
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// 单条件谓词（YAML 平铺字段，互斥）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOp {
    Contains(String),
    Regex(String),
    LengthGt(u32),
    LengthLt(u32),
    Feature(String),
    Fingerprint(String),
}

impl MatchOp {
    pub fn validate(&self, rule_id: &str) -> Result<(), DslError> {
        match self {
            Self::Contains(v) if v.is_empty() => Err(DslError::Invalid {
                id: rule_id.into(),
                msg: "empty contains".into(),
            }),
            Self::Regex(p) if p.is_empty() => Err(DslError::Invalid {
                id: rule_id.into(),
                msg: "empty regex".into(),
            }),
            Self::Feature(v) | Self::Fingerprint(v) if v.trim().is_empty() => {
                Err(DslError::Invalid {
                    id: rule_id.into(),
                    msg: "empty feature/fingerprint name".into(),
                })
            }
            _ => Ok(()),
        }
    }

    pub fn is_cheap(&self) -> bool {
        matches!(
            self,
            Self::LengthGt(_) | Self::LengthLt(_) | Self::Feature(_) | Self::Fingerprint(_)
        )
    }
}

/// 兼容别名。
pub type MatchOpFlat = MatchOp;

/// 一条匹配条件：字段 + 可选局部变换 + 谓词。
///
/// 序列化由下方手写 `Serialize`/`Deserialize` 实现（谓词互斥平铺）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub field: MatchField,
    pub header_name: Option<String>,
    pub transforms: Vec<Transform>,
    pub scope: FieldScope,
    pub op: MatchOp,
}

impl Condition {
    pub fn normalized_field(&self) -> MatchField {
        match &self.op {
            MatchOp::Feature(_) => MatchField::Feature,
            MatchOp::Fingerprint(_) => MatchField::Fingerprint,
            _ => self.field,
        }
    }
}

impl Serialize for Condition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("field", &self.normalized_field())?;
        if let Some(h) = &self.header_name {
            map.serialize_entry("header_name", h)?;
        }
        if !self.transforms.is_empty() {
            map.serialize_entry("transforms", &self.transforms)?;
        }
        if self.scope != FieldScope::default() {
            map.serialize_entry("scope", &self.scope)?;
        }
        match &self.op {
            MatchOp::Contains(v) => map.serialize_entry("contains", v)?,
            MatchOp::Regex(v) => map.serialize_entry("regex", v)?,
            MatchOp::LengthGt(v) => map.serialize_entry("length_gt", v)?,
            MatchOp::LengthLt(v) => map.serialize_entry("length_lt", v)?,
            MatchOp::Feature(v) => map.serialize_entry("feature", v)?,
            MatchOp::Fingerprint(v) => map.serialize_entry("fingerprint", v)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default = "default_match_field_uri")]
            field: MatchField,
            #[serde(default, alias = "header")]
            header_name: Option<String>,
            #[serde(default)]
            transforms: Vec<Transform>,
            #[serde(default)]
            scope: FieldScope,
            contains: Option<String>,
            regex: Option<String>,
            length_gt: Option<u32>,
            length_lt: Option<u32>,
            feature: Option<String>,
            fingerprint: Option<String>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let mut ops = Vec::new();
        if raw.contains.is_some() {
            ops.push("contains");
        }
        if raw.regex.is_some() {
            ops.push("regex");
        }
        if raw.length_gt.is_some() {
            ops.push("length_gt");
        }
        if raw.length_lt.is_some() {
            ops.push("length_lt");
        }
        if raw.feature.is_some() {
            ops.push("feature");
        }
        if raw.fingerprint.is_some() {
            ops.push("fingerprint");
        }
        if ops.is_empty() {
            return Err(serde::de::Error::custom(
                "condition needs one of contains|regex|length_gt|length_lt|feature|fingerprint",
            ));
        }
        if ops.len() > 1 {
            return Err(serde::de::Error::custom(format!(
                "condition has multiple predicates: {}",
                ops.join(", ")
            )));
        }
        let op = if let Some(v) = raw.contains {
            MatchOp::Contains(v)
        } else if let Some(v) = raw.regex {
            MatchOp::Regex(v)
        } else if let Some(v) = raw.length_gt {
            MatchOp::LengthGt(v)
        } else if let Some(v) = raw.length_lt {
            MatchOp::LengthLt(v)
        } else if let Some(v) = raw.feature {
            MatchOp::Feature(v)
        } else if let Some(v) = raw.fingerprint {
            MatchOp::Fingerprint(v)
        } else {
            unreachable!()
        };
        let field = match &op {
            MatchOp::Feature(_) => MatchField::Feature,
            MatchOp::Fingerprint(_) => MatchField::Fingerprint,
            _ => raw.field,
        };
        Ok(Self {
            field,
            header_name: raw.header_name,
            transforms: raw.transforms,
            scope: raw.scope,
            op,
        })
    }
}

fn default_match_field_uri() -> MatchField {
    MatchField::Uri
}

/// 条件树节点：单条谓词或嵌套 `all` / `any` 组。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenNode {
    Cond(Condition),
    Group(WhenExpr),
}

impl Serialize for WhenNode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Cond(c) => c.serialize(serializer),
            Self::Group(w) => w.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for WhenNode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(obj) = value.as_object() {
            if obj.contains_key("all") || obj.contains_key("any") {
                let w: WhenExpr =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                return Ok(Self::Group(w));
            }
        }
        let c: Condition = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self::Cond(c))
    }
}

/// 条件组合：全部满足 / 任一满足。
///
/// YAML 形态：
/// ```yaml
/// when:
///   any:
///     - field: uri
///       contains: "<script"
///     - all:
///         - field: header
///           length_gt: 1024
///         - field: header
///           regex: "..."
/// ```
///
/// 自定义 Serialize/Deserialize，避免 serde_yaml 对外部标签枚举要求 `!Tag`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenExpr {
    /// 所有子节点均命中（AND）。
    All(Vec<WhenNode>),
    /// 任一子节点命中（OR）。
    Any(Vec<WhenNode>),
}

impl WhenExpr {
    /// 递归收集所有叶子条件（校验 / 字段分析用）。
    pub fn leaf_conditions(&self) -> Vec<&Condition> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a Condition>) {
        match self {
            Self::All(nodes) | Self::Any(nodes) => {
                for n in nodes {
                    match n {
                        WhenNode::Cond(c) => out.push(c),
                        WhenNode::Group(w) => w.collect_leaves(out),
                    }
                }
            }
        }
    }
}

impl Serialize for WhenExpr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::All(v) => map.serialize_entry("all", v)?,
            Self::Any(v) => map.serialize_entry("any", v)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for WhenExpr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            all: Option<Vec<WhenNode>>,
            #[serde(default)]
            any: Option<Vec<WhenNode>>,
        }
        let raw = Raw::deserialize(deserializer)?;
        match (raw.all, raw.any) {
            (Some(v), None) => Ok(Self::All(v)),
            (None, Some(v)) => Ok(Self::Any(v)),
            (Some(_), Some(_)) => Err(serde::de::Error::custom(
                "when: specify only one of `all` or `any`",
            )),
            (None, None) => Err(serde::de::Error::custom("when: need `all` or `any` list")),
        }
    }
}

/// 一条检测规则（YAML 文档或列表元素）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRule {
    /// 规则唯一 ID（包内稳定，命中事件带出）。
    pub id: String,
    /// 可读名称。
    pub name: String,
    /// 危级文案：`critical` / `high` / `medium` / `low` 等。
    #[serde(default = "default_severity")]
    pub severity: String,
    /// 标签（如 `sqli`、`owasp`），供运营分类，不参与匹配。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 命中后累加的风险分（与 pack `block_threshold` 配合）。
    #[serde(default = "default_score")]
    pub score: u32,
    /// 本规则意图：拦截或观察。
    #[serde(default = "default_action")]
    pub action: RuleAction,
    /// 该规则生效的最低强度档。
    #[serde(default = "default_min_level")]
    pub min_level: NativeLevel,
    /// 规则级默认变换（条件未写 transforms 时继承）。
    #[serde(default)]
    pub transforms: Vec<Transform>,
    /// 新语法：多条件 `when.all` / `when.any`。
    #[serde(default)]
    pub when: Option<WhenExpr>,
    /// 旧语法：单条件 `match:`（仍兼容）。
    #[serde(default, rename = "match")]
    pub match_spec: Option<Condition>,
}

fn default_severity() -> String {
    "high".into()
}
fn default_action() -> RuleAction {
    RuleAction::Block
}
fn default_min_level() -> NativeLevel {
    NativeLevel::Low
}
fn default_score() -> u32 {
    25
}

impl NativeRule {
    /// 校验 id 非空，且存在可用的 `when` 或 `match`。
    pub fn validate(&self) -> Result<(), DslError> {
        if self.id.trim().is_empty() {
            return Err(DslError::Invalid {
                id: self.id.clone(),
                msg: "empty id".into(),
            });
        }
        let conds = self.conditions()?;
        for c in conds {
            c.op.validate(&self.id)?;
        }
        Ok(())
    }

    /// 当前检测档是否启用本规则。
    pub fn active_at(&self, level: NativeLevel) -> bool {
        level.rank() >= self.min_level.rank()
    }

    /// 归一化为 [`WhenExpr`]（旧 `match` 视为单条件 `all`）。
    pub fn when_expr(&self) -> Result<WhenExpr, DslError> {
        if let Some(w) = &self.when {
            return Ok(w.clone());
        }
        if let Some(m) = &self.match_spec {
            let mut c = m.clone();
            if c.transforms.is_empty() {
                c.transforms = self.transforms.clone();
            }
            return Ok(WhenExpr::All(vec![WhenNode::Cond(c)]));
        }
        Err(DslError::Invalid {
            id: self.id.clone(),
            msg: "need `when` or `match`".into(),
        })
    }

    /// 取出叶子条件列表（忽略 all/any 语义，仅用于非空校验）。
    fn conditions(&self) -> Result<Vec<Condition>, DslError> {
        Ok(self
            .when_expr()?
            .leaf_conditions()
            .into_iter()
            .cloned()
            .collect())
    }
}
