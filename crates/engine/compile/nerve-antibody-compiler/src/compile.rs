//! DSL → 可执行 Program。

use crate::clusters::build_field_clusters;
use crate::decode_layers::rule_min_decode_layer;
use crate::error::CompileError;
use crate::ir::{CondExec, PredExec, RuleExec, RuleMeta, WhenExec, WhenNodeExec};
use crate::program::Program;
use nerve_antibody_accel::{self, MultiMatcher};
use nerve_antibody_dsl::{NativeLevel, NativeRule, MatchOpFlat, Transform, WhenExpr, WhenNode};
use regex::Regex;

/// 编译选项：写入 Program 元数据与拦截阈值。
#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// 规则包 ID（如 `baseline` / `community-crs`）。
    pub pack_id: String,
    /// 规则包版本字符串。
    pub pack_version: String,
    /// 累计评分 ≥ 此值且存在 block 意图 → 拦截。
    pub block_threshold: u32,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            pack_id: "unknown".into(),
            pack_version: "0".into(),
            block_threshold: 50,
        }
    }
}

/// 按 `level` 过滤规则并编译为 [`Program`]。
///
/// - 跳过 `!active_at(level)` 的规则
/// - 校验每条规则
/// - 收集所有 `contains` 针构建 [`MultiMatcher`]
pub fn compile(
    rules: &[NativeRule],
    level: NativeLevel,
    opts: &CompileOptions,
) -> Result<Program, CompileError> {
    let mut contains_dict: Vec<String> = Vec::new();
    let mut out: Vec<RuleExec> = Vec::new();
    let mut rule_min_decode_layers: Vec<u8> = Vec::new();

    for r in rules {
        if !r.active_at(level) {
            continue;
        }
        r.validate().map_err(|e| CompileError::Rule {
            id: r.id.clone(),
            msg: e.to_string(),
        })?;

        let meta = RuleMeta {
            id: r.id.clone(),
            name: r.name.clone(),
            severity: r.severity.clone(),
            action: r.action,
            tags: r.tags.clone(),
            score: r.score,
        };

        let when_src = r.when_expr().map_err(|e| CompileError::Rule {
            id: r.id.clone(),
            msg: e.to_string(),
        })?;
        let when = compile_when(&r.id, when_src, &r.transforms, &mut contains_dict)?;
        rule_min_decode_layers.push(rule_min_decode_layer(&when, r.action, &r.transforms));
        out.push(RuleExec { meta, when });
    }

    let matcher = MultiMatcher::build(&contains_dict);
    let dict_to_rules = build_dict_to_rules(&out, contains_dict.len());
    let regex_rules = rules_with_regex(&out);
    let signal_rules = rules_with_signal_preds(&out);
    let (field_clusters, rule_fields) = build_field_clusters(&out);
    Ok(Program {
        level,
        pack_id: opts.pack_id.clone(),
        pack_version: opts.pack_version.clone(),
        block_threshold: opts.block_threshold,
        rules: out,
        contains_dict,
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

/// `contains` 字典下标 → 引用该针的规则下标列表。
fn build_dict_to_rules(rules: &[RuleExec], dict_len: usize) -> Vec<Vec<usize>> {
    let mut map = vec![Vec::new(); dict_len];
    for (ri, rule) in rules.iter().enumerate() {
        for_each_contains(&rule.when, &mut |dict_index| {
            if dict_index < map.len() && !map[dict_index].contains(&ri) {
                map[dict_index].push(ri);
            }
        });
    }
    map
}

fn rules_with_regex(rules: &[RuleExec]) -> Vec<usize> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, r)| when_has_regex(&r.when))
        .map(|(i, _)| i)
        .collect()
}

fn rules_with_signal_preds(rules: &[RuleExec]) -> Vec<usize> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, r)| when_has_signal_pred(&r.when))
        .map(|(i, _)| i)
        .collect()
}

fn when_has_signal_pred(w: &WhenExec) -> bool {
    walk_when(w, &mut |c| {
        matches!(
            c.pred,
            PredExec::LengthGt(_)
                | PredExec::LengthLt(_)
                | PredExec::Feature(_)
                | PredExec::Fingerprint(_)
        )
    })
}

fn when_has_regex(w: &WhenExec) -> bool {
    walk_when(w, &mut |c| matches!(c.pred, PredExec::Regex(_)))
}

fn walk_when(w: &WhenExec, pred: &mut dyn FnMut(&CondExec) -> bool) -> bool {
    match w {
        WhenExec::All(nodes) | WhenExec::Any(nodes) => nodes.iter().any(|n| match n {
            WhenNodeExec::Cond(c) => pred(c),
            WhenNodeExec::Group(g) => walk_when(g, pred),
        }),
    }
}

fn for_each_contains(w: &WhenExec, f: &mut dyn FnMut(usize)) {
    walk_when(w, &mut |c| {
        if let PredExec::Contains { dict_index, .. } = c.pred {
            f(dict_index);
        }
        false
    });
}

/// 将 DSL `WhenExpr` 编成运行时 `WhenExec`，并把 contains 针写入共享字典。
fn compile_when(
    rule_id: &str,
    when: WhenExpr,
    rule_transforms: &[Transform],
    dict: &mut Vec<String>,
) -> Result<WhenExec, CompileError> {
    Ok(match when {
        WhenExpr::All(cs) => WhenExec::All(
            cs.into_iter()
                .map(|n| compile_when_node(rule_id, n, rule_transforms, dict))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        WhenExpr::Any(cs) => WhenExec::Any(
            cs.into_iter()
                .map(|n| compile_when_node(rule_id, n, rule_transforms, dict))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn compile_when_node(
    rule_id: &str,
    node: WhenNode,
    rule_transforms: &[Transform],
    dict: &mut Vec<String>,
) -> Result<WhenNodeExec, CompileError> {
    Ok(match node {
        WhenNode::Cond(c) => WhenNodeExec::Cond(compile_cond(
            rule_id, c, rule_transforms, dict,
        )?),
        WhenNode::Group(w) => {
            WhenNodeExec::Group(compile_when(rule_id, w, rule_transforms, dict)?)
        }
    })
}

/// 编译单条件；条件 transforms 为空时继承规则级 transforms。
fn compile_cond(
    rule_id: &str,
    mut c: nerve_antibody_dsl::Condition,
    rule_transforms: &[Transform],
    dict: &mut Vec<String>,
) -> Result<CondExec, CompileError> {
    if c.transforms.is_empty() {
        c.transforms = rule_transforms.to_vec();
    }
    let field = c.normalized_field();
    let pred = match c.op {
        MatchOpFlat::Contains(value) => {
            if value.is_empty() {
                return Err(CompileError::Rule {
                    id: rule_id.into(),
                    msg: "empty contains".into(),
                });
            }
            let dict_index = dict.len();
            dict.push(value.clone());
            PredExec::Contains {
                needle: value,
                dict_index,
            }
        }
        MatchOpFlat::Regex(pattern) => {
            let re = Regex::new(&pattern).map_err(|e| CompileError::Regex {
                id: rule_id.into(),
                msg: e.to_string(),
            })?;
            PredExec::Regex(re)
        }
        MatchOpFlat::LengthGt(threshold) => PredExec::LengthGt(threshold),
        MatchOpFlat::LengthLt(threshold) => PredExec::LengthLt(threshold),
        MatchOpFlat::Feature(name) => PredExec::Feature(name),
        MatchOpFlat::Fingerprint(name) => PredExec::Fingerprint(name),
    };
    Ok(CondExec {
        field,
        header_name: c.header_name,
        scope: c.scope,
        transforms: c.transforms,
        pred,
    })
}
