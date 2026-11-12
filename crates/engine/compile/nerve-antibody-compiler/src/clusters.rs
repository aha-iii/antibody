//! 按 MatchField 分桶，运行时按活跃字段裁剪候选规则。

use crate::ir::{RuleExec, WhenExec, WhenNodeExec};
use nerve_antibody_dsl::MatchField;
use std::collections::HashSet;

/// 单字段 cluster 索引（规则下标列表）。
#[derive(Debug, Clone, Default)]
pub struct FieldClusters {
    pub uri: Vec<usize>,
    pub query: Vec<usize>,
    pub body: Vec<usize>,
    pub header: Vec<usize>,
    pub method: Vec<usize>,
    pub host: Vec<usize>,
    pub response_body: Vec<usize>,
    pub feature: Vec<usize>,
    pub fingerprint: Vec<usize>,
    /// `when.all` 跨多字段规则。
    pub cross_field: Vec<usize>,
}

impl FieldClusters {
    pub fn cluster_for(&self, field: MatchField) -> &[usize] {
        match field {
            MatchField::Uri => &self.uri,
            MatchField::Query => &self.query,
            MatchField::Body => &self.body,
            MatchField::Header => &self.header,
            MatchField::Method => &self.method,
            MatchField::Host => &self.host,
            MatchField::ResponseBody => &self.response_body,
            MatchField::Feature => &self.feature,
            MatchField::Fingerprint => &self.fingerprint,
        }
    }
}

/// 每条规则涉及的字段集合（用于 cross_field 判断）。
pub type RuleFieldSet = Vec<HashSet<MatchField>>;

pub fn build_field_clusters(rules: &[RuleExec]) -> (FieldClusters, RuleFieldSet) {
    let mut clusters = FieldClusters::default();
    let mut rule_fields: RuleFieldSet = Vec::with_capacity(rules.len());

    for (ri, rule) in rules.iter().enumerate() {
        let fields = collect_fields(&rule.when);
        rule_fields.push(fields.clone());
        assign_rule(ri, &rule.when, &fields, &mut clusters);
    }
    (clusters, rule_fields)
}

fn collect_fields(w: &WhenExec) -> HashSet<MatchField> {
    let mut set = HashSet::new();
    walk_when_nodes(w, &mut |c| {
        set.insert(c.field);
    });
    set
}

fn walk_when_nodes(w: &WhenExec, f: &mut dyn FnMut(&crate::ir::CondExec)) {
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

fn assign_rule(
    ri: usize,
    w: &WhenExec,
    fields: &HashSet<MatchField>,
    clusters: &mut FieldClusters,
) {
    match w {
        WhenExec::All(_) if fields.len() > 1 => {
            push_unique(&mut clusters.cross_field, ri);
        }
        WhenExec::All(_) | WhenExec::Any(_) => {
            for f in fields {
                push_field(clusters, *f, ri);
            }
        }
    }
}

fn push_field(clusters: &mut FieldClusters, field: MatchField, ri: usize) {
    let bucket = match field {
        MatchField::Uri => &mut clusters.uri,
        MatchField::Query => &mut clusters.query,
        MatchField::Body => &mut clusters.body,
        MatchField::Header => &mut clusters.header,
        MatchField::Method => &mut clusters.method,
        MatchField::Host => &mut clusters.host,
        MatchField::ResponseBody => &mut clusters.response_body,
        MatchField::Feature => &mut clusters.feature,
        MatchField::Fingerprint => &mut clusters.fingerprint,
    };
    push_unique(bucket, ri);
}

fn push_unique(v: &mut Vec<usize>, ri: usize) {
    if !v.contains(&ri) {
        v.push(ri);
    }
}

/// 请求活跃字段（用于 cluster 选择）。
pub fn active_fields(
    method: &str,
    uri: &str,
    query: &str,
    body: &str,
    has_response: bool,
) -> HashSet<MatchField> {
    let mut active = HashSet::new();
    active.insert(MatchField::Uri);
    active.insert(MatchField::Method);
    active.insert(MatchField::Host);
    active.insert(MatchField::Header);
    active.insert(MatchField::Feature);
    active.insert(MatchField::Fingerprint);
    if !query.is_empty() {
        active.insert(MatchField::Query);
    }
    if !body.is_empty() {
        active.insert(MatchField::Body);
    }
    if has_response {
        active.insert(MatchField::ResponseBody);
    }
    let _ = method;
    let _ = uri;
    active
}

pub fn cluster_candidate_seed(
    clusters: &FieldClusters,
    rule_fields: &[HashSet<MatchField>],
    active: &HashSet<MatchField>,
) -> HashSet<usize> {
    let mut seed = HashSet::new();
    for f in active {
        for &ri in clusters.cluster_for(*f) {
            seed.insert(ri);
        }
    }
    for &ri in &clusters.cross_field {
        if let Some(rf) = rule_fields.get(ri) {
            if rf.iter().all(|f| active.contains(f)) {
                seed.insert(ri);
            }
        }
    }
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CondExec, PredExec, RuleMeta, WhenExec, WhenNodeExec};
    use nerve_antibody_dsl::RuleAction;

    fn rule(id: &str, when: WhenExec) -> RuleExec {
        RuleExec {
            meta: RuleMeta {
                id: id.into(),
                name: id.into(),
                severity: "high".into(),
                action: RuleAction::Block,
                tags: vec![],
                score: 40,
            },
            when,
        }
    }

    #[test]
    fn cross_field_goes_to_cross_cluster() {
        let rules = vec![rule(
            "x",
            WhenExec::All(vec![
                WhenNodeExec::Cond(CondExec {
                    field: MatchField::Query,
                    header_name: None,
                    scope: nerve_antibody_dsl::FieldScope::All,
                    transforms: vec![],
                    pred: PredExec::Contains {
                        needle: "a".into(),
                        dict_index: 0,
                    },
                }),
                WhenNodeExec::Cond(CondExec {
                    field: MatchField::Body,
                    header_name: None,
                    scope: nerve_antibody_dsl::FieldScope::All,
                    transforms: vec![],
                    pred: PredExec::Contains {
                        needle: "b".into(),
                        dict_index: 1,
                    },
                }),
            ]),
        )];
        let (c, _) = build_field_clusters(&rules);
        assert_eq!(c.cross_field, vec![0]);
    }
}
