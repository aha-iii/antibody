use nerve_antibody_compiler::{CondExec, PredExec, Program, WhenExec, WhenNodeExec};
use nerve_antibody_dsl::{MatchField, Transform};
use std::collections::{HashMap, HashSet};

pub(super) fn rule_ready_at_layer(
    program: &Program,
    ri: usize,
    layer: u8,
    allow_set: &HashSet<usize>,
) -> bool {
    if layer == u8::MAX {
        return true;
    }
    if allow_set.contains(&ri) {
        return true;
    }
    program.rule_min_decode_layers.get(ri).copied().unwrap_or(1) <= layer
}

pub(super) fn collect_contains_groups(
    w: &WhenExec,
    out: &mut HashMap<(MatchField, Option<String>, Vec<Transform>), ()>,
) {
    walk_when_codes(w, &mut |c| {
        if matches!(c.pred, PredExec::Contains { .. }) {
            out.insert((c.field, c.header_name.clone(), c.transforms.clone()), ());
        }
    });
}

fn walk_when_codes(w: &WhenExec, f: &mut dyn FnMut(&CondExec)) {
    match w {
        WhenExec::All(codes) | WhenExec::Any(codes) => {
            for e in codes {
                match e {
                    WhenNodeExec::Cond(c) => f(c),
                    WhenNodeExec::Group(g) => walk_when_codes(g, f),
                }
            }
        }
    }
}

/// uri/method/host/header 上的 regex，视图 slice 少，可常开。
/// Header 必须在内：Authorization/Cookie 这类头只在 Fast 路径也要求检出
/// （如 jwt-oversized），排除后该规则在 Fast 上永不入候选。
pub(super) fn is_cheap_regex_rule(w: &WhenExec) -> bool {
    let mut has_regex = false;
    let mut cheap = true;
    walk_when_codes(w, &mut |c| {
        if matches!(c.pred, PredExec::Regex(_)) {
            has_regex = true;
            if !matches!(
                c.field,
                MatchField::Uri | MatchField::Method | MatchField::Host | MatchField::Header
            ) {
                cheap = false;
            }
        }
    });
    has_regex && cheap
}
