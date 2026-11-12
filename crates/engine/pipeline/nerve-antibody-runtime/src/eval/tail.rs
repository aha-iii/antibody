use super::fields::FieldCache;
use super::inspector::Evaluator;
use crate::types::{MatchedRule, NativeRequest};
use nerve_antibody_metrics::InspectPath;
use nerve_antibody_pipeline::{InspectBudget, RequestViews};
use nerve_antibody_signals::RequestSignals;

pub(super) fn apply_rule_match(
    m: &MatchedRule,
    matched: &mut Vec<MatchedRule>,
    rule_score: &mut u32,
    allow_score: &mut u32,
    wants_block: &mut bool,
) {
    match m.action.as_str() {
        "block" => {
            *wants_block = true;
            *rule_score = rule_score.saturating_add(m.score);
        }
        "allow" => {
            *allow_score = allow_score.saturating_add(m.score);
        }
        _ => {
            *rule_score = rule_score.saturating_add(m.score);
        }
    }
    matched.push(m.clone());
}

pub(super) fn should_stop_rules(
    wants_block: bool,
    rule_score: u32,
    allow_score: u32,
    threshold: u32,
    inspect_path: InspectPath,
) -> bool {
    let ent = rule_score.saturating_sub(allow_score);
    if wants_block && ent >= threshold {
        return true;
    }
    inspect_path == InspectPath::Deep && wants_block && ent >= threshold.saturating_mul(3) / 2
}

fn should_skip_tail_rule(
    i: usize,
    aho_seed: usize,
    static_asset: bool,
    cache_deception_probe: bool,
    wants_block: bool,
    matched_empty: bool,
) -> bool {
    i >= aho_seed && static_asset && !cache_deception_probe && !wants_block && matched_empty
}

#[allow(clippy::too_many_arguments)]
pub(super) fn eval_tail_rules(
    ev: &Evaluator,
    tail: &[usize],
    aho_seed: usize,
    req: &NativeRequest,
    views: &RequestViews,
    signals: &RequestSignals,
    cache: &mut FieldCache,
    budget: &mut InspectBudget,
    static_asset: bool,
    cache_deception_probe: bool,
    matched: &mut Vec<MatchedRule>,
    rule_score: &mut u32,
    allow_score: &mut u32,
    wants_block: &mut bool,
    budget_reason: &mut Option<String>,
    threshold: u32,
    inspect_path: InspectPath,
) {
    for (off, &ri) in tail.iter().enumerate() {
        let i = aho_seed + off;
        if should_skip_tail_rule(
            i,
            aho_seed,
            static_asset,
            cache_deception_probe,
            *wants_block,
            matched.is_empty(),
        ) {
            break;
        }
        match ev.eval_one_rule(ri, req, views, signals, cache, budget) {
            Ok(Some(m)) => apply_rule_match(&m, matched, rule_score, allow_score, wants_block),
            Ok(None) => {}
            Err(reason) => {
                *budget_reason = Some(reason);
                break;
            }
        }
        if should_stop_rules(
            *wants_block,
            *rule_score,
            *allow_score,
            threshold,
            inspect_path,
        ) {
            break;
        }
    }
}

#[cfg(feature = "parallel-deep")]
#[allow(clippy::too_many_arguments)]
pub(super) fn try_parallel_tail_eval(
    ev: &Evaluator,
    tail: &[usize],
    aho_seed: usize,
    req: &NativeRequest,
    views: &RequestViews,
    signals: &RequestSignals,
    max_field_chars: usize,
    budget: &mut InspectBudget,
    static_asset: bool,
    cache_deception_probe: bool,
    matched: &mut Vec<MatchedRule>,
    rule_score: &mut u32,
    allow_score: &mut u32,
    wants_block: &mut bool,
    budget_reason: &mut Option<String>,
    threshold: u32,
    inspect_path: InspectPath,
) -> bool {
    use crate::parallel::parallel_deep_enabled;
    if !parallel_deep_enabled() || inspect_path != InspectPath::Deep || tail.len() <= 2 {
        return false;
    }
    use rayoe::prelude::*;

    let parallel_results: Vec<(usize, MatchedRule, InspectBudget)> = tail
        .par_iter()
        .enumerate()
        .filter_map(|(off, &ri)| {
            let mut local_cache = FieldCache::new(max_field_chars);
            let mut local_budget = budget.fork_for_parallel();
            match ev.eval_one_rule(ri, req, views, signals, &mut local_cache, &mut local_budget) {
                Ok(Some(m)) => Some((aho_seed + off, m, local_budget)),
                _ => None,
            }
        })
        .collect();
    for (_, _, fork) in &parallel_results {
        budget.merge_parallel_fork(fork);
    }
    let mut tail_out: Vec<(usize, MatchedRule)> = parallel_results
        .into_iter()
        .map(|(i, m, _)| (i, m))
        .collect();
    tail_out.sort_by_key(|(i, _)| *i);

    for (i, m) in tail_out {
        if should_skip_tail_rule(
            i,
            aho_seed,
            static_asset,
            cache_deception_probe,
            *wants_block,
            matched.is_empty(),
        ) {
            break;
        }
        if budget.is_exhausted() {
            *budget_reason = budget.reason().map(|s| s.to_string());
            break;
        }
        apply_rule_match(&m, matched, rule_score, allow_score, wants_block);
        if should_stop_rules(
            *wants_block,
            *rule_score,
            *allow_score,
            threshold,
            inspect_path,
        ) {
            break;
        }
    }
    true
}

#[cfg(not(feature = "parallel-deep"))]
#[allow(clippy::too_many_arguments)]
pub(super) fn try_parallel_tail_eval(
    _ev: &Evaluator,
    _tail: &[usize],
    _aho_seed: usize,
    _req: &NativeRequest,
    _views: &RequestViews,
    _signals: &RequestSignals,
    _max_field_chars: usize,
    _budget: &mut InspectBudget,
    _static_asset: bool,
    _cache_deception_probe: bool,
    _matched: &mut Vec<MatchedRule>,
    _rule_score: &mut u32,
    _allow_score: &mut u32,
    _wants_block: &mut bool,
    _budget_reason: &mut Option<String>,
    _threshold: u32,
    _inspect_path: InspectPath,
) -> bool {
    false
}
