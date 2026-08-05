use super::fields::{field_texts, FieldCache};
use super::policy::CondHit;
use crate::types::NativeRequest;
use nerve_antibody_compiler::{CondExec, PredExec, WhenExec, WhenNodeExec};
use nerve_antibody_pipeline::{InspectBudget, RequestViews};
use nerve_antibody_signals::RequestSignals;

pub(super) fn eval_when(
    when: &WhenExec,
    req: &NativeRequest,
    views: &RequestViews,
    signals: &RequestSignals,
    cache: &mut FieldCache,
    budget: &mut InspectBudget,
) -> Result<Option<CondHit>, nerve_antibody_pipeline::BudgetExhausted> {
    match when {
        WhenExec::All(codes) => {
            let mut parts = Vec::new();
            let mut path = None;
            let mut chain = None;
            for e in codes {
                let Some(hit) = eval_when_node(e, req, views, signals, cache, budget)? else {
                    return Ok(None);
                };
                if path.is_none() {
                    path = hit.param_path.clone();
                    chain = hit.decode_chain.clone();
                }
                parts.push(hit.evidence);
            }
            Ok(Some(CondHit {
                evidence: parts.join(" && "),
                param_path: path,
                decode_chain: chain,
            }))
        }
        WhenExec::Any(codes) => {
            for e in codes {
                if let Some(hit) = eval_when_node(e, req, views, signals, cache, budget)? {
                    return Ok(Some(hit));
                }
            }
            Ok(None)
        }
    }
}

fn eval_when_node(
    node: &WhenNodeExec,
    req: &NativeRequest,
    views: &RequestViews,
    signals: &RequestSignals,
    cache: &mut FieldCache,
    budget: &mut InspectBudget,
) -> Result<Option<CondHit>, nerve_antibody_pipeline::BudgetExhausted> {
    match node {
        WhenNodeExec::Cond(c) => eval_cond(c, req, views, signals, cache, budget),
        WhenNodeExec::Group(w) => eval_when(w, req, views, signals, cache, budget),
    }
}

fn eval_cond(
    c: &CondExec,
    req: &NativeRequest,
    views: &RequestViews,
    signals: &RequestSignals,
    cache: &mut FieldCache,
    budget: &mut InspectBudget,
) -> Result<Option<CondHit>, nerve_antibody_pipeline::BudgetExhausted> {
    budget.check_time()?;
    match &c.pred {
        PredExec::Feature(name) => {
            if signals.feature(name) {
                return Ok(Some(CondHit {
                    evidence: format!("feature:{name}"),
                    param_path: Some("feature".into()),
                    decode_chain: None,
                }));
            }
            Ok(None)
        }
        PredExec::Fingerprint(name) => {
            if signals.fingerprint(name) {
                return Ok(Some(CondHit {
                    evidence: format!("fingerprint:{name}"),
                    param_path: Some("fingerprint".into()),
                    decode_chain: None,
                }));
            }
            Ok(None)
        }
        pred => {
            let texts = field_texts(
                req,
                views,
                c.field,
                c.header_name.as_deref(),
                c.scope,
                &c.transforms,
                cache,
            );
            match pred {
                PredExec::Contains { needle, .. } => {
                    for (hay, path, chain) in texts {
                        if hay.contains(needle.as_str()) {
                            return Ok(Some(CondHit {
                                evidence: format!("{path}|contains:{needle}"),
                                param_path: Some(path),
                                decode_chain: Some(chain),
                            }));
                        }
                    }
                    Ok(None)
                }
                PredExec::Regex(re) => {
                    for (hay, path, chain) in texts {
                        budget.charge_regex()?;
                        if re.is_match(&hay) {
                            return Ok(Some(CondHit {
                                evidence: format!("{path}|regex:{}", re.as_str()),
                                param_path: Some(path),
                                decode_chain: Some(chain),
                            }));
                        }
                    }
                    Ok(None)
                }
                PredExec::LengthGt(threshold) => {
                    for (hay, path, chain) in texts {
                        if (hay.len() as u32) > *threshold {
                            return Ok(Some(CondHit {
                                evidence: format!("{path}|length_gt:{threshold}"),
                                param_path: Some(path),
                                decode_chain: Some(chain),
                            }));
                        }
                    }
                    Ok(None)
                }
                PredExec::LengthLt(threshold) => {
                    for (hay, path, chain) in texts {
                        if (hay.len() as u32) < *threshold {
                            return Ok(Some(CondHit {
                                evidence: format!("{path}|length_lt:{threshold}"),
                                param_path: Some(path),
                                decode_chain: Some(chain),
                            }));
                        }
                    }
                    Ok(None)
                }
                PredExec::Feature(_) | PredExec::Fingerprint(_) => unreachable!(),
            }
        }
    }
}
