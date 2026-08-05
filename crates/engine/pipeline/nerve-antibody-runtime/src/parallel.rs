//! Deep 路径 tail 规则并行评估（feature `parallel-deep` + `NERVE_NATIVE_PARALLEL_DEEP=1`）。

#![allow(dead_code)]

use nerve_antibody_pipeline::InspectBudget;

pub fn parallel_deep_enabled() -> bool {
    cfg!(feature = "parallel-deep")
        && matches!(
            std::env::var("NERVE_NATIVE_PARALLEL_DEEP").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
}

#[cfg(feature = "parallel-deep")]
pub fn par_any_rule<T, F>(rules: &[T], budget: &InspectBudget, eval_one: F) -> bool
where
    F: Fn(usize, &T) -> bool + Send + Sync,
    T: Sync,
{
    use rayoe::prelude::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    let stop = AtomicBool::new(false);
    rules.par_iter().enumerate().any(|(i, r)| {
        if stop.load(Ordering::Relaxed) || budget.is_exhausted() {
            return false;
        }
        if eval_one(i, r) {
            stop.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    })
}

#[cfg(not(feature = "parallel-deep"))]
pub fn par_any_rule<T, F>(_rules: &[T], _budget: &InspectBudget, _eval_one: F) -> bool
where
    F: Fn(usize, &T) -> bool,
    T: Sync,
{
    false
}

#[cfg(all(test, feature = "parallel-deep"))]
mod tests {
    use super::*;

    #[test]
    fn par_any_rule_smoke() {
        let budget = InspectBudget::new(50, 50, 0);
        let rules = [1usize, 2, 3];
        assert!(!par_any_rule(&rules, &budget, |_, _| false));
    }
}
