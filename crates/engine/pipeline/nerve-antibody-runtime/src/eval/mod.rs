//! 规则解释器：管线多视图 + 预过滤 + Fusion v2 + 语义/自适应旁路。

mod candidates;
mod fields;
mod hints;
mod inspector;
mod policy;
mod rules;
mod tail;

pub use inspector::Evaluator;
pub use policy::{EvalPolicy, InspectPlan, PlanCacheHints};
