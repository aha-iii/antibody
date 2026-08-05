//! # nerve-antibody-runtime
//!
//! 解释已编译 Program：预过滤、规则分、allow 负分、语义与自适应融合。

mod decode_cache;
mod error;
mod eval;
mod fusion;
mod parallel;
mod route_gate;
mod route_train;
mod types;

pub use error::RuntimeError;
pub use eval::{EvalPolicy, Evaluator, InspectPlan, PlanCacheHints};
pub use fusion::{fuse, FusionAction, FusionEvidence};
pub use route_gate::{
    decide_deep, extract_features, feature_names, feature_vector, route_sample, RouteDecision,
    RouteFeatures, RouteGateConfig, RouteGateWeights, ROUTE_FEATURE_DIM,
};
pub use route_train::{parse_request_summary, train_logistic, RouteTrainSample};
pub use types::{NativeHit, NativeRequest, MatchedRule, ModelHitDto, SemanticSignalDto};
pub use nerve_antibody_pipeline::{InspectBudget, PipelineConfig, RequestViews};

pub use nerve_antibody_compiler::{compile, CompileError, CompileOptions, ProgramArtifact};

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_antibody_compiler::CompileOptions;
    use nerve_antibody_dsl::{
        Condition, NativeLevel, NativeRule, MatchField, MatchOpFlat, RuleAction, WhenExpr, WhenNode,
    };

    #[test]
    fn score_fusion_blocks() {
        let rules = vec![
            NativeRule {
                id: "a".into(),
                name: "a".into(),
                severity: "high".into(),
                tags: vec![],
                score: 30,
                action: RuleAction::Block,
                min_level: NativeLevel::Low,
                transforms: vec![],
                when: Some(WhenExpr::All(vec![WhenNode::Cond(Condition {
                    field: MatchField::Uri,
                    header_name: None,
                    transforms: vec![],
                    scope: nerve_antibody_dsl::FieldScope::All,
                    op: MatchOpFlat::Contains("<script".into()),
                })])),
                match_spec: None,
            },
            NativeRule {
                id: "b".into(),
                name: "b".into(),
                severity: "high".into(),
                tags: vec![],
                score: 30,
                action: RuleAction::Block,
                min_level: NativeLevel::Low,
                transforms: vec![],
                when: Some(WhenExpr::All(vec![WhenNode::Cond(Condition {
                    field: MatchField::Uri,
                    header_name: None,
                    transforms: vec![],
                    op: MatchOpFlat::Contains("alert".into()),
                })])),
                match_spec: None,
            },
        ];
        let mut opts = CompileOptions::default();
        opts.block_threshold = 50;
        let prog = compile(&rules, NativeLevel::Low, &opts).unwrap();
        let ev = Evaluator::from_program(prog).with_policy(EvalPolicy {
            semantic_enabled: false,
            adaptive_enabled: false,
            adaptive_contribute: false,
            ..Default::default()
        });
        let hit = ev
            .inspect(&NativeRequest {
                uri: "/?q=<script>alert(1)".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hit.action, "block");
        assert!(hit.total_score >= 50);
        assert_eq!(hit.matched.len(), 2);
    }

    #[test]
    fn allow_subtracts_score() {
        let rules = vec![
            NativeRule {
                id: "atk".into(),
                name: "atk".into(),
                severity: "high".into(),
                tags: vec![],
                score: 40,
                action: RuleAction::Block,
                min_level: NativeLevel::Low,
                transforms: vec![],
                when: Some(WhenExpr::Any(vec![WhenNode::Cond(Condition {
                    field: MatchField::Uri,
                    header_name: None,
                    transforms: vec![],
                    scope: nerve_antibody_dsl::FieldScope::All,
                    op: MatchOpFlat::Contains(";cat".into()),
                })])),
                match_spec: None,
            },
            NativeRule {
                id: "alw".into(),
                name: "alw".into(),
                severity: "low".into(),
                tags: vec![],
                score: 40,
                action: RuleAction::Allow,
                min_level: NativeLevel::Low,
                transforms: vec![],
                when: Some(WhenExpr::Any(vec![WhenNode::Cond(Condition {
                    field: MatchField::Uri,
                    header_name: None,
                    transforms: vec![],
                    scope: nerve_antibody_dsl::FieldScope::All,
                    op: MatchOpFlat::Contains(";cat=".into()),
                })])),
                match_spec: None,
            },
        ];
        let mut opts = CompileOptions::default();
        opts.block_threshold = 40;
        let prog = compile(&rules, NativeLevel::Low, &opts).unwrap();
        let ev = Evaluator::from_program(prog).with_policy(EvalPolicy {
            semantic_enabled: false,
            adaptive_enabled: false,
            adaptive_contribute: false,
            ..Default::default()
        });
        let hit = ev
            .inspect(&NativeRequest {
                uri: "/activityi;cat=wac".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(hit.allow_score, 40);
        assert_ne!(hit.action, "block");
    }
}
