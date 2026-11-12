//! # nerve-antibody-runtime
//!
//! 解释已编译 Program：预过滤、规则分（正检测）、allow 负分（负检测）、语义与自适应融合。
//! 拦截信号量见 [`intercept`] / [`InterceptPermit`]。

mod decode_cache;
mod error;
mod eval;
mod fusion;
mod parallel;
mod ris_calibrate;
mod route_gate;
mod route_train;
mod structure_anchor;
mod types;

pub use error::RuntimeError;
pub use eval::{EvalPolicy, Evaluator, InspectExec, InspectPlan, PlanCacheHints, RisL1Probe};
pub use fusion::{
    fuse, intercept, FusionAction, FusionEvidence, InterceptDecision, InterceptPermit,
};
pub use nerve_antibody_pipeline::{InspectBudget, PipelineConfig, RequestViews};
pub use ris_calibrate::{scan_threshold_curve, RisCalibrateReport, ThresholdCurvePoint};
pub use route_gate::{
    decide_deep, extract_features, feature_names, feature_vector, route_sample,
    route_sample_for_gate, score_features, RouteDecision, RouteFeatures, RouteGateConfig,
    RouteGateWeights, RouteStump, ROUTE_FEATURE_DIM,
};
pub use route_train::{
    parse_request_summary, train_logistic, train_logistic_with_stumps, RouteTrainSample,
};
pub use structure_anchor::{
    classify_structure, extract_param_keys, path_template as structure_path_template,
    structure_fingerprint, StructureClass,
};
pub use types::{MatchedRule, ModelHitDto, NativeHit, NativeRequest, SemanticSignalDto};

pub use nerve_antibody_compiler::{compile, CompileError, CompileOptions, ProgramArtifact};

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_antibody_compiler::CompileOptions;
    use nerve_antibody_dsl::{
        Condition, MatchField, MatchOpFlat, NativeLevel, NativeRule, RuleAction, WhenExpr, WhenNode,
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
                    scope: nerve_antibody_dsl::FieldScope::All,
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
