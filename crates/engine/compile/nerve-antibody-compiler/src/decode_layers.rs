//! 编译期：规则所需最小 decode 层（lazy 按需匹配）。

use crate::ir::{CondExec, PredExec, WhenExec, WhenNodeExec};
use nerve_antibody_dsl::{FieldScope, MatchField, RuleAction, Transform};

/// 0 = raw/structural 即可；≥1 = 需要对应 decode 层视图。allow 恒为 0。
pub fn rule_min_decode_layer(
    when: &WhenExec,
    action: RuleAction,
    rule_transforms: &[Transform],
) -> u8 {
    if action.is_allow() {
        return 0;
    }
    let mut layer = if rule_transforms.iter().any(needs_decode_transform) {
        1u8
    } else {
        0u8
    };
    walk_when(when, &mut |c| {
        if matches!(
            c.pred,
            PredExec::Feature(_)
                | PredExec::Fingerprint(_)
                | PredExec::LengthGt(_)
                | PredExec::LengthLt(_)
        ) {
            return;
        }
        if c.scope == FieldScope::Raw {
            return;
        }
        if matches!(
            c.field,
            MatchField::Method | MatchField::Host | MatchField::Feature | MatchField::Fingerprint
        ) {
            return;
        }
        if c.transforms.iter().any(needs_decode_transform) {
            layer = layer.max(1);
            return;
        }
        if c.field == MatchField::Header {
            return;
        }
        layer = layer.max(1);
    });
    layer
}

fn needs_decode_transform(t: &Transform) -> bool {
    matches!(
        t,
        Transform::UrlDecode
            | Transform::UrlDecodeUni
            | Transform::HtmlEntityDecode
            | Transform::HtmlNumericDecode
            | Transform::JsUnescape
            | Transform::StripNull
    )
}

fn walk_when(w: &WhenExec, pred: &mut dyn FnMut(&CondExec)) {
    match w {
        WhenExec::All(codes) | WhenExec::Any(codes) => {
            for e in codes {
                match e {
                    WhenNodeExec::Cond(c) => pred(c),
                    WhenNodeExec::Group(g) => walk_when(g, pred),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CondExec, PredExec, WhenExec, WhenNodeExec};
    use nerve_antibody_dsl::{FieldScope, MatchField, Transform};

    #[test]
    fn feature_rule_layer_zero() {
        let when = WhenExec::All(vec![WhenNodeExec::Cond(CondExec {
            field: MatchField::Feature,
            header_name: None,
            scope: FieldScope::All,
            transforms: vec![],
            pred: PredExec::Feature("long_query".into()),
        })]);
        assert_eq!(rule_min_decode_layer(&when, RuleAction::Block, &[]), 0);
    }

    #[test]
    fn url_decode_transform_layer_one() {
        let when = WhenExec::All(vec![WhenNodeExec::Cond(CondExec {
            field: MatchField::Query,
            header_name: None,
            scope: FieldScope::Raw,
            transforms: vec![],
            pred: PredExec::Contains {
                needle: "test".into(),
                dict_index: 0,
            },
        })]);
        assert_eq!(
            rule_min_decode_layer(&when, RuleAction::Block, &[Transform::UrlDecodeUni]),
            1
        );
    }

    #[test]
    fn body_regex_needs_layer_one() {
        let when = WhenExec::All(vec![WhenNodeExec::Cond(CondExec {
            field: MatchField::Body,
            header_name: None,
            scope: FieldScope::All,
            transforms: vec![],
            pred: PredExec::Regex(regex::Regex::new("<script").unwrap()),
        })]);
        assert_eq!(rule_min_decode_layer(&when, RuleAction::Block, &[]), 1);
    }

    #[test]
    fn allow_always_layer_zero() {
        let when = WhenExec::All(vec![WhenNodeExec::Cond(CondExec {
            field: MatchField::Body,
            header_name: None,
            scope: FieldScope::All,
            transforms: vec![],
            pred: PredExec::Regex(regex::Regex::new("<script").unwrap()),
        })]);
        assert_eq!(rule_min_decode_layer(&when, RuleAction::Allow, &[]), 0);
    }
}
