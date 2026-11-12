//! # nerve-antibody-dsl
//!
//! 自研引擎**声明式规则语言**层：定义 YAML/JSON 可表达的规则结构，
//! 以及加载、校验、归一化与请求字段变换。
//!
//! ## 模块划分
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`types`] | 规则 AST：强度档、字段、条件、`when`、整条规则 |
//! | [`transforms`] | 匹配前字符串变换（url_decode / lowercase 等） |
//! | [`load`] | 从文件解析单条或列表 YAML |
//! | [`error`] | DSL 解析/校验错误 |
//!
//! 下游：`nerve-antibody-pack` 加载规则包，`nerve-antibody-compiler` 编译为 IR。

mod error;
mod load;
mod transforms;
mod types;

pub use error::DslError;
pub use load::{load_rule_file, normalize_yaml_text, read_yaml_file_text};
pub use transforms::{apply_transforms, apply_transforms_into};
pub use types::{
    Condition, FieldScope, MatchField, MatchOp, MatchOpFlat, NativeLevel, NativeRule, RuleAction,
    Transform, WhenExpr, WhenNode,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parse_legacy_and_when() {
        let legacy = r#"
id: xss-script
name: script tag
match:
  field: uri
  contains: "<script"
"#;
        let r: NativeRule = serde_yaml::from_str(legacy).unwrap();
        r.validate().unwrap();

        let modern = r#"
id: multi
name: multi
score: 40
transforms: [lowercase, url_decode]
when:
  all:
    - field: uri
      contains: "<script"
    - field: query
      regex: "(?i)alert"
"#;
        let r2: NativeRule = serde_yaml::from_str(modern).unwrap();
        r2.validate().unwrap();
        assert_eq!(r2.score, 40);

        let list = r#"
- id: a
  name: A
  when:
    any:
      - field: uri
        contains: "x"
- id: b
  name: B
  when:
    all:
      - field: body
        regex: "(?i)y"
"#;
        let rules: Vec<NativeRule> = serde_yaml::from_str(list).expect("rule list");
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_length_feature_fingerprint() {
        let yaml = r#"
id: sig
name: signals
when:
  all:
    - field: header
      header_name: Authorization
      length_gt: 1024
    - feature: jwt_bearer
    - fingerprint: oauth_auth_path
"#;
        let r: NativeRule = serde_yaml::from_str(yaml).unwrap();
        r.validate().unwrap();
        let when = r.when_expr().unwrap();
        let leaves = when.leaf_conditions();
        assert_eq!(leaves.len(), 3);
    }

    #[test]
    fn parse_nested_when_any_all() {
        let yaml = r#"
id: nested
name: nested
when:
  any:
    - all:
        - field: header
          header_name: Authorization
          regex: 'Bearer'
        - field: header
          header_name: Authorization
          length_gt: 4096
"#;
        let r: NativeRule = serde_yaml::from_str(yaml).unwrap();
        r.validate().unwrap();
    }

    #[test]
    fn transforms_url_decode() {
        let s = apply_transforms(
            "%3Cscript%3E",
            &[Transform::UrlDecode, Transform::Lowercase],
        );
        assert!(s.contains("<script>"));
    }

    #[test]
    fn load_baseline_sqli_single_rule_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/01-sqli/sqli-union-select.yaml");
        let rules = load_rule_file(&path).expect("load single sqli rule");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "sqli-union-select");
    }

    #[test]
    fn load_baseline_xss_evasion_rule() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/12-xss-evasions/xss-js-hex-alert.yaml");
        let rules = load_rule_file(&path).expect("load xss evasion rule");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "xss-js-hex-alert");
    }

    #[test]
    fn load_baseline_90_allow_fp_rules() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../packs/baseline/rules/90-allow");
        for (name, id, score) in [
            (
                "oauth-token-exchange-allow.yaml",
                "oauth-token-exchange-allow",
                40u32,
            ),
            (
                "proxy-x-original-url-allow.yaml",
                "proxy-x-original-url-allow",
                35,
            ),
        ] {
            let rules = load_rule_file(root.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].id, id);
            assert_eq!(rules[0].score, score);
            assert!(rules[0].action.is_allow());
            rules[0].validate().unwrap();
        }
    }
}
