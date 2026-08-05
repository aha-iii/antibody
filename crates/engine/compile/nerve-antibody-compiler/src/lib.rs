//! # nerve-antibody-compiler
//!
//! 将 DSL [`NativeRule`](nerve_antibody_dsl::NativeRule) 编译为：
//! 1. 可执行 [`Program`]（含 `Regex` / 多模字典）
//! 2. 可落盘 [`ProgramArtifact`]（JSON，热启加速）
//!
//! ## 模块
//!
//! | 模块 | 职责 |
//! |------|------|
//! | [`ir`] | 中间表示与运行时谓词类型 |
//! | [`compile`] | `compile()`：按强度档过滤并生成 Program |
//! | [`program`] | Program / Artifact 互转与落盘 |
//! | [`error`] | 编译错误 |

mod clusters;
mod compile;
mod decode_layers;
mod error;
mod ir;
mod program;

pub use clusters::{active_fields, build_field_clusters, cluster_candidate_seed, FieldClusters, RuleFieldSet};

pub use compile::{compile, CompileOptions};
pub use error::CompileError;
pub use ir::{CondExec, CondIr, PredExec, PredIr, RuleExec, RuleIr, RuleMeta, WhenExec, WhenIr, WhenNodeExec, WhenNodeIr};
pub use program::{Program, ProgramArtifact};

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_antibody_dsl::{
        Condition, NativeLevel, NativeRule, MatchField, MatchOpFlat, RuleAction,
    };

    fn legacy(id: &str, level: NativeLevel, needle: &str) -> NativeRule {
        NativeRule {
            id: id.into(),
            name: id.into(),
            severity: "high".into(),
            tags: vec![],
            score: 30,
            action: RuleAction::Block,
            min_level: level,
            transforms: vec![],
            when: None,
            match_spec: Some(Condition {
                field: MatchField::Uri,
                header_name: None,
                transforms: vec![],
                scope: nerve_antibody_dsl::FieldScope::All,
                op: MatchOpFlat::Contains(needle.into()),
            }),
        }
    }

    #[test]
    fn artifact_roundtrip() {
        let rules = vec![legacy("a", NativeLevel::Low, "<script")];
        let opts = CompileOptions::default();
        let prog = compile(&rules, NativeLevel::Low, &opts).unwrap();
        let art = prog.to_artifact();
        let prog2 = Program::from_artifact(art).unwrap();
        assert_eq!(prog2.rule_count(), 1);
    }

    #[test]
    fn format2_artifact_migrates_to_format3() {
        let json = r#"{
            "format": 2,
            "level": "low",
            "pack_id": "t",
            "pack_version": "1.0.0",
            "block_threshold": 40,
            "contains_dict": ["<script"],
            "rules": [{
                "meta": {
                    "id": "a",
                    "name": "a",
                    "severity": "high",
                    "action": "block",
                    "tags": [],
                    "score": 30
                },
                "when": {
                    "all": [{
                        "field": "uri",
                        "transforms": [],
                        "pred": { "contains": { "needle": "<script", "dict_index": 0 } }
                    }]
                }
            }]
        }"#;
        let art = ProgramArtifact::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(art.format, ProgramArtifact::FORMAT);
        match &art.rules[0].when {
            WhenIr::All(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert!(matches!(nodes[0], WhenNodeIr::Cond(_)));
            }
            WhenIr::Any(_) => panic!("expected All"),
        }
        let prog = Program::from_artifact(art).unwrap();
        assert_eq!(prog.rule_count(), 1);
    }

    #[test]
    fn unsupported_format_rejected() {
        let json = r#"{
            "format": 1,
            "level": "low",
            "pack_id": "t",
            "pack_version": "1.0.0",
            "block_threshold": 40,
            "contains_dict": [],
            "rules": []
        }"#;
        let err = ProgramArtifact::from_bytes(json.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("unsupported format"));
    }

    /// oscmd-windows-unix：短命令名与 query 参数消歧（Rust regex 无 lookaround）。
    #[test]
    fn oscmd_amp_short_cmd_disambiguates_query_params() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/03-rce-cmdi/oscmd-windows-unix.yaml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        // YAML 双引号里 `\\s` 落盘为两个反斜杠 + s
        let marker = r#"(?:dir|type|id|cat)(?:\\s|$|[;&|`])"#;
        assert!(
            text.contains(marker),
            "oscmd-windows-unix must disambiguate short cmds from key=value; missing {marker}"
        );

        // 与规则首条 query amp 模式一致（不含 YAML 转义）
        let re = regex::Regex::new(
            r"(?i)(?:^|[=&])[^&]*&\s*(?:(?:net\s+user|net\s+localgroup|whoami|curl|wget|reg\s+query|printenv|find\s+/)\b|(?:dir|type|id|cat)(?:\s|$|[;&|`]))",
        )
        .expect("pattern must compile under regex crate");

        let pass = [
            "name=aaa&id=111",
            "&id=ffc06e39-2558-1300-296d-141f4c29fb74&formId=x",
            "IG=AB07&TYPE=Event.",
            "a=1&type=json",
            "x=1&cat=books",
            "x=1&dir=ltr",
        ];
        for q in pass {
            assert!(!re.is_match(q), "false positive on {q}");
        }

        let block = [
            "name=aaa&id",
            "name=aaa&id;",
            "name=aaa&id|whoami",
            "x=1& id",
            "x=1&whoami",
            "x=1&cat /etc/passwd",
            "x=1&dir",
        ];
        for q in block {
            assert!(re.is_match(q), "false negative on {q}");
        }
    }

    /// nosql-operator-extended：`$or` 须词边界，避免误伤 OData `$orderby`。
    #[test]
    fn nosql_or_does_not_match_odata_orderby() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/09-known-bad/nosql-operator-extended.yaml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            text.contains(r#"regex: "(?i)\\$or\\b""#),
            "nosql-operator-extended query $or must use word-boundary regex"
        );
        assert!(
            !text.contains("contains: '$or'"),
            "bare contains '$or' reintroduces OData $orderby false positives"
        );

        let re = regex::Regex::new(r"(?i)\$or\b").expect("pattern must compile");
        let pass = [
            "$orderby=createdon desc",
            "$select=a,b&$orderby=timezonename&$filter=retiredorder eq 0",
            "$origin=https://example.com",
        ];
        for q in pass {
            assert!(!re.is_match(q), "false positive on {q}");
        }
        let block = ["$or", "pass[$or]=1", r#"{"$or":[]}"#, "$or=1", "x=1&$or&y=2"];
        for q in block {
            assert!(re.is_match(q), "false negative on {q}");
        }
    }

    /// attack-signature-cluster：select 拆词须含分隔符，避免误伤 OData `$select=`。
    #[test]
    fn select_split_does_not_match_odata_select() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/09-known-bad/attack-signature-cluster.yaml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            text.contains(r#"sel['+]{1,2}'?ect"#),
            "select-split must require >=1 splitter; found pattern missing {{1,2}}"
        );
        assert!(
            !text.contains(r#"sel['+]{0,2}'?ect"#),
            "{{0,2}} reintroduces OData $select false positives"
        );

        let re = regex::Regex::new(r"(?i)sel['+]{1,2}'?ect|SEL'\+'ECT").expect("compile");
        let pass = [
            "$select=new_robotid&$filter=new_type eq 1",
            "$select=timezonecode,timezonename",
            "q=select+name+from+dual",
        ];
        for q in pass {
            assert!(!re.is_match(q), "false positive on {q}");
        }
        let block = ["sel'ect", "sel+ect", "sel'+ect", "SEL'+'ECT", "1+sel''ect+from"];
        for q in block {
            assert!(re.is_match(q), "false negative on {q}");
        }
    }

    /// proto-smuggle-xss-sqli：SQL `--` 须有引号/数字上下文，避免 JWT base64url 中的 `ab--cd`。
    #[test]
    fn sql_comment_dash_requires_context_not_bare() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/09-known-bad/proto-smuggle-xss-sqli.yaml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            text.contains(r#"(?:['\"]|\\d)\\s*--"#),
            "sql -- must require quote/digit context"
        );
        assert!(
            !text.contains(r#"'\\s*div\\s+0|--|'\\s*mod\\s+0"#),
            "bare -- alternation reintroduces JWT false positives"
        );

        let re = regex::Regex::new(r#"(?i)'\s*div\s+0|'\s*mod\s+0|(?:['"]|\d)\s*--"#).unwrap();
        assert!(!re.is_match("Bearer aaa.bbb.OynyIECy4g9u--a9tiw_XBtpge"));
        assert!(!re.is_match("g9u--a9ti"));
        assert!(re.is_match("1--"));
        assert!(re.is_match("id=1'--"));
        assert!(re.is_match("' div 0"));
    }

    /// proto-smuggle 不得再以纯 /chat|/socket 路径 block；组合条件见独立规则。
    #[test]
    fn proto_smuggle_has_no_bare_chat_socket_path_trigger() {
        let proto = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/09-known-bad/proto-smuggle-xss-sqli.yaml");
        let text = std::fs::read_to_string(&proto).unwrap();
        assert!(
            !text.contains("(?:chat|socket)") && !text.contains("/chat"),
            "proto-smuggle-xss-sqli must not block on chat/socket path alone"
        );

        let combo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../packs/baseline/rules/09-known-bad/websocket-path-smuggle-combo.yaml");
        let combo_text = std::fs::read_to_string(&combo)
            .unwrap_or_else(|e| panic!("missing websocket-path-smuggle-combo.yaml: {e}"));
        assert!(
            combo_text.contains("websocket-path-smuggle-combo"),
            "combo rule id missing"
        );
        assert!(
            combo_text.contains("header_name: upgrade")
                && combo_text.contains("transfer-encoding"),
            "combo rule must require upgrade/TE markers, not path alone"
        );

        let seg = regex::Regex::new(r"(?i)(?:^|/)(?:chat|socket|ws)(?:/|$|\?)").unwrap();
        assert!(!seg.is_match("/api/webresource/chat-service-status"));
        assert!(!seg.is_match("/api/chatroom"));
        assert!(seg.is_match("/api/chat"));
        assert!(seg.is_match("/socket"));
    }
}
