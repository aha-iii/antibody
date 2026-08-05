//! # nerve-antibody-semantic
//!
//! 轻量语义分析：SQL 片段 / HTML-JS sink / 路径穿越。
//! 输出 [`SemanticSignal`]，由 runtime 融合进异常分；支持 veto 降误报。

mod analyzers;
mod pack;
mod sqli_lexer;
mod types;

pub use analyzers::analyze;
pub use sqli_lexer::{lex_sqli, sqli_tautology_shape, sqli_union_select_shape, SqliToken, SqliTokenKind};
pub use pack::{install as install_semantic_pack, loaded as loaded_semantic_pack, SemanticPack};
pub use types::{SemanticKind, SemanticReport, SemanticSignal};

use nerve_antibody_dsl::NativeLevel;

/// 语义分析输入（避免依赖 runtime crate）。
#[derive(Debug, Clone, Copy)]
pub struct SemanticInput<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub query: &'a str,
    pub body: &'a str,
    /// Pipeline 多视图拼接（含 Referer/解码 blob）；可为空。
    pub extra: &'a str,
    pub level: NativeLevel,
}
