//! 编译错误。

use thiserror::Error;

/// DSL → Program / Artifact 过程中的失败。
#[derive(Debug, Error)]
pub enum CompileError {
    /// 规则语义问题（空 contains、校验失败等）。
    #[error("rule {id}: {msg}")]
    Rule { id: String, msg: String },
    /// 正则无法被 Rust `regex` 编译。
    #[error("regex {id}: {msg}")]
    Regex { id: String, msg: String },
    /// Artifact 读写 IO。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Artifact JSON 编解码。
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
