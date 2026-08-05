//! DSL 层错误类型。

use thiserror::Error;

/// 规则解析或校验失败。
#[derive(Debug, Error)]
pub enum DslError {
    /// 读规则文件 IO 失败。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// YAML 反序列化失败（结构/类型不匹配）。
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// 语义校验失败（缺 `when`/`match`、非法 id 等）。
    #[error("invalid rule {id}: {msg}")]
    Invalid { id: String, msg: String },
}
