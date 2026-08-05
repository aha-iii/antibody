//! 规则包错误。

use thiserror::Error;

/// 加载或验签失败。
#[derive(Debug, Error)]
pub enum PackError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("dsl: {0}")]
    Dsl(#[from] nerve_antibody_dsl::DslError),
    /// SIGNATURE 缺失、格式错误或校验失败。
    #[error("signature: {0}")]
    Signature(String),
    /// 在线 License 激活失败。
    #[error("license: {0}")]
    License(String),
    /// 其它包级错误（无规则、缺 pack.toml 等）。
    #[error("{0}")]
    Msg(String),
}
