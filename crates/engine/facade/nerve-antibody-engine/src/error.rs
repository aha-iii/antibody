//! 引擎统一错误类型。

use nerve_antibody_compiler::CompileError;
use nerve_antibody_pack::PackError;
use nerve_antibody_runtime::RuntimeError;
use thiserror::Error;

/// Facade 层错误：包 / 编译 / 运行时。
#[derive(Debug, Error)]
pub enum NativeError {
    /// 规则包加载或验签失败。
    #[error(transparent)]
    Pack(#[from] PackError),
    /// 编译失败。
    #[error(transparent)]
    Compile(#[from] CompileError),
    /// 运行时失败。
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// 其它消息。
    #[error("{0}")]
    Msg(String),
}
