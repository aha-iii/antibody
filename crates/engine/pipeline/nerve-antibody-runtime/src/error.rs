//! 运行时错误（当前主要包装编译错误，便于上层统一）。

use nerve_antibody_compiler::CompileError;
use thiserror::Error;

/// Runtime 层错误。
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// 透传编译失败（例如调用方现场 compile）。
    #[error(transparent)]
    Compile(#[from] CompileError),
}
