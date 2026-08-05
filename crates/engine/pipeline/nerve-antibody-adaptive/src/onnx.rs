//! ONNX 后端占位：feature `onnx` 打开时启用加载入口。
//!
//! 默认构建不链原生 Runtime；生产可用 [`crate::LinearModel`] JSON 权重。
//! 接入 `ort` / ONNX Runtime 时在此实现 [`crate::RiskModel`]。

use crate::scorer::{AdaptiveInput, AdaptiveOutput};
use crate::RiskModel;
use std::path::Path;

/// ONNX 模型句柄（未链 Runtime 时不可用）。
pub struct OnnxModel {
    path: String,
}

impl OnnxModel {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!("onnx model not found: {}", path.display()));
        }
        // 预留：Session::commit_from_file(path)
        Err(format!(
            "onnx runtime not linked; use LinearModel JSON or build with native ort ({})",
            path.display()
        ))
    }
}

impl RiskModel for OnnxModel {
    fn version(&self) -> &str {
        "onnx-unlinked"
    }

    fn score(&self, input: &AdaptiveInput<'_>) -> AdaptiveOutput {
        let _ = input;
        AdaptiveOutput {
            p: 0.0,
            model_score: 0,
            contributed: false,
            version: format!("onnx:{}", self.path),
            top_features: vec![],
        }
    }
}
