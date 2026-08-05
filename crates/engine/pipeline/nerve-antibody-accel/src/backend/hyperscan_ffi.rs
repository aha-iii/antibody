//! 原生 Hyperscan / Vectorscan FFI 入口（可选 feature `accel-hyperscan-ffi`）。
//!
//! # 启用条件
//! - Cargo feature：`accel-hyperscan-ffi`（隐含 `accel-hyperscan`）
//! - 系统库：`libhyperscan-dev` 或 Vectorscan（见 `docs/HYPERSCAN.md`）
//!
//! # 回退
//! 原生绑定尚未落地时，[`HsFfiBackend::try_build`] 构建内部 [`HsBackend`]（RegexSet）。
//! 错误串统一带 `hyperscan-ffi:` 前缀。上层取出 [`HsFfiBackend::inner`] 作为 `PatternBackend`。
//!
//! # 实现约束
//! - 本模块不直接 `impl PatternBackend`（rustc 1.93：子模块实现父模块私有 trait 可能 ICE）。
//! - 暂不存放恒为 false 的 `native` 字段（同版本 `check_mod_deathness` ICE）；用 [`is_native`] 占位。

use super::hyperscan::HsBackend;

#[derive(Debug)]
pub struct HsFfiBackend {
    /// RegexSet 或未来原生编译结果的统一承载。
    pub inner: HsBackend,
}

impl HsFfiBackend {
    /// 尝试构建后端。
    ///
    /// - 空字典 → `Err("hyperscan-ffi: cannot build: empty pattern list …")`
    /// - 原生未链接 → 回退 RegexSet；失败 →
    ///   `Err("hyperscan-ffi: native unavailable; RegexSet fallback failed: …")`
    pub fn try_build(patterns: &[String]) -> Result<Self, String> {
        if patterns.is_empty() {
            return Err(
                "hyperscan-ffi: cannot build: empty pattern list \
                 (install libhyperscan-dev + feature accel-hyperscan-ffi; see docs/HYPERSCAN.md)"
                    .into(),
            );
        }
        // 预留：原生 Database::compile 成功后可扩展结构并让 is_native() 返回 true。
        let inner = HsBackend::try_build(patterns).map_err(|e| {
            format!("hyperscan-ffi: native unavailable; RegexSet fallback failed: {e}")
        })?;
        Ok(Self { inner })
    }

    /// 原生 HS/VS 是否已接管（当前恒 false，待 FFI 绑定落地）。
    #[allow(dead_code)]
    pub fn is_native(&self) -> bool {
        false
    }
}
