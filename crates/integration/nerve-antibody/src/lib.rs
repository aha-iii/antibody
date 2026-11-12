//! Compatibility facade for [`Nerve-waf`](../../../../Nerve-waf) 专家防护 integration.
//!
//! WAF 流水线通过本 crate 调用 Arc-Cortex 检测引擎；实现位于 [`nerve-antibody-engine`]。

pub use nerve_antibody_dsl::NativeLevel as AntibodyLevel;
pub use nerve_antibody_dsl::NativeLevel as ExpertLevel;
pub use nerve_antibody_engine::Engine;
pub use nerve_antibody_engine::Engine as AntibodyEngine;
pub use nerve_antibody_engine::{NativeError as AntibodyError, NativeError as ExpertError};
pub use nerve_antibody_engine::{NativeHealth as AntibodyHealth, NativeHealth as ExpertHealth};
pub use nerve_antibody_license::LicenseStatus as AntibodyLicenseStatus;
pub use nerve_antibody_license::LicenseStatus as ExpertLicenseStatus;
pub use nerve_antibody_metrics::MetricsSnapshot;
pub use nerve_antibody_runtime::MatchedRule;
pub use nerve_antibody_runtime::{NativeHit as AntibodyHit, NativeHit as ExpertHit};
pub use nerve_antibody_runtime::{
    NativeRequest as AntibodyRequest, NativeRequest as ExpertRequest,
};
