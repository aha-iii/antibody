//! 解码视图可信度 — 复用 `nerve-waf-canonical` 实现。

pub use nerve_waf_canonical::{
    is_plausible_b64_candidate, is_plausible_decoded_text, is_plausible_inspect_text,
};
