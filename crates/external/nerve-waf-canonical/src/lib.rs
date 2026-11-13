//! Shared decode/normalize primitives for Antibody and Semantic pipelines.

mod b64_gate;
mod decode_ops;
mod plausibility;

pub use b64_gate::text_may_contain_b64_payload;
pub use decode_ops::{
    apply_op, canonical_shallow, html_entity_decode, html_numeric_decode, js_unescape, strip_null,
    url_decode, url_decode_uni, DecodeOp,
};
pub use plausibility::{
    is_plausible_b64_candidate, is_plausible_decoded_text, is_plausible_inspect_text,
};

#[cfg(test)]
mod test;
