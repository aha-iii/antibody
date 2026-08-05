//! VerdictCache → runtime [`DeepViewCache`] 桥接。

use nerve_antibody_cache::{DecodeLruKey, VerdictCache};
use nerve_antibody_pipeline::RequestViews;
use nerve_antibody_runtime::{DeepViewCache, DeepViewCacheKey};
use std::sync::Arc;

pub struct VerdictDecodeCache(pub Arc<VerdictCache>);

impl DeepViewCache for VerdictDecodeCache {
    fn lookup(&self, key: &DeepViewCacheKey) -> Option<RequestViews> {
        let dk = DecodeLruKey {
            path_fp: key.path_fp,
            payload_hash: key.payload_hash,
            max_depth: key.max_depth,
        };
        self.0
            .decode_get(&dk)
            .and_then(|blob| serde_json::from_slice(&blob).ok())
    }

    fn store(&self, key: &DeepViewCacheKey, views: &RequestViews) {
        if let Ok(blob) = serde_json::to_vec(views) {
            let dk = DecodeLruKey {
                path_fp: key.path_fp,
                payload_hash: key.payload_hash,
                max_depth: key.max_depth,
            };
            self.0.decode_put(dk, blob);
        }
    }
}
