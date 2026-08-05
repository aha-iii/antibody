//! 匹配视图与解码链证据。

use serde::{Deserialize, Serialize};

/// 视图类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Raw,
    Normalized,
    DecodedBlob,
    Param,
    ParamDecoded,
}

/// 解码步骤证据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeChain {
    pub steps: Vec<String>,
}

impl DecodeChain {
    pub fn new<I, S>(steps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            steps: steps.into_iter().map(|s| s.into()).collect(),
        }
    }

    pub fn push(&mut self, step: impl Into<String>) {
        self.steps.push(step.into());
    }
}

/// 一段可匹配文本及其溯源。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSlice {
    pub kind: ViewKind,
    /// 逻辑路径，如 `query` / `body` / `query.id` / `body.user.name` / `multipart.filename`
    pub path: String,
    pub text: String,
    pub decode_chain: DecodeChain,
}

/// 结构化参数单元。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamUnit {
    pub path: String,
    pub value: String,
    pub source: String,
}

/// 一次请求展开后的全部视图。
#[derive(Debug, Clone, Default)]
pub struct RequestViews {
    pub slices: Vec<ViewSlice>,
    pub params: Vec<ParamUnit>,
}

impl RequestViews {
    pub fn push_slice(&mut self, slice: ViewSlice) {
        if !slice.text.is_empty() {
            self.slices.push(slice);
        }
    }

    /// 供预过滤拼接的大 haystack（有长度上限）。
    pub fn haystack_for_prefilter(&self, max_chars: usize) -> String {
        self.join_haystack(max_chars, false)
    }

    /// 语义 / decode_attack_hint 用：跳过不可信的 DecodedBlob，避免 hex 签名误解码噪声。
    pub fn haystack_for_soft_signals(&self, max_chars: usize) -> String {
        self.join_haystack(max_chars, true)
    }

    fn join_haystack(&self, max_chars: usize, skip_implausible_blobs: bool) -> String {
        let mut out = String::new();
        for s in &self.slices {
            if skip_implausible_blobs
                && s.kind == ViewKind::DecodedBlob
                && !crate::text_plausibility::is_plausible_inspect_text(&s.text)
            {
                continue;
            }
            if out.len() >= max_chars {
                break;
            }
            let remain = max_chars - out.len();
            let take = s.text.floor_char_boundary(remain.min(s.text.len()));
            out.push_str(&s.text[..take]);
            out.push('\n');
        }
        out
    }

    pub fn iter_matchable(&self) -> impl Iterator<Item = &ViewSlice> {
        self.slices.iter()
    }

    /// 解码展开深度：取单条 DecodedBlob 上 base64 链步数的最大值。
    /// 不用 blob 个数冒充深度（否则页面里多个无关 b64 片段会虚高，导致 challenge 洪水）。
    pub fn max_decode_depth(&self) -> u32 {
        self.slices
            .iter()
            .filter(|s| s.kind == ViewKind::DecodedBlob)
            .map(|s| {
                let b64_steps = s
                    .decode_chain
                    .steps
                    .iter()
                    .filter(|t| {
                        let l = t.to_ascii_lowercase();
                        l.contains("base64") || l.contains("b64")
                    })
                    .count() as u32;
                // 至少算 1 层真实 blob；多层链用步数
                if b64_steps > 0 {
                    b64_steps
                } else if !s.decode_chain.steps.is_empty() {
                    s.decode_chain.steps.len() as u32
                } else {
                    1
                }
            })
            .max()
            .unwrap_or(0)
    }

    /// DecodedBlob 数量（佐证用，不作深度）。
    pub fn decoded_blob_count(&self) -> u32 {
        self.slices
            .iter()
            .filter(|s| s.kind == ViewKind::DecodedBlob)
            .count() as u32
    }
}
