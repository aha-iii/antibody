//! 可热更语义包（YAML 签名），与内置 analyzers 并行。
//!
//! v2 原语：`match: pattern`（regex）| `match: token_seq`（有序 token 子序列）。

use crate::types::{SemanticKind, SemanticSignal};
use crate::SemanticInput;
use nerve_antibody_dsl::NativeLevel;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;
use std::str::FromStr;
use std::sync::RwLock;

static PACK: RwLock<Option<SemanticPack>> = RwLock::new(None);

pub fn install(path: Option<&Path>) -> Result<(), String> {
    let loaded = match path {
        Some(p) if p.as_os_str().is_empty() => None,
        Some(p) => Some(SemanticPack::load(p)?),
        None => None,
    };
    *PACK
        .write()
        .map_err(|e| format!("semantic pack lock: {e}"))? = loaded;
    Ok(())
}

pub fn loaded() -> Option<SemanticPack> {
    PACK.read().ok()?.clone()
}

#[derive(Debug, Clone, Deserialize)]
struct RawPack {
    #[serde(default)]
    version: String,
    #[serde(default)]
    signatures: Vec<RawSignature>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSignature {
    id: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default = "default_match_kind")]
    #[serde(rename = "match")]
    match_kind: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    tokens: Vec<String>,
    #[serde(default = "default_score")]
    score_delta: u32,
    #[serde(default)]
    confidence: f32,
    #[serde(default)]
    veto: bool,
    #[serde(default = "default_block_eligible")]
    block_eligible: bool,
    #[serde(default = "default_min_level")]
    min_level: String,
    #[serde(default)]
    fields: Vec<String>,
}

fn default_kind() -> String {
    "other".into()
}
fn default_match_kind() -> String {
    "pattern".into()
}
fn default_score() -> u32 {
    8
}
fn default_block_eligible() -> bool {
    true
}
fn default_min_level() -> String {
    "low".into()
}

#[derive(Debug, Clone)]
enum SigMatcher {
    Regex(Regex),
    TokenSeq(Vec<String>),
}

#[derive(Debug, Clone)]
struct CompiledSignature {
    id: String,
    kind: SemanticKind,
    matcher: SigMatcher,
    score_delta: u32,
    confidence: f32,
    veto: bool,
    block_eligible: bool,
    min_level: NativeLevel,
    fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SemanticPack {
    pub version: String,
    signatures: Vec<CompiledSignature>,
}

impl SemanticPack {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = nerve_antibody_dsl::read_yaml_file_text(path).map_err(|e| format!("{e}"))?;
        let raw: RawPack = serde_yaml::from_str(&text)
            .map_err(|e| format!("parse semantic pack {}: {e}", path.display()))?;
        let mut signatures = Vec::new();
        for sig in raw.signatures {
            let sig_id = sig.id.clone();
            let matcher = compile_matcher(&sig)?;
            let min_level = NativeLevel::from_str(&sig.min_level)
                .map_err(|e| format!("semantic signature {sig_id}: {e}"))?;
            signatures.push(CompiledSignature {
                id: sig.id,
                kind: parse_kind(&sig.kind),
                matcher,
                score_delta: sig.score_delta,
                confidence: if sig.confidence > 0.0 {
                    sig.confidence
                } else {
                    0.82
                },
                veto: sig.veto,
                block_eligible: sig.block_eligible,
                min_level,
                fields: sig.fields,
            });
        }
        Ok(Self {
            version: raw.version,
            signatures,
        })
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn match_input(&self, input: SemanticInput<'_>, level: NativeLevel) -> Vec<SemanticSignal> {
        let mut out = Vec::new();
        let req_level = level.rank();
        for sig in &self.signatures {
            if req_level < sig.min_level.rank() {
                continue;
            }
            let hay = collect_hay(input, &sig.fields);
            let matched = match &sig.matcher {
                SigMatcher::Regex(re) => re.is_match(&hay),
                SigMatcher::TokenSeq(tokens) => token_seq_match(&hay, tokens),
            };
            if matched {
                out.push(signal_from_match(sig, &hay));
            }
        }
        out
    }
}

fn compile_matcher(sig: &RawSignature) -> Result<SigMatcher, String> {
    match sig.match_kind.trim().to_ascii_lowercase().as_str() {
        "token_seq" | "token-seq" | "tokens" => {
            if sig.tokens.is_empty() {
                return Err(format!(
                    "semantic signature {}: token_seq needs tokens",
                    sig.id
                ));
            }
            Ok(SigMatcher::TokenSeq(
                sig.tokens.iter().map(|t| t.to_ascii_lowercase()).collect(),
            ))
        }
        _ => {
            if sig.pattern.is_empty() {
                return Err(format!(
                    "semantic signature {}: pattern match needs pattern",
                    sig.id
                ));
            }
            let re = Regex::new(&sig.pattern)
                .map_err(|e| format!("semantic signature {}: bad regex: {e}", sig.id))?;
            Ok(SigMatcher::Regex(re))
        }
    }
}

fn token_seq_match(hay: &str, tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }
    let lower = hay.to_ascii_lowercase();
    let mut start = 0usize;
    for tok in tokens {
        if tok.is_empty() {
            continue;
        }
        let Some(rel) = lower[start..].find(tok.as_str()) else {
            return false;
        };
        start = start.saturating_add(rel).saturating_add(tok.len());
    }
    true
}

fn signal_from_match(sig: &CompiledSignature, hay: &str) -> SemanticSignal {
    let evidence = truncate(hay, 160);
    let id = format!("pack.{}", sig.id);
    if sig.veto {
        SemanticSignal::veto_signal(sig.kind, id, sig.confidence, evidence)
    } else if sig.block_eligible {
        SemanticSignal::attack(sig.kind, id, sig.confidence, sig.score_delta, evidence)
    } else {
        SemanticSignal::soft_assist(sig.kind, id, sig.confidence, sig.score_delta, evidence)
    }
}

fn parse_kind(s: &str) -> SemanticKind {
    match s.trim().to_ascii_lowercase().as_str() {
        "sqli" => SemanticKind::Sqli,
        "xss" => SemanticKind::Xss,
        "path" => SemanticKind::Path,
        "rce" => SemanticKind::Rce,
        "ssti" => SemanticKind::Ssti,
        "ldap" => SemanticKind::Ldap,
        "upload" => SemanticKind::Upload,
        _ => SemanticKind::Other,
    }
}

fn collect_hay(input: SemanticInput<'_>, fields: &[String]) -> String {
    if fields.is_empty() {
        return format!(
            "{} {} {} {} {}",
            input.method, input.uri, input.query, input.body, input.extra
        );
    }
    let mut parts = Vec::new();
    for f in fields {
        match f.trim().to_ascii_lowercase().as_str() {
            "uri" => parts.push(input.uri.to_string()),
            "query" => parts.push(input.query.to_string()),
            "body" => parts.push(input.body.to_string()),
            "method" => parts.push(input.method.to_string()),
            "extra" => parts.push(input.extra.to_string()),
            _ => {}
        }
    }
    parts.join("\n")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let end = floor_char_boundary(s, max);
        format!("{}…", &s[..end])
    }
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_seq_union_select() {
        assert!(token_seq_match(
            "id=1' UNION ALL SELECT null",
            &["union".into(), "select".into()]
        ));
        assert!(!token_seq_match(
            "union leaders meet",
            &["union".into(), "select".into()]
        ));
    }
}
