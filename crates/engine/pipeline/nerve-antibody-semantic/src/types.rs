//! 语义信号类型。

use serde::{Deserialize, Serialize};

/// 信号类别（同类取 max 分时用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticKind {
    Sqli,
    Xss,
    Path,
    Rce,
    Ssti,
    Ldap,
    Upload,
    Other,
}

fn default_block_eligible() -> bool {
    true
}

/// 单条语义信号。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticSignal {
    pub kind: SemanticKind,
    /// 信号 id（如 `sqli.tautology`）。
    pub id: String,
    pub confidence: f32,
    /// 建议加分（融合时同类取 max）。
    pub score_delta: u32,
    /// 为 true 时强制总分不过阈（否决假阳性）。
    pub veto: bool,
    /// 是否允许语义单独/主导定罪（Fusion v2）。
    #[serde(default = "default_block_eligible")]
    pub block_eligible: bool,
    pub evidence: String,
}

impl SemanticSignal {
    pub fn attack(
        kind: SemanticKind,
        id: impl Into<String>,
        confidence: f32,
        score_delta: u32,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            confidence,
            score_delta,
            veto: false,
            block_eligible: confidence >= 0.78,
            evidence: evidence.into(),
        }
    }

    /// 软信号：参与加分/佐证，不可单独定罪（控 prose FP）。
    pub fn soft_assist(
        kind: SemanticKind,
        id: impl Into<String>,
        confidence: f32,
        score_delta: u32,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            confidence,
            score_delta,
            veto: false,
            block_eligible: false,
            evidence: evidence.into(),
        }
    }

    pub fn veto_signal(
        kind: SemanticKind,
        id: impl Into<String>,
        confidence: f32,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            confidence,
            score_delta: 0,
            veto: true,
            block_eligible: false,
            evidence: evidence.into(),
        }
    }
}

/// 一次分析汇总。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticReport {
    pub signals: Vec<SemanticSignal>,
    /// 融合用语义分（同类 max 后再求和）。
    pub score: u32,
    pub veto: bool,
    /// 是否存在可定罪攻击信号。
    #[serde(default)]
    pub block_eligible: bool,
}

impl SemanticReport {
    pub fn from_signals(signals: Vec<SemanticSignal>) -> Self {
        let veto = signals.iter().any(|s| s.veto);
        let block_eligible = signals
            .iter()
            .any(|s| s.block_eligible && !s.veto && s.score_delta > 0);

        let mut sqli = 0u32;
        let mut xss = 0u32;
        let mut path = 0u32;
        let mut rce = 0u32;
        let mut ssti = 0u32;
        let mut ldap = 0u32;
        let mut upload = 0u32;
        let mut other = 0u32;

        for s in &signals {
            if s.veto {
                continue;
            }
            match s.kind {
                SemanticKind::Sqli => sqli = sqli.max(s.score_delta),
                SemanticKind::Xss => xss = xss.max(s.score_delta),
                SemanticKind::Path => path = path.max(s.score_delta),
                SemanticKind::Rce => rce = rce.max(s.score_delta),
                SemanticKind::Ssti => ssti = ssti.max(s.score_delta),
                SemanticKind::Ldap => ldap = ldap.max(s.score_delta),
                SemanticKind::Upload => upload = upload.max(s.score_delta),
                SemanticKind::Other => other = other.max(s.score_delta),
            }
        }

        Self {
            score: sqli
                .saturating_add(xss)
                .saturating_add(path)
                .saturating_add(rce)
                .saturating_add(ssti)
                .saturating_add(ldap)
                .saturating_add(upload)
                .saturating_add(other),
            veto,
            block_eligible,
            signals,
        }
    }
}
