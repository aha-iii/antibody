//! Fusion v2：分层定罪（L1 / L2 / L3 佐证），禁止裸模型硬拦。
//!
//! 治理口径（沙箱 · 正负检测 · 拦截信号量）见 `docs/GOVERNANCE-ARCHITECTURE-zh.md`。
//!
//! - **正检测**：`rule_score` + `semantic_score` + `model_score`
//! - **负检测**：`allow_score`（自体豁免）
//! - **拦截信号量**：[`intercept`] / [`InterceptPermit`] —— 分数回答「多像攻击」，许可回答「允不允许拦」
//!
//! # 生产动作边界（必须清晰）
//! - **pass / observe**：无攻击佐证（模型未贡献、无解码攻击片段）
//! - **challenge**：有可解释可疑点但不够硬拦 → 深检，不硬拒
//!   - 模型已贡献（贡献门闩要求：攻击关键字 / 规则命中 / 语义分），或
//!   - 解码视图出现攻击形片段（`decode_attack_hint`）
//! - **block**：强 L1 / 可定罪语义 / 过阈融合 → 硬拦
//!
//! 决策优先级（从高到低）：
//! 1. `observe_only` → observe（拦截许可=0，含沙箱路径）
//! 2. 强 L1（block 规则）过阈 → block
//! 3. 强 L2（`block_eligible` 语义）过阈 → block
//! 4. 弱 L1 ∧ 模型加分 过阈 → block
//! 5. 可定罪语义 ∧ 模型加分 过阈 → block
//! 6. 攻击特征佐证 ∧ 模型加分（medium+）过阈 → block
//! 7. medium/high：可解释可疑 → challenge
//! 8. 否则 observe
//!
//! `semantic_veto` 只压制软分，不能抹掉已过阈的强 L1。

use nerve_antibody_dsl::NativeLevel;

/// 融合后动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionAction {
    Block,
    Challenge,
    Observe,
}

impl FusionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Challenge => "challenge",
            Self::Observe => "observe",
        }
    }
}

/// 融合输入（由 Evaluator 从规则/语义/模型汇总）。
#[derive(Debug, Clone)]
pub struct FusionEvidence {
    pub wants_block: bool,
    pub any_rule_hit: bool,
    pub rule_score: u32,
    pub allow_score: u32,
    pub semantic_score: u32,
    pub semantic_block_eligible: bool,
    pub semantic_veto: bool,
    pub model_score: u32,
    pub model_p: f32,
    pub model_contributed: bool,
    /// sql + xss + path + rce 关键字命中合计。
    pub attack_kw_hits: u32,
    pub decode_depth: u32,
    /// 解码视图中出现攻击形片段（SSTI/SQLi/XSS 等）→ 可 challenge。
    pub decode_attack_hint: bool,
    /// URI CRLF / 密集 unicode·实体逃逸 → 可 challenge。
    pub evasion_hint: bool,
    /// 静态资源路径：无佐证时强制 observe（界面 pass）。
    pub static_asset: bool,
    /// Web cache deception：带静态后缀的敏感 API 路径，不可 static pass。
    pub cache_deception_probe: bool,
    pub threshold: u32,
    pub level: NativeLevel,
    pub observe_only: bool,
    /// Fusion v3：弱信号 block 至少需要的独立信号类数（强 L1/L2 不受限）。
    pub min_independent_signals: u8,
}

impl FusionEvidence {
    /// 正检测累加分（攻击规则 + 语义 + 模型），未扣 allow。
    pub fn positive_score(&self) -> u32 {
        self.rule_score
            .saturating_add(self.semantic_score)
            .saturating_add(self.model_score)
    }

    /// 负检测分（allow / 自体豁免）。
    pub fn negative_score(&self) -> u32 {
        self.allow_score
    }

    /// L1 净分：规则分 − allow。
    pub fn net_l1_score(&self) -> u32 {
        self.rule_score.saturating_sub(self.allow_score)
    }
}

/// 拦截信号量许可：是否授予硬拦 / 挑战资格。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptPermit {
    /// 允许生产 block。
    Block,
    /// 允许 challenge，不允许硬拦。
    Challenge,
    /// 无拦截许可（observe / 沙箱 / 证据不足）。
    None,
}

impl InterceptPermit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Challenge => "challenge",
            Self::None => "none",
        }
    }
}

/// 拦截信号量判决（分数 + 许可 + 最终动作）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptDecision {
    pub total_score: u32,
    pub positive_score: u32,
    pub negative_score: u32,
    pub permit: InterceptPermit,
    pub action: FusionAction,
}

/// 拦截信号量入口：包装 [`fuse`]，显式给出正负分与许可。
pub fn intercept(e: &FusionEvidence) -> InterceptDecision {
    let (total_score, action) = fuse(e);
    let permit = match action {
        FusionAction::Block => InterceptPermit::Block,
        FusionAction::Challenge => InterceptPermit::Challenge,
        FusionAction::Observe => InterceptPermit::None,
    };
    InterceptDecision {
        total_score,
        positive_score: e.positive_score(),
        negative_score: e.negative_score(),
        permit,
        action,
    }
}

fn independent_signal_classs(e: &FusionEvidence) -> u8 {
    let mut n = 0u8;
    if e.any_rule_hit {
        n = n.saturating_add(1);
    }
    if e.semantic_block_eligible && e.semantic_score > 0 {
        n = n.saturating_add(1);
    }
    if e.model_contributed && e.model_score > 0 {
        n = n.saturating_add(1);
    }
    if e.decode_attack_hint {
        n = n.saturating_add(1);
    }
    if e.evasion_hint {
        n = n.saturating_add(1);
    }
    n
}

fn weak_block_needs_more_evidence(e: &FusionEvidence) -> bool {
    e.min_independent_signals > 1 && independent_signal_classs(e) < e.min_independent_signals
}

/// 计算总分与动作。
pub fn fuse(e: &FusionEvidence) -> (u32, FusionAction) {
    let mut total = e
        .rule_score
        .saturating_sub(e.allow_score)
        .saturating_add(e.semantic_score)
        .saturating_add(e.model_score);

    // 散文否决：压掉语义/模型软分，但绝不抹掉强 L1（否则真攻击被 veto 误放）
    if e.semantic_veto {
        let l1 = e.rule_score.saturating_sub(e.allow_score);
        if e.wants_block {
            // hard L1 已由上游裁定（solo block / 净分达阈）；veto 不得抹掉
            total = e.rule_score.max(l1).max(e.threshold);
        } else {
            total = total.min(e.threshold.saturating_sub(1)).min(l1);
        }
    }

    if e.observe_only {
        return (total, FusionAction::Observe);
    }

    let over = total >= e.threshold;
    let level = e.level.rank();

    // 1) 强 L1：上游已裁定 hard block 时，高分 allow 不得把动作降成 observe
    if e.wants_block {
        return (total.max(e.threshold), FusionAction::Block);
    }

    // 2) 强 L2：可定罪语义（veto 已压分）
    if e.semantic_block_eligible && e.semantic_score > 0 && over && !e.semantic_veto {
        return (total, FusionAction::Block);
    }

    // 3) 弱 L1 ∧ 模型
    if e.any_rule_hit && e.model_contributed && e.model_score > 0 && over && !e.semantic_veto {
        if weak_block_needs_more_evidence(e) {
            return (total, FusionAction::Challenge);
        }
        return (total, FusionAction::Block);
    }

    // 4) 可定罪语义 ∧ 模型
    if e.semantic_block_eligible
        && e.semantic_score > 0
        && e.model_contributed
        && e.model_score > 0
        && over
        && !e.semantic_veto
    {
        if weak_block_needs_more_evidence(e) {
            return (total, FusionAction::Challenge);
        }
        return (total, FusionAction::Block);
    }

    // 5) 攻击特征佐证 ∧ 模型
    let kw_need = if level >= NativeLevel::High.rank() {
        2
    } else {
        3
    };
    let deep = e.decode_depth >= 3;
    let feature_ok = e.attack_kw_hits >= kw_need || (e.attack_kw_hits >= 2 && deep);
    if level >= NativeLevel::Medium.rank()
        && e.model_contributed
        && e.model_score > 0
        && feature_ok
        && over
        && !e.semantic_veto
    {
        if weak_block_needs_more_evidence(e) {
            return (total, FusionAction::Challenge);
        }
        return (total, FusionAction::Block);
    }

    // 静态资源：无攻击佐证 → 明确 pass（observe），避免 JS/CSS 刷 challenge
    // cache deception 探测刻意伪装成 .js/.css，不得走此放行
    if e.static_asset
        && !e.cache_deception_probe
        && !e.decode_attack_hint
        && !e.evasion_hint
        && e.attack_kw_hits == 0
        && !e.any_rule_hit
        && !e.wants_block
        && e.semantic_score == 0
    {
        return (total, FusionAction::Observe);
    }

    // 6) challenge：可解释可疑，但不够硬拦
    //    - 模型已贡献（门闩：关键字/规则/语义）
    //    - 或逃逸攻击形片段
    //    decode_attack_hint 单独不足以 challenge（hex 签名 / API 噪声易误触）
    if level >= NativeLevel::Medium.rank()
        && !e.semantic_veto
        && ((e.model_contributed && e.model_score > 0) || e.evasion_hint)
    {
        if e.allow_score > 0 && !e.wants_block && e.attack_kw_hits == 0 && !e.any_rule_hit {
            return (total, FusionAction::Observe);
        }
        return (total, FusionAction::Challenge);
    }

    if level >= NativeLevel::Medium.rank()
        && !e.semantic_veto
        && e.decode_attack_hint
        && (e.model_contributed && e.model_score > 0)
    {
        return (total, FusionAction::Challenge);
    }

    (total, FusionAction::Observe)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FusionEvidence {
        FusionEvidence {
            wants_block: false,
            any_rule_hit: false,
            rule_score: 0,
            allow_score: 0,
            semantic_score: 0,
            semantic_block_eligible: false,
            semantic_veto: false,
            model_score: 0,
            model_p: 0.0,
            model_contributed: false,
            attack_kw_hits: 0,
            decode_depth: 0,
            decode_attack_hint: false,
            evasion_hint: false,
            static_asset: false,
            cache_deception_probe: false,
            threshold: 40,
            level: NativeLevel::Medium,
            observe_only: false,
            min_independent_signals: 1,
        }
    }

    #[test]
    fn strong_l1_blocks() {
        let mut e = base();
        e.wants_block = true;
        e.rule_score = 40;
        let (t, a) = fuse(&e);
        assert_eq!(t, 40);
        assert_eq!(a, FusionAction::Block);
        let d = intercept(&e);
        assert_eq!(d.permit, InterceptPermit::Block);
        assert_eq!(d.positive_score, 40);
        assert_eq!(d.negative_score, 0);
    }

    #[test]
    fn strong_l1_blocks_despite_high_allow_score() {
        let mut e = base();
        e.wants_block = true;
        e.any_rule_hit = true;
        e.rule_score = 40;
        e.allow_score = 200;
        let (t, a) = fuse(&e);
        assert_eq!(a, FusionAction::Block);
        assert!(t >= e.threshold);
    }

    #[test]
    fn observe_only_clears_intercept_permit() {
        let mut e = base();
        e.wants_block = true;
        e.rule_score = 40;
        e.observe_only = true;
        let d = intercept(&e);
        assert_eq!(d.action, FusionAction::Observe);
        assert_eq!(d.permit, InterceptPermit::None);
        assert_eq!(d.total_score, 40);
    }

    #[test]
    fn allow_negative_detector_reduces_net_l1() {
        let mut e = base();
        e.rule_score = 40;
        e.allow_score = 25;
        assert_eq!(e.positive_score(), 40);
        assert_eq!(e.negative_score(), 25);
        assert_eq!(e.net_l1_score(), 15);
    }

    #[test]
    fn naked_uncontributed_model_passes() {
        let mut e = base();
        e.model_score = 0;
        e.model_contributed = false;
        e.model_p = 0.4;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Observe);
    }

    #[test]
    fn contributed_model_challenges_not_hard_block() {
        let mut e = base();
        e.model_score = 8;
        e.model_contributed = true;
        e.model_p = 0.4;
        e.decode_depth = 2;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Challenge);
    }

    #[test]
    fn feature_corroborated_model_blocks() {
        let mut e = base();
        e.model_score = 15;
        e.model_contributed = true;
        e.attack_kw_hits = 3;
        e.rule_score = 25; // total 40
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Block);
    }

    #[test]
    fn semantic_eligible_blocks() {
        let mut e = base();
        e.semantic_score = 40;
        e.semantic_block_eligible = true;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Block);
    }

    #[test]
    fn deep_decode_contributed_challenges() {
        let mut e = base();
        e.model_score = 10;
        e.model_contributed = true;
        e.model_p = 0.45;
        e.decode_depth = 3;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Challenge);
    }

    #[test]
    fn veto_prevents_soft_block() {
        let mut e = base();
        e.semantic_score = 40;
        e.semantic_block_eligible = true;
        e.semantic_veto = true;
        let (t, a) = fuse(&e);
        assert!(t < 40);
        assert_eq!(a, FusionAction::Observe);
    }

    #[test]
    fn veto_does_not_override_strong_l1() {
        let mut e = base();
        e.wants_block = true;
        e.rule_score = 120;
        e.semantic_score = 40;
        e.model_score = 11;
        e.semantic_veto = true;
        let (t, a) = fuse(&e);
        assert!(t >= 40);
        assert_eq!(a, FusionAction::Block);
    }

    #[test]
    fn static_asset_without_hint_passes() {
        let mut e = base();
        e.static_asset = true;
        e.model_score = 8;
        e.model_contributed = true;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Observe);
    }

    #[test]
    fn evasion_hint_challenges() {
        let mut e = base();
        e.evasion_hint = true;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Challenge);
    }

    #[test]
    fn decode_attack_hint_alone_observes() {
        let mut e = base();
        e.decode_attack_hint = true;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Observe);
    }

    #[test]
    fn decode_attack_hint_with_model_challenges() {
        let mut e = base();
        e.decode_attack_hint = true;
        e.model_score = 10;
        e.model_contributed = true;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Challenge);
    }

    #[test]
    fn allow_only_hit_does_not_challenge() {
        let mut e = base();
        e.any_rule_hit = false;
        e.allow_score = 40;
        e.model_score = 20;
        e.model_contributed = true;
        e.model_p = 0.9;
        e.attack_kw_hits = 0;
        let (_, a) = fuse(&e);
        assert_eq!(a, FusionAction::Observe);
    }
}
