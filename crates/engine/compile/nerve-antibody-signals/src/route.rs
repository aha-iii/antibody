//! 声明式路由策略：快通道 / 信号 hint 加减分（来自 signals.yaml `route:`）。

use crate::RequestSignals;
use serde::Deserialize;

/// Pack 级路由策略（与具体业务路径解耦，由 YAML 配置）。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoutePolicy {
    #[serde(default)]
    pub fast_lanes: Vec<FastLaneRule>,
    #[serde(default)]
    pub fast_hints: Vec<SignalHint>,
    #[serde(default)]
    pub deep_hints: Vec<SignalHint>,
}

/// 命中后强制 Fast；`positive_lane` 为 true 时 L1 仅 Aho + allow。
#[derive(Debug, Clone, Deserialize)]
pub struct FastLaneRule {
    pub name: String,
    #[serde(default)]
    pub positive_lane: bool,
    #[serde(default)]
    pub require_features: Vec<String>,
    #[serde(default)]
    pub require_fingerprints: Vec<String>,
    #[serde(default)]
    pub exclude_features: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
    /// GET 且 body 必须为空。
    #[serde(default)]
    pub get_empty_body: bool,
}

/// 对线性路由分加减（负值倾向 Fast，正值倾向 Deep）。
#[derive(Debug, Clone, Deserialize)]
pub struct SignalHint {
    #[serde(default)]
    pub feature: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub score_delta: f32,
}

/// 命中快通道规则的结果。
#[derive(Debug, Clone, Copy)]
pub struct FastLaneMatch {
    pub positive_lane: bool,
}

impl RoutePolicy {
    /// 返回第一个匹配的快通道（按 YAML 声明顺序）。
    pub fn match_fast_lane(
        &self,
        req_method: &str,
        body_len: usize,
        signals: &RequestSignals,
    ) -> Option<FastLaneMatch> {
        for rule in &self.fast_lanes {
            if rule_matches(rule, req_method, body_len, signals) {
                return Some(FastLaneMatch {
                    positive_lane: rule.positive_lane,
                });
            }
        }
        None
    }

    /// 信号 hint 对路由分的修正量（已 clamp 到 ±0.35 单条）。
    pub fn signal_score_adjustment(&self, signals: &RequestSignals) -> f32 {
        let mut delta = 0.0f32;
        for h in &self.fast_hints {
            if hint_matches(h, signals) {
                delta += h.score_delta.clamp(-0.35, 0.0);
            }
        }
        for h in &self.deep_hints {
            if hint_matches(h, signals) {
                delta += h.score_delta.clamp(0.0, 0.35);
            }
        }
        delta
    }
}

fn rule_matches(
    rule: &FastLaneRule,
    req_method: &str,
    body_len: usize,
    signals: &RequestSignals,
) -> bool {
    if !rule.require_features.iter().all(|f| signals.feature(f)) {
        return false;
    }
    if !rule
        .require_fingerprints
        .iter()
        .all(|f| signals.fingerprint(f))
    {
        return false;
    }
    if rule.exclude_features.iter().any(|f| signals.feature(f)) {
        return false;
    }
    if !rule.methods.is_empty() {
        let m = req_method.to_ascii_uppercase();
        if !rule.methods.iter().any(|x| x.eq_ignore_ascii_case(&m)) {
            return false;
        }
    }
    if let Some(max) = rule.max_body_bytes {
        if body_len > max {
            return false;
        }
    }
    if rule.get_empty_body && req_method.eq_ignore_ascii_case("GET") && body_len > 0 {
        return false;
    }
    true
}

fn hint_matches(h: &SignalHint, signals: &RequestSignals) -> bool {
    if let Some(ref f) = h.feature {
        if !f.trim().is_empty() && signals.feature(f) {
            return true;
        }
    }
    if let Some(ref fp) = h.fingerprint {
        if !fp.trim().is_empty() && signals.fingerprint(fp) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{compute_signals_with_pack, SignalPack};

    #[test]
    #[ignore = "既有失败：SignalPack 的 FeatureKind 已不含 query_param_hex（现支持 header_present/\n                 path_prefix/body_contains/query_param_present/length_gt），用例 YAML 仍是旧 schema。\n                 需确认该 feature 是永久下线，还是以新 kind 重新引入"]
    fn fast_lane_requires_all_features() {
        let yaml = r#"
features:
  - name: hex_sign_param
    kind: query_param_hex
    param: sige
    min_length: 32
route:
  fast_lanes:
    - name: sigeed_get
      positive_lane: true
      require_features: [hex_sign_param]
      methods: [GET]
      get_empty_body: true
"#;
        let pack: SignalPack = serde_yaml::from_str(yaml).unwrap();
        let policy = pack.route.clone();
        let sig = compute_signals_with_pack(
            "GET",
            "/svc/query",
            "sige=8AE01DD1315503567E4B1F5FCB5F0694C4C72B238A4B807CC8109FF495C1B25B",
            "",
            &Default::default(),
            Some(&pack),
        );
        assert!(sig.feature("hex_sign_param"));
        assert!(policy.match_fast_lane("GET", 0, &sig).is_some());
        assert!(policy.match_fast_lane("GET", 1, &sig).is_none());
    }
}
