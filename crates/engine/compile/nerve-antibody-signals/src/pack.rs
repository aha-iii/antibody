//! 声明式信号包（YAML）：在不改 Rust 的情况下扩展 feature / fingerprint。

use serde::Deserialize;
use std::path::Path;

/// 加载信号包；`None` 或空路径返回空包（仅内置）。
pub fn load_signal_pack(path: Option<&Path>) -> Result<SignalPack, String> {
    match path {
        Some(p) if p.as_os_str().is_empty() => Ok(SignalPack::default()),
        Some(p) => SignalPack::load(p),
        None => Ok(SignalPack::default()),
    }
}

/// Pack 根下的声明式信号定义。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SignalPack {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub features: Vec<DeclaredSignal>,
    #[serde(default)]
    pub fingerprints: Vec<DeclaredSignal>,
    #[serde(default)]
    pub route: crate::route::RoutePolicy,
}

impl SignalPack {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read signal pack {}: {e}", path.display()))?;
        let pack: SignalPack = serde_yaml::from_str(&text)
            .map_err(|e| format!("parse signal pack {}: {e}", path.display()))?;
        pack.validate()?;
        Ok(pack)
    }

    pub fn is_empty(&self) -> bool {
        self.features.is_empty() && self.fingerprints.is_empty()
    }

    fn validate(&self) -> Result<(), String> {
        for s in self.features.iter().chain(self.fingerprints.iter()) {
            s.kind.validate(&s.name)?;
        }
        Ok(())
    }
}

/// 单条声明式信号。
#[derive(Debug, Clone, Deserialize)]
pub struct DeclaredSignal {
    pub name: String,
    #[serde(flatten)]
    pub kind: SignalKind,
}

/// 长度比较目标（`length_gt`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthTarget {
    Header,
    Query,
    Body,
}

/// 声明式信号原语。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalKind {
    HeaderPresent { header: String },
    PathPrefix { prefix: String },
    BodyContains { value: String },
    QueryParamPresent { param: String },
    LengthGt {
        target: LengthTarget,
        #[serde(default)]
        header: Option<String>,
        threshold: usize,
    },
}

impl SignalKind {
    fn validate(&self, name: &str) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("signal name must not be empty".into());
        }
        match self {
            Self::HeaderPresent { header } if header.trim().is_empty() => {
                Err(format!("signal {name}: header_present needs header"))
            }
            Self::PathPrefix { prefix } if prefix.is_empty() => {
                Err(format!("signal {name}: path_prefix needs prefix"))
            }
            Self::BodyContains { value } if value.is_empty() => {
                Err(format!("signal {name}: body_contains needs value"))
            }
            Self::QueryParamPresent { param } if param.trim().is_empty() => {
                Err(format!("signal {name}: query_param_present needs param"))
            }
            Self::LengthGt {
                target: LengthTarget::Header,
                header,
                ..
            } if header.as_ref().map(|h| h.trim().is_empty()).unwrap_or(true) => {
                Err(format!("signal {name}: length_gt target=header needs header"))
            }
            _ => Ok(()),
        }
    }
}
