//! Bot：UA / 路径粗评分。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

const BOT_UA: &[&str] = &[
    "curl",
    "wget",
    "pythoe-requests",
    "scrapy",
    "bot",
    "spider",
    "crawler",
    "headless",
    "phaetomjs",
    "selenium",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_threshold")]
    pub score_threshold: u8,
}

fn default_true() -> bool {
    true
}
fn default_action() -> String {
    "challenge".into()
}
fn default_threshold() -> u8 {
    50
}

impl Default for BotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: default_action(),
            score_threshold: default_threshold(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotVerdict {
    pub score: u8,
    pub is_bot: bool,
    pub reason: String,
}

pub struct BotEngine {
    config: Mutex<BotConfig>,
}

impl BotEngine {
    pub fn new(config: BotConfig) -> Self {
        Self {
            config: Mutex::new(config),
        }
    }

    pub fn update_config(&self, config: BotConfig) {
        *self.config.lock() = config;
    }

    pub fn score(&self, user_agent: &str, uri: &str) -> BotVerdict {
        let cfg = self.config.lock().clone();
        if !cfg.enabled {
            return BotVerdict {
                score: 0,
                is_bot: false,
                reason: String::new(),
            };
        }
        let ua = user_agent.to_lowercase();
        let mut score: u8 = 0;
        let mut reasons = Vec::new();
        for sig in BOT_UA {
            if ua.contains(sig) {
                score = score.saturating_add(40);
                reasons.push(*sig);
            }
        }
        if uri.contains("robots.txt") {
            score = score.saturating_add(20);
            reasons.push("robots.txt");
        }
        if ua.is_empty() {
            score = score.saturating_add(30);
            reasons.push("empty_ua");
        }
        BotVerdict {
            is_bot: score >= cfg.score_threshold,
            score,
            reason: reasons.join(","),
        }
    }
}
