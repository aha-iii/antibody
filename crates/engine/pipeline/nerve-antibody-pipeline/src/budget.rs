//! Inspect 预算：时间、regex 评估次数、视图 slice 数熔断。

use std::time::{Duration, Instant};

/// 预算耗尽。
#[derive(Debug, Clone)]
pub struct BudgetExhausted {
    pub reason: &'static str,
}

/// 单次 inspect 预算。
#[derive(Debug, Clone)]
pub struct InspectBudget {
    start: Instant,
    max_ms: u64,
    max_regex: u32,
    max_view_slices: u32,
    regex_used: u32,
    exhausted: Option<&'static str>,
}

impl InspectBudget {
    pub fn new(max_ms: u64, max_regex: u32, max_view_slices: u32) -> Self {
        Self::with_limits(max_ms, max_regex, max_view_slices)
    }

    pub fn with_limits(max_ms: u64, max_regex: u32, max_view_slices: u32) -> Self {
        Self {
            start: Instant::now(),
            max_ms,
            max_regex,
            max_view_slices,
            regex_used: 0,
            exhausted: None,
        }
    }

    pub fn unlimited() -> Self {
        Self::new(0, 0, 0)
    }

    pub fn max_view_slices(&self) -> u32 {
        self.max_view_slices
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted.is_some()
    }

    pub fn reason(&self) -> Option<&'static str> {
        self.exhausted
    }

    pub fn check_time(&mut self) -> Result<(), BudgetExhausted> {
        if self.max_ms == 0 {
            return Ok(());
        }
        if self.start.elapsed() >= Duration::from_millis(self.max_ms) {
            self.exhausted = Some("max_inspect_ms");
            return Err(BudgetExhausted {
                reason: "max_inspect_ms",
            });
        }
        Ok(())
    }

    pub fn charge_regex(&mut self) -> Result<(), BudgetExhausted> {
        self.check_time()?;
        if self.max_regex == 0 {
            return Ok(());
        }
        self.regex_used = self.regex_used.saturating_add(1);
        if self.regex_used > self.max_regex {
            self.exhausted = Some("max_regex_evals");
            return Err(BudgetExhausted {
                reason: "max_regex_evals",
            });
        }
        Ok(())
    }

    /// 追加视图 slice 前检查上限；`current_count` 为当前已有 slice 数。
    pub fn charge_view_slice(&mut self, current_count: u32) -> Result<(), BudgetExhausted> {
        self.check_time()?;
        if self.max_view_slices > 0 && current_count >= self.max_view_slices {
            self.exhausted = Some("max_view_slices");
            return Err(BudgetExhausted {
                reason: "max_view_slices",
            });
        }
        Ok(())
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}
