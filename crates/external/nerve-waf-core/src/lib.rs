//! Core transaction model: phases, verdicts, timing, and journey hops.

mod inspect_timing;
mod journey;
mod phase;
mod transaction;
mod verdict;

pub use inspect_timing::{InspectNodeTiming, InspectTimingReport};
pub use journey::{build_waf_journey_hops, WafJourneyContext, WAF_PIPELINE_ID, WAF_PIPELINE_NAME};
pub use phase::InspectPhase;
pub use transaction::WafTransaction;
pub use verdict::{InspectHit, InspectVerdict, WafAction};

#[cfg(test)]
mod test;
