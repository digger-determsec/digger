#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

/// Digger Knowledge Models — canonical semantic types for security knowledge.
///
/// These types represent extracted, normalized, and classified security knowledge
/// from any source. They are consumed by the reasoning engine as supporting
/// evidence — never as primary analysis input.
///
/// The KnowledgeSource trait is the generic interface for all knowledge providers.
/// Every implementation normalizes its output into NormalizedKnowledge before
/// it enters the reasoning engine. The engine never sees source-specific formats.
///
/// All structures are deterministic and JSON serializable.
/// No exploit signatures. No heuristics. No AI.
pub mod audit;
pub mod enrichment;
pub mod finding;
pub mod graph;
pub mod knowledge_evidence;
pub mod pattern;
pub mod source;

pub use audit::*;
pub use enrichment::*;
pub use finding::*;
pub use graph::*;
pub use knowledge_evidence::*;
pub use pattern::*;
pub use source::*;

#[cfg(test)]
mod tests;
