//! Deterministic estimated investigation scope.
//!
//! Scope is a deterministic SIZE estimate (integer counts of related recovered
//! facts), not an effort/time guess and not a score. The band is assigned by
//! fixed integer thresholds, documented below, so identical facts always yield
//! the same scope.

use serde::{Deserialize, Serialize};

/// Deterministic scope band, assigned from `related_node_count` by fixed
/// thresholds. These thresholds are constants, not heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScopeBand {
    /// `related_node_count <= FOCUSED_MAX`.
    Focused,
    /// `FOCUSED_MAX < related_node_count <= MODERATE_MAX`.
    Moderate,
    /// `related_node_count > MODERATE_MAX`.
    Broad,
}

/// Upper bound (inclusive) of the Focused band.
pub const FOCUSED_MAX: u32 = 2;
/// Upper bound (inclusive) of the Moderate band.
pub const MODERATE_MAX: u32 = 5;

impl ScopeBand {
    pub fn from_related_count(related_node_count: u32) -> ScopeBand {
        if related_node_count <= FOCUSED_MAX {
            ScopeBand::Focused
        } else if related_node_count <= MODERATE_MAX {
            ScopeBand::Moderate
        } else {
            ScopeBand::Broad
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScopeBand::Focused => "focused",
            ScopeBand::Moderate => "moderate",
            ScopeBand::Broad => "broad",
        }
    }
}

/// Deterministic estimated investigation scope for a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeEstimate {
    /// Distinct related ProtocolModel fact ids supporting the target.
    pub related_node_count: u32,
    /// Capabilities involved in the target.
    pub capability_count: u32,
    /// Trust boundaries involved in the target.
    pub trust_boundary_count: u32,
    pub band: ScopeBand,
}

impl ScopeEstimate {
    pub fn new(related_node_count: u32, capability_count: u32, trust_boundary_count: u32) -> Self {
        ScopeEstimate {
            related_node_count,
            capability_count,
            trust_boundary_count,
            band: ScopeBand::from_related_count(related_node_count),
        }
    }
}
