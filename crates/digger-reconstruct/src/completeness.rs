//! Deterministic reconstruction completeness (Gen5 A3.3 / ADR-0017).
//!
//! NO percentages, NO heuristic scoring. Completeness is reported PER DOMAIN as
//! a discrete [`CompletenessLevel`] derived ENTIRELY from (a) whether recovered
//! facts exist for the domain and (b) the deterministic [`EvidenceRequirement`]s
//! that remain outstanding.

use crate::dependency::RecoveredDependency;
use crate::deployment::RecoveredDeployment;
use crate::evidence_requirement::EvidenceRequirement;
use serde::{Deserialize, Serialize};

/// Discrete completeness level for one domain. There is no numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompletenessLevel {
    /// Facts exist and nothing is outstanding.
    Recovered,
    /// Facts exist but evidence requirements remain.
    Partial,
    /// No facts/evidence for this domain.
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReconstructionDomain {
    Deployment,
    Storage,
    Architecture,
    StateMachine,
    Permissions,
    TrustBoundaries,
    Dependencies,
}

/// Completeness of a single reconstruction domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCompleteness {
    pub domain: ReconstructionDomain,
    pub level: CompletenessLevel,
    /// Deterministic, sorted outstanding requirements (empty when Recovered).
    pub outstanding: Vec<EvidenceRequirement>,
}

impl DomainCompleteness {
    /// Deterministic rule (no scoring):
    /// - no facts                => Unavailable
    /// - facts, none outstanding => Recovered
    /// - facts, some outstanding => Partial
    pub fn assess(
        domain: ReconstructionDomain,
        has_facts: bool,
        outstanding: Vec<EvidenceRequirement>,
    ) -> Self {
        let mut outstanding = outstanding;
        outstanding.sort();
        outstanding.dedup();
        let level = if !has_facts {
            CompletenessLevel::Unavailable
        } else if outstanding.is_empty() {
            CompletenessLevel::Recovered
        } else {
            CompletenessLevel::Partial
        };
        DomainCompleteness {
            domain,
            level,
            outstanding,
        }
    }
}

/// Per-domain completeness report. Derives entirely from recovered facts and
/// their outstanding evidence requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructionCompleteness {
    pub domains: Vec<DomainCompleteness>,
}

impl ReconstructionCompleteness {
    pub fn new(domains: Vec<DomainCompleteness>) -> Self {
        ReconstructionCompleteness { domains }
    }
    pub fn level_for(&self, domain: ReconstructionDomain) -> Option<CompletenessLevel> {
        self.domains
            .iter()
            .find(|d| d.domain == domain)
            .map(|d| d.level)
    }
    /// All outstanding requirements across domains (deterministic order).
    pub fn all_outstanding(&self) -> Vec<EvidenceRequirement> {
        let mut out = Vec::new();
        for d in &self.domains {
            out.extend(d.outstanding.iter().cloned());
        }
        out.sort();
        out.dedup();
        out
    }
    /// Derive Deployment / Storage / Dependencies directly from recovered facts.
    /// Domains without facts yet are reported `Unavailable` (never fabricated).
    pub fn from_facts(
        deployment: Option<&RecoveredDeployment>,
        dependencies: &[RecoveredDependency],
    ) -> Self {
        let (dep_has, dep_out) = match deployment {
            Some(d) => (true, d.outstanding_requirements()),
            None => (false, Vec::new()),
        };
        let storage_out: Vec<EvidenceRequirement> = dep_out
            .iter()
            .filter(|r| matches!(r, EvidenceRequirement::NeedsStorage(_)))
            .cloned()
            .collect();
        let deps_out: Vec<EvidenceRequirement> = dependencies
            .iter()
            .flat_map(|d| d.address.requirements().iter().cloned())
            .collect();
        let domains = vec![
            DomainCompleteness::assess(ReconstructionDomain::Deployment, dep_has, dep_out),
            DomainCompleteness::assess(ReconstructionDomain::Storage, dep_has, storage_out),
            DomainCompleteness::assess(ReconstructionDomain::Architecture, false, Vec::new()),
            DomainCompleteness::assess(ReconstructionDomain::StateMachine, false, Vec::new()),
            DomainCompleteness::assess(ReconstructionDomain::Permissions, false, Vec::new()),
            DomainCompleteness::assess(ReconstructionDomain::TrustBoundaries, false, Vec::new()),
            DomainCompleteness::assess(
                ReconstructionDomain::Dependencies,
                !dependencies.is_empty(),
                deps_out,
            ),
        ];
        ReconstructionCompleteness { domains }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn levels_derive_from_facts_and_requirements() {
        let recovered = DomainCompleteness::assess(ReconstructionDomain::Deployment, true, vec![]);
        assert_eq!(recovered.level, CompletenessLevel::Recovered);
        let partial = DomainCompleteness::assess(
            ReconstructionDomain::Storage,
            true,
            vec![EvidenceRequirement::NeedsStorage("0x1".into())],
        );
        assert_eq!(partial.level, CompletenessLevel::Partial);
        let unavailable =
            DomainCompleteness::assess(ReconstructionDomain::StateMachine, false, vec![]);
        assert_eq!(unavailable.level, CompletenessLevel::Unavailable);
    }
}
