//! Deterministic confidence tiers (ADR-0009). NO numeric scores, ever.

use serde::{Deserialize, Serialize};

/// Confidence tiers as a TOTAL ORDER. Declared weakest -> strongest so the
/// derived `Ord` increases with strength: `Authoritative` is the greatest.
/// Use [`ConfidenceTier::weakest_of`] to combine inputs (a fact is never more
/// confident than its weakest load-bearing input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfidenceTier {
    /// Downstream conjecture not directly grounded in reconstructed evidence.
    Hypothesized,
    /// Deterministically deduced from corroborating evidence; records a basis.
    Inferred,
    /// Deterministically lifted from bytecode.
    Recovered,
    /// From source / verified source.
    Authoritative,
}

impl ConfidenceTier {
    /// The weakest (lowest) tier among inputs, or `None` if empty.
    pub fn weakest_of<I: IntoIterator<Item = ConfidenceTier>>(iter: I) -> Option<ConfidenceTier> {
        iter.into_iter().min()
    }
    /// Stable lower-case label.
    pub fn label(&self) -> &'static str {
        match self {
            ConfidenceTier::Hypothesized => "hypothesized",
            ConfidenceTier::Inferred => "inferred",
            ConfidenceTier::Recovered => "recovered",
            ConfidenceTier::Authoritative => "authoritative",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordering_strength() {
        assert!(ConfidenceTier::Authoritative > ConfidenceTier::Recovered);
        assert!(ConfidenceTier::Recovered > ConfidenceTier::Inferred);
        assert!(ConfidenceTier::Inferred > ConfidenceTier::Hypothesized);
    }
    #[test]
    fn weakest_wins() {
        let t = ConfidenceTier::weakest_of([
            ConfidenceTier::Authoritative,
            ConfidenceTier::Inferred,
            ConfidenceTier::Recovered,
        ]);
        assert_eq!(t, Some(ConfidenceTier::Inferred));
    }
}
