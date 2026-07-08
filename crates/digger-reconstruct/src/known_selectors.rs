//! Known 4-byte selector → DependencyKind mapping (C3.1).
//!
//! Deterministic, static lookup table. No network, no inference.

use crate::dependency::DependencyKind;

/// Returns the DependencyKind for a known 4-byte hex selector (lowercase, no 0x prefix).
pub fn classify_selector(selector: &str) -> Option<DependencyKind> {
    match selector {
        // Token
        "a9059cbb" | "23b872dd" | "095ea7b3" | "70a08231" => Some(DependencyKind::Token),
        // PriceOracle
        "feaf968c" | "50d25bcd" => Some(DependencyKind::PriceOracle),
        // Router
        "38ed1739" | "7ff36ab5" | "d06ca61f" => Some(DependencyKind::Router),
        // Vault
        "6e553f65" | "ba087652" | "b460af94" => Some(DependencyKind::Vault),
        // Governance
        "56781388" | "da95691a" => Some(DependencyKind::Governance),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_selectors_present() {
        assert_eq!(classify_selector("a9059cbb"), Some(DependencyKind::Token));
        assert_eq!(
            classify_selector("feaf968c"),
            Some(DependencyKind::PriceOracle)
        );
        assert_eq!(classify_selector("38ed1739"), Some(DependencyKind::Router));
        assert_eq!(classify_selector("6e553f65"), Some(DependencyKind::Vault));
        assert_eq!(
            classify_selector("56781388"),
            Some(DependencyKind::Governance)
        );
    }

    #[test]
    fn unknown_selector_returns_none() {
        assert_eq!(classify_selector("deadbeef"), None);
    }
}
