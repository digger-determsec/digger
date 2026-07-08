//! Deterministic chain capability model (Gen5 A3.2 / ADR-0015).
//!
//! Generation 5 prefers CAPABILITY checks over blockchain-specific branching.
//! Code asks "does this target support proxy recovery?" instead of "is this
//! EVM?". Capabilities are a deterministic function of the target only.

use crate::lifter::TargetKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A single deterministic reconstruction capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    SupportsProxyRecovery,
    SupportsUpgradeablePrograms,
    SupportsStorageRecovery,
    SupportsAccountRecovery,
    SupportsSelectorRecovery,
    SupportsInterfaceRecovery,
}

/// The deterministic capability set for a reconstruction target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCapabilities {
    set: BTreeSet<Capability>,
}

impl ChainCapabilities {
    pub fn new<I: IntoIterator<Item = Capability>>(caps: I) -> Self {
        ChainCapabilities {
            set: caps.into_iter().collect(),
        }
    }

    /// True if the target supports `cap`.
    pub fn supports(&self, cap: Capability) -> bool {
        self.set.contains(&cap)
    }

    /// Sorted, deduped list of capabilities (deterministic).
    pub fn capabilities(&self) -> Vec<Capability> {
        self.set.iter().copied().collect()
    }

    /// Deterministic capability set for a target. This is the ONE place that
    /// maps a chain to its capabilities; everywhere else asks `supports(...)`.
    pub fn for_target(target: TargetKind) -> Self {
        use Capability::*;
        match target {
            TargetKind::Evm => ChainCapabilities::new([
                SupportsProxyRecovery,
                SupportsStorageRecovery,
                SupportsSelectorRecovery,
                SupportsInterfaceRecovery,
            ]),
            TargetKind::SolanaBpf => ChainCapabilities::new([
                SupportsUpgradeablePrograms,
                SupportsAccountRecovery,
                SupportsInterfaceRecovery,
            ]),
            TargetKind::Move => ChainCapabilities::new([SupportsInterfaceRecovery]),
            TargetKind::Wasm => ChainCapabilities::new([SupportsInterfaceRecovery]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_supports_proxy_not_account_recovery() {
        let caps = ChainCapabilities::for_target(TargetKind::Evm);
        assert!(caps.supports(Capability::SupportsProxyRecovery));
        assert!(caps.supports(Capability::SupportsStorageRecovery));
        assert!(!caps.supports(Capability::SupportsAccountRecovery));
        assert!(!caps.supports(Capability::SupportsUpgradeablePrograms));
    }

    #[test]
    fn solana_supports_upgradeable_programs_and_accounts() {
        let caps = ChainCapabilities::for_target(TargetKind::SolanaBpf);
        assert!(caps.supports(Capability::SupportsUpgradeablePrograms));
        assert!(caps.supports(Capability::SupportsAccountRecovery));
        assert!(!caps.supports(Capability::SupportsProxyRecovery));
    }

    #[test]
    fn capabilities_are_sorted_and_deterministic() {
        let a = ChainCapabilities::for_target(TargetKind::Evm).capabilities();
        let mut sorted = a.clone();
        sorted.sort();
        assert_eq!(a, sorted);
    }
}
