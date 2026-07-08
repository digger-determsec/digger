//! Known Solana program IDs → DependencyKind mapping (C3.2).
//!
//! Deterministic, curated lookup. Unknown program IDs → ExternalProtocol.

use crate::dependency::DependencyKind;

/// Well-known Solana program IDs (base58 strings as used in account.owner fields).
pub fn classify_program(program_id: &str) -> Option<DependencyKind> {
    match program_id {
        // SPL Token Program
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" => Some(DependencyKind::Token),
        // SPL Token-2022 Program
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" => Some(DependencyKind::Token),
        // Associated Token Account Program
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" => {
            Some(DependencyKind::SharedInfrastructure)
        }
        _ => None,
    }
}

/// Returns true if a program ID is well-known infrastructure (System, BPF Loader, Sysvar).
pub fn is_infrastructure(program_id: &str) -> bool {
    program_id == "11111111111111111111111111111111"
        || program_id == "BPFLoaderUpgradeab1e11111111111111111111111"
        || program_id == "BPFLoader2111111111111111111111111111111111"
        || program_id.starts_with("Sysvar")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spl_token_classified() {
        assert_eq!(
            classify_program("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            Some(DependencyKind::Token)
        );
        assert_eq!(
            classify_program("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
            Some(DependencyKind::Token)
        );
        assert_eq!(
            classify_program("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
            Some(DependencyKind::SharedInfrastructure)
        );
    }

    #[test]
    fn infrastructure_filtered() {
        assert!(is_infrastructure("11111111111111111111111111111111"));
        assert!(is_infrastructure(
            "BPFLoaderUpgradeab1e11111111111111111111111"
        ));
        assert!(is_infrastructure(
            "BPFLoader2111111111111111111111111111111111"
        ));
        assert!(is_infrastructure(
            "SysvarRent111111111111111111111111111111111"
        ));
    }

    #[test]
    fn unknown_not_infrastructure() {
        assert!(!is_infrastructure(
            "SomeRandomProgramId1111111111111111111111111"
        ));
    }
}
