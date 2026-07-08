/// Structural enforcement of the provenance→graduation ceiling.
///
/// The scan endpoint (`run_scan`) is the ONLY site that assigns a
/// `"graduated"` or `"experimental"` label to per-finding confidence.
/// This module gates that decision on `EvidenceModality`, making it
/// structurally impossible for bytecode-only or behavioral-only evidence
/// to receive a graduated label — even if a future scan path (e.g.
/// lifted-bytecode) is wired in.
///
/// **FORCING FUNCTION:** The exhaustive `match` in `graduation_label`
/// means any new `EvidenceModality` variant (or any new scan path)
/// MUST be classified here, and only `SourceCorroborated` can yield
/// "graduated". A future bytecode-only path MUST set `BytecodeOnly`,
/// which the gate caps to "experimental".

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceModality {
    /// Source code was directly available and parsed. All current detectors
    /// (Solana access_control, CPI, type-cosplay, unchecked-owner,
    /// EVM price_manipulation, readonly_reentrancy) operate on source.
    SourceCorroborated,

    /// Bytecode was lifted/decompiled but no source was available.
    /// A future lifted-bytecode scan path MUST set this modality.
    /// The graduation gate caps it to "experimental" — never "graduated".
    #[allow(dead_code)]
    BytecodeOnly,
}

/// Map evidence modality to the per-finding confidence label.
///
/// The exhaustive `match` is the structural ceiling: only source-corroborated
/// findings may graduate. Bytecode-only evidence is permanently capped at
/// experimental. Any future modality variant must be classified here — the
/// compiler will reject the build if the match is non-exhaustive.
pub(crate) fn graduation_label(modality: EvidenceModality) -> &'static str {
    match modality {
        EvidenceModality::SourceCorroborated => "graduated",
        EvidenceModality::BytecodeOnly => "experimental",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_corroborated_graduates() {
        assert_eq!(
            graduation_label(EvidenceModality::SourceCorroborated),
            "graduated"
        );
    }

    #[test]
    fn test_bytecode_only_never_graduates() {
        let label = graduation_label(EvidenceModality::BytecodeOnly);
        assert_eq!(label, "experimental");
        assert_ne!(label, "graduated");
    }

    #[test]
    fn test_all_modalities_exhaustive() {
        // Compile-time check: if you add a variant to EvidenceModality and
        // forget to update graduation_label, this test won't compile.
        let _ = graduation_label(EvidenceModality::SourceCorroborated);
        let _ = graduation_label(EvidenceModality::BytecodeOnly);
    }
}
