//! Source code provider: parse + build SystemIR (Gen1), then feed the single
//! downstream analysis (Gen2 + Gen3). Source is an evidence provider into the
//! one shared pipeline — it does not introduce a second downstream path.

use std::collections::BTreeMap;

use digger_ir::{Language, SystemIR};

use crate::analyze::analyze_systems;

/// Source code provider: parse + build SystemIR (Gen1), then feed the single
/// downstream analysis (Gen2 + Gen3). Source is an evidence provider into the
/// one shared pipeline — it does not introduce a second downstream path.
pub fn investigate_source(code: &str, lang: &str) -> crate::analyze::InvestigationOutcome {
    let raw = digger_parser::parse_program(code, lang);
    let language = match lang.to_ascii_lowercase().as_str() {
        "solidity" | "sol" => Language::Solidity,
        "anchor" => Language::Anchor,
        "rust" | "rs" => Language::Rust,
        _ => Language::Unknown,
    };
    let ir: SystemIR = digger_graph::build_system_ir_with_language(raw, language);
    let id = ir.program_id.clone();
    let mut systems = BTreeMap::new();
    systems.insert(id.clone(), ir);
    analyze_systems(&systems, &id, &id)
}

/// Same as investigate_source, but with optional corpus evidence attached
/// to derived hypotheses. DEFAULT OFF: when store is None, behavior is
/// byte-identical to investigate_source.
pub fn investigate_source_with_corpus(
    code: &str,
    lang: &str,
    store: Option<&digger_knowledge_models::HistoricalFindingStore>,
    snapshot_id: Option<&str>,
    source_id: Option<&str>,
) -> crate::analyze::InvestigationOutcome {
    let raw = digger_parser::parse_program(code, lang);
    let language = match lang.to_ascii_lowercase().as_str() {
        "solidity" | "sol" => Language::Solidity,
        "anchor" => Language::Anchor,
        "rust" | "rs" => Language::Rust,
        _ => Language::Unknown,
    };
    let ir: SystemIR = digger_graph::build_system_ir_with_language(raw, language);
    let id = ir.program_id.clone();
    let mut systems = BTreeMap::new();
    systems.insert(id.clone(), ir);

    let ctx = digger_hypothesis::derivation::DerivationContext {
        knowledge: store,
        corpus_snapshot_id: snapshot_id,
        corpus_source_id: source_id,
        ..Default::default()
    };
    crate::analyze::analyze_systems_with_ctx(&systems, &id, &id, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOL: &str = "contract V { function withdraw() public { msg.sender.call(\"\"); } }";

    #[test]
    fn source_provider_yields_one_system() {
        let outcome = investigate_source(SOL, "solidity");
        assert_eq!(outcome.systems.len(), 1);
        assert!(!outcome.systems[0].system_id.is_empty());
    }

    #[test]
    fn source_provider_is_deterministic() {
        let a = format!(
            "{:#?}",
            investigate_source(SOL, "solidity").systems[0].hypotheses
        );
        let b = format!(
            "{:#?}",
            investigate_source(SOL, "solidity").systems[0].hypotheses
        );
        assert_eq!(a, b);
    }
}
