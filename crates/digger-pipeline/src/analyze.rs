//! Downstream analysis adapter (ADR-0025, C1.3a–d). Routes the Gen5 bridge's
//! `SystemIR` (one per system) into the existing Gen1–Gen4 consumers:
//!
//! - Gen2: hypotheses (`derive`) + security surface (`SecurityIntelligenceOutput`)
//! - Gen3: exploit synthesis (`synthesize`)
//!
//! Gen4 (execution/verification) lands in C1.3c. Iteration follows the bridge's
//! BTreeMap order, so the outcome is deterministic. Only the SystemIR and the
//! security surface feed Gen3 for now; the richer Gen2 report inputs
//! (expansion, transitions, actors, economics, ...) are wired in later slices.

use std::collections::BTreeMap;

use digger_hypothesis::{derive, HypothesisResult};
use digger_ir::SystemIR;
use digger_surface::SecurityIntelligenceOutput;
use digger_synthesis::engine::{synthesize, SynthesisConfig, SynthesisInputs};
use digger_synthesis::ExploitSearchReport;

use crate::reconstruct::{EvidenceInput, ReconstructError};
use crate::spine::Gen5Spine;
use crate::Target;

/// Per-system downstream analysis derived from one bridged `SystemIR`.
#[derive(Debug, Clone)]
pub struct SystemAnalysis {
    pub system_id: String,
    pub hypotheses: HypothesisResult,
    pub surface: SecurityIntelligenceOutput,
    pub exploits: ExploitSearchReport,
}

/// The unified terminal artifact of one investigation: the Gen5 model/context
/// identity plus per-system downstream analysis.
#[derive(Debug, Clone)]
pub struct InvestigationOutcome {
    pub model_id: String,
    pub context_id: String,
    pub systems: Vec<SystemAnalysis>,
}

/// Build the minimal Gen3 inputs from the signals we currently produce.
fn synthesis_inputs<'a>(
    ir: &'a SystemIR,
    surface: &'a SecurityIntelligenceOutput,
) -> SynthesisInputs<'a> {
    SynthesisInputs {
        ir: Some(ir),
        expansion: None,
        transitions: None,
        lifecycles: None,
        temporal: None,
        actors: None,
        economics: None,
        verification: None,
        adversarial: None,
        protocol: None,
        surface: Some(surface),
    }
}

/// Route a collection of `SystemIR` through Gen2 + Gen3 consumers.
/// Provider-agnostic: works for any source of SystemIR (bridge or source-parse).
pub fn analyze_systems(
    systems: &BTreeMap<String, SystemIR>,
    model_id: &str,
    context_id: &str,
) -> InvestigationOutcome {
    let config = SynthesisConfig::default();
    let mut analyses = Vec::new();
    for (id, ir) in systems {
        let hypotheses = derive(ir);
        let surface = SecurityIntelligenceOutput::build(ir);
        let exploits = synthesize(&synthesis_inputs(ir, &surface), &config);
        analyses.push(SystemAnalysis {
            system_id: id.clone(),
            hypotheses,
            surface,
            exploits,
        });
    }
    InvestigationOutcome {
        model_id: model_id.to_string(),
        context_id: context_id.to_string(),
        systems: analyses,
    }
}

/// Same as analyze_systems but with a DerivationContext (for corpus evidence).
pub fn analyze_systems_with_ctx(
    systems: &BTreeMap<String, SystemIR>,
    model_id: &str,
    context_id: &str,
    ctx: &digger_hypothesis::derivation::DerivationContext,
) -> InvestigationOutcome {
    let config = SynthesisConfig::default();
    let mut analyses = Vec::new();
    for (id, ir) in systems {
        let hypotheses = digger_hypothesis::derivation::derive_with_context(ir, ctx);
        let surface = SecurityIntelligenceOutput::build(ir);
        let exploits = synthesize(&synthesis_inputs(ir, &surface), &config);
        analyses.push(SystemAnalysis {
            system_id: id.clone(),
            hypotheses,
            surface,
            exploits,
        });
    }
    InvestigationOutcome {
        model_id: model_id.to_string(),
        context_id: context_id.to_string(),
        systems: analyses,
    }
}

/// Route every bridged `SystemIR` through the Gen2 + Gen3 consumers.
pub fn analyze(spine: &Gen5Spine) -> InvestigationOutcome {
    analyze_systems(
        &spine.bridged.systems,
        &spine.model.id,
        &spine.bridged.context_id,
    )
}

/// Evidence → reconstruction → Gen5 spine → Gen2/Gen3 analysis, in one call.
pub fn investigate_and_analyze(
    target: Target,
    evidence: &EvidenceInput,
) -> Result<InvestigationOutcome, ReconstructError> {
    let spine = crate::investigate(target, evidence)?;
    Ok(analyze(&spine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_reconstruct::SolanaAccount as Acct;

    const BPF_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

    fn evm_evidence() -> EvidenceInput {
        EvidenceInput::Evm {
            runtime_bytecode: vec![0x60, 0x00, 0x60, 0x00, 0x00],
        }
    }

    fn solana_evidence() -> EvidenceInput {
        let pd_key_hex = "11".repeat(32);
        let program = Acct {
            pubkey: "aa".repeat(32),
            owner: BPF_LOADER.to_string(),
            executable: true,
            data_hex: format!("02000000{}", pd_key_hex),
        };
        let program_data = Acct {
            pubkey: pd_key_hex.clone(),
            owner: BPF_LOADER.to_string(),
            executable: false,
            data_hex: "00".repeat(8),
        };
        EvidenceInput::Solana {
            program_id: "aa".repeat(32),
            accounts: vec![program, program_data],
            owned_accounts: vec![],
        }
    }

    #[test]
    fn analyze_yields_one_analysis_per_system() {
        let outcome = investigate_and_analyze(Target::Evm, &evm_evidence()).unwrap();
        assert_eq!(outcome.systems.len(), 1);
        assert_eq!(outcome.systems[0].system_id, outcome.model_id);
    }

    #[test]
    fn analyze_is_deterministic_through_gen3() {
        let a = investigate_and_analyze(Target::Evm, &evm_evidence()).unwrap();
        let b = investigate_and_analyze(Target::Evm, &evm_evidence()).unwrap();
        assert_eq!(format!("{:#?}", a), format!("{:#?}", b));
    }

    #[test]
    fn solana_flows_through_to_gen3() {
        let outcome = investigate_and_analyze(Target::Solana, &solana_evidence()).unwrap();
        assert_eq!(outcome.systems.len(), 1);
    }

    #[test]
    fn analyze_systems_works_with_manual_map() {
        let ir: SystemIR = digger_ir::SystemIR {
            program_id: "manual".into(),
            language: digger_ir::Language::Unknown,
            functions: vec![],
            state: vec![],
            edges: vec![],
        };
        let mut systems = BTreeMap::new();
        systems.insert("manual".into(), ir);
        let outcome = analyze_systems(&systems, "model", "ctx");
        assert_eq!(outcome.systems.len(), 1);
        assert_eq!(outcome.model_id, "model");
        assert_eq!(outcome.context_id, "ctx");
    }
}
