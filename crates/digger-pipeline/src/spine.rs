//! The deterministic Gen5 spine: identical for every blockchain target.
//! RecoveredFacts → ProtocolModel → InvestigationPlan → ResearchGraph →
//! ResearchContext → SystemIR (BridgedOutput). No chain-specific types appear.

use digger_investigation::{build_investigation_plan, InvestigationPlan};
use digger_protocol_model::model::{build_protocol_model, ProtocolModel};
use digger_reconstruct::body::RecoveredBodyGraph;
use digger_reconstruct::dependency::RecoveredDependency;
use digger_reconstruct::deployment::RecoveredDeployment;
use digger_reconstruct::interface::RecoveredInterface;
use digger_research_context::{assemble_research_context, ResearchContext};
use digger_research_graph::build_research_graph;
use digger_research_graph::graph::ResearchGraph;
use digger_systemir_bridge::{bridge_to_systemir, BridgedOutput};

/// Chain-agnostic recovered-fact bundle: the output of reconstruction and the
/// input to the Gen5 spine. Only chain-agnostic recovered-fact types appear.
#[derive(Debug, Clone)]
pub struct RecoveredFacts {
    pub deployment: Option<RecoveredDeployment>,
    pub dependencies: Vec<RecoveredDependency>,
    pub interface: Option<RecoveredInterface>,
    /// Body/operation evidence (ADR-0026). Always `None` until C5.2+
    /// recovery logic is implemented. Existing consumers are unaffected.
    pub body: Option<RecoveredBodyGraph>,
}

/// All deterministic stage outputs of one investigation, retained for lineage.
#[derive(Debug, Clone)]
pub struct Gen5Spine {
    pub model: ProtocolModel,
    pub plan: InvestigationPlan,
    pub graph: ResearchGraph,
    pub context: ResearchContext,
    pub bridged: BridgedOutput,
}

/// Run the deterministic Gen5 spine. Pure: equal facts yield byte-identical
/// output. Preserves provenance/confidence/ids from each underlying builder.
pub fn run_gen5_spine(facts: &RecoveredFacts) -> Gen5Spine {
    let model = build_protocol_model(
        facts.deployment.as_ref(),
        &facts.dependencies,
        facts.interface.as_ref(),
    );
    let plan = build_investigation_plan(&model);
    let graph = build_research_graph(&model, &plan);
    let context = assemble_research_context(&model, &plan, &graph);
    let bridged = bridge_to_systemir(&model, &plan, &context);
    Gen5Spine {
        model,
        plan,
        graph,
        context,
        bridged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digger_reconstruct::confidence::ConfidenceTier;
    use digger_reconstruct::deployment::{
        AuthorityKind, DeploymentDetail, DeploymentKind, DeploymentMetadata, EvmDeployment,
        RecoveredAddress, RecoveredAuthority, RecoveredDeployment,
    };
    use digger_reconstruct::provenance::{EvidenceSource, Provenance, ReconstructionStage};

    fn prov() -> Provenance {
        Provenance::new(
            EvidenceSource::DeploymentBytecode,
            ReconstructionStage::Recover,
            ConfidenceTier::Recovered,
            "pipeline-spine-test",
        )
    }

    fn facts() -> RecoveredFacts {
        let dep = RecoveredDeployment {
            id: "deploy:spine".to_string(),
            kind: DeploymentKind::Evm,
            detail: DeploymentDetail::Evm(EvmDeployment {
                id: "evmdeploy:spine".to_string(),
                proxies: vec![],
                implementation_chain: vec![],
                upgrade_authority: Some(RecoveredAuthority {
                    id: "auth:spine".to_string(),
                    kind: AuthorityKind::UpgradeAuthority,
                    address: RecoveredAddress::Resolved("0x5678".to_string()),
                    provenance: prov(),
                }),
                upgrade_path: vec![],
                relationships: vec![],
                metadata: DeploymentMetadata {
                    runtime_code_len: 0,
                    runtime_code_digest: "0".to_string(),
                },
                truncated_at_max_depth: false,
                provenance: prov(),
            }),
            provenance: prov(),
        };
        RecoveredFacts {
            deployment: Some(dep),
            dependencies: vec![],
            interface: None,
            body: None,
        }
    }

    #[test]
    fn spine_produces_one_system() {
        let out = run_gen5_spine(&facts());
        assert_eq!(out.bridged.systems.len(), 1);
        assert!(out.bridged.systems.contains_key(&out.model.id));
        assert_eq!(out.bridged.context_id, out.context.id);
    }

    #[test]
    fn spine_is_deterministic() {
        let f = facts();
        let a = run_gen5_spine(&f);
        let b = run_gen5_spine(&f);
        assert_eq!(format!("{:#?}", a.bridged), format!("{:#?}", b.bridged));
    }
}
