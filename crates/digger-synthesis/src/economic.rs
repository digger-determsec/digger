/// Generation 3.1c — Economic Validation Layer
///
/// Estimates asset movement through synthesized attacks, tracks value
/// conservation, estimates attacker gain/loss, and rejects economically
/// impossible or unprofitable exploit paths.
use crate::models::*;
use std::collections::BTreeMap;

/// Result of economic validation for a chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EconomicValidationResult {
    /// Chain being validated.
    pub chain_id: String,
    /// Estimated asset flows per step.
    pub step_flows: Vec<EconomicStepFlow>,
    /// Total estimated attacker gain.
    pub estimated_gain: BTreeMap<String, f64>,
    /// Total estimated attacker cost.
    pub estimated_cost: BTreeMap<String, f64>,
    /// Net profit estimate.
    pub net_profit: BTreeMap<String, f64>,
    /// Whether value is conserved across all steps.
    pub value_conserved: bool,
    /// Whether the exploit is economically viable.
    pub economically_viable: bool,
    /// Conservation violations.
    pub conservation_violations: Vec<String>,
    /// Explanation.
    pub explanation: String,
}

/// Asset flow for a single step.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EconomicStepFlow {
    /// Step index.
    pub step_index: usize,
    /// Assets entering the attacker's control.
    pub inflows: BTreeMap<String, f64>,
    /// Assets leaving the attacker's control.
    pub outflows: BTreeMap<String, f64>,
    /// Net flow for this step.
    pub net: BTreeMap<String, f64>,
}

/// Validate economic viability of an exploit chain.
pub fn validate_economics(
    chain: &ExploitChain,
    inputs: &crate::engine::SynthesisInputs,
) -> EconomicValidationResult {
    let mut step_flows = Vec::new();
    let mut total_gain: BTreeMap<String, f64> = BTreeMap::new();
    let mut total_cost: BTreeMap<String, f64> = BTreeMap::new();
    let mut conservation_violations = Vec::new();

    for step in &chain.steps {
        let flow = estimate_step_flow(step, inputs);
        step_flows.push(flow);
    }

    // Aggregate flows
    for flow in &step_flows {
        for (asset, amount) in &flow.inflows {
            *total_gain.entry(asset.clone()).or_insert(0.0) += amount;
        }
        for (asset, amount) in &flow.outflows {
            *total_cost.entry(asset.clone()).or_insert(0.0) += amount;
        }
    }

    // Compute net profit
    let mut net_profit: BTreeMap<String, f64> = BTreeMap::new();
    for (asset, gain) in &total_gain {
        let cost = total_cost.get(asset).unwrap_or(&0.0);
        net_profit.insert(asset.clone(), gain - cost);
    }

    // Check value conservation
    let value_conserved = check_value_conservation(&step_flows, &mut conservation_violations);

    // Determine economic viability
    let net_positive = net_profit.values().any(|v| *v > 0.0);
    let has_evidence = !chain.evidence_provenance.is_empty();
    let economically_viable = net_positive && has_evidence && value_conserved;

    let explanation = if economically_viable {
        format!(
            "Economically viable: net profit from {} asset(s), value conserved",
            net_profit.len()
        )
    } else if !net_positive {
        "Not economically viable: net loss across all assets".into()
    } else if !value_conserved {
        format!(
            "Value conservation violated: {}",
            conservation_violations.join(", ")
        )
    } else {
        "Not economically viable: insufficient evidence".into()
    };

    EconomicValidationResult {
        chain_id: chain.chain_id.clone(),
        step_flows,
        estimated_gain: total_gain,
        estimated_cost: total_cost,
        net_profit,
        value_conserved,
        economically_viable,
        conservation_violations,
        explanation,
    }
}

/// Estimate asset flow for a single step.
fn estimate_step_flow(
    step: &ExploitStep,
    _inputs: &crate::engine::SynthesisInputs,
) -> EconomicStepFlow {
    let mut inflows = BTreeMap::new();
    let mut outflows = BTreeMap::new();

    match step.state_transition {
        ExploitState::ValueExtraction => {
            // Value extraction step — attacker gains
            for asset in &step.affected_assets {
                inflows.insert(asset.clone(), 1.0); // Abstract unit
            }
        }
        ExploitState::Execution => {
            // Execution may require paying gas/fees
            for asset in &step.affected_assets {
                outflows.insert(asset.clone(), 0.01); // Abstract cost
            }
        }
        ExploitState::Preparation => {
            // Preparation may require depositing funds
            for asset in &step.affected_assets {
                outflows.insert(asset.clone(), 0.001); // Small setup cost
            }
        }
        _ => {}
    }

    let mut net = BTreeMap::new();
    for (asset, amount) in &inflows {
        let cost = outflows.get(asset).unwrap_or(&0.0);
        net.insert(asset.clone(), amount - cost);
    }
    for (asset, amount) in &outflows {
        if !net.contains_key(asset) {
            net.insert(asset.clone(), -*amount);
        }
    }

    EconomicStepFlow {
        step_index: step.index,
        inflows,
        outflows,
        net,
    }
}

/// Check value conservation across all steps.
fn check_value_conservation(flows: &[EconomicStepFlow], violations: &mut Vec<String>) -> bool {
    let mut total_by_asset: BTreeMap<String, f64> = BTreeMap::new();

    for flow in flows {
        for (asset, net) in &flow.net {
            *total_by_asset.entry(asset.clone()).or_insert(0.0) += net;
        }
    }

    // Check if net flows are reasonable (not creating value from nothing)
    // A positive net means value was transferred TO attacker, which is expected for exploits
    // A very large positive net might indicate impossible value creation
    for (asset, net) in &total_by_asset {
        if *net > 1000.0 {
            violations.push(format!(
                "Suspiciously large value creation for {}: {}",
                asset, net
            ));
        }
    }

    violations.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_economic_validation_empty() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.5,
            severity: digger_ir::Severity::Medium,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };

        let inputs = crate::engine::SynthesisInputs {
            ir: None,
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };

        let result = validate_economics(&chain, &inputs);
        assert!(result.value_conserved);
    }

    #[test]
    fn test_value_extraction_flow() {
        let chain = ExploitChain {
            chain_id: "test".into(),
            goal: "test".into(),
            steps: vec![ExploitStep {
                index: 0,
                state_transition: ExploitState::ValueExtraction,
                function: "withdraw".into(),
                action: "extract".into(),
                required_capability: ExploitCapability::TransferAssets,
                affected_state: vec![],
                affected_assets: vec!["USDC".into()],
                prerequisites: vec![],
                mutations: vec!["withdraw USDC".into()],
                evidence_refs: vec![],
                confidence: 0.7,
                explanation: "test".into(),
            }],
            required_capabilities: vec![],
            assumptions: vec![],
            violated_invariants: vec![],
            evidence_provenance: vec![],
            confidence: 0.7,
            severity: digger_ir::Severity::High,
            historical_similarity: vec![],
            rank: None,
            explanation: "test".into(),
        };

        let inputs = crate::engine::SynthesisInputs {
            ir: None,
            expansion: None,
            transitions: None,
            lifecycles: None,
            temporal: None,
            actors: None,
            economics: None,
            verification: None,
            adversarial: None,
            protocol: None,
            surface: None,
        };

        let result = validate_economics(&chain, &inputs);
        assert!(result.estimated_gain.contains_key("USDC"));
        assert!(*result.estimated_gain.get("USDC").unwrap() > 0.0);
    }
}
