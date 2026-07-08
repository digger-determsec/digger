/// Protocol IR models — cross-program analysis structures.
///
/// All structures are deterministic and JSON serializable.
/// No AI, no inference, no heuristics, no scoring.
use serde::{Deserialize, Serialize};

/// Top-level protocol analysis result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolIR {
    /// Protocol identifier (directory name or explicit).
    pub protocol_id: String,
    /// All contracts analyzed.
    pub contracts: Vec<ContractAnalysis>,
    /// Cross-program call edges.
    pub cross_program_calls: Vec<CrossProgramCall>,
    /// Storage layouts per contract.
    pub storage_layouts: Vec<StorageLayout>,
    /// Detected proxy patterns.
    pub proxy_patterns: Vec<ProxyPattern>,
    /// Detected vulnerabilities.
    pub vulnerabilities: Vec<ProtocolVulnerability>,
}

/// Analysis of a single contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractAnalysis {
    /// Contract name.
    pub name: String,
    /// Contract kind: "contract", "interface", "abstract", "library".
    pub kind: String,
    /// State variable declarations in order.
    pub state_variables: Vec<StateVariableDecl>,
    /// Whether this contract has a fallback function with delegatecall.
    pub has_delegatecall_fallback: bool,
    /// Whether this contract has an initialize function.
    pub has_initializer: bool,
    /// Whether this contract uses delegatecall anywhere.
    pub uses_delegatecall: bool,
}

/// A state variable declaration with storage position.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateVariableDecl {
    /// Variable name.
    pub name: String,
    /// Type string.
    pub ty: String,
    /// Storage slot number (0-indexed, sequential from declaration order).
    pub slot: usize,
    /// Byte offset within the slot (0 for most types, 0-31 for packed).
    pub offset: usize,
    /// Whether the variable occupies a full slot (32 bytes).
    pub full_slot: bool,
}

/// Storage layout for a contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageLayout {
    /// Contract name.
    pub contract_name: String,
    /// State variables with slot assignments.
    pub variables: Vec<StateVariableDecl>,
    /// Total slots used.
    pub total_slots: usize,
}

/// A cross-program call relationship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrossProgramCall {
    /// Calling contract name.
    pub from_contract: String,
    /// Calling function name.
    pub from_function: String,
    /// Target contract or interface name.
    pub to_contract: String,
    /// Call type: "delegatecall", "external", "interface".
    pub call_type: String,
}

/// A detected proxy pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyPattern {
    /// Proxy contract name.
    pub proxy_contract: String,
    /// Implementation contract name (if resolvable).
    pub implementation_contract: Option<String>,
    /// Storage slot of the implementation address variable.
    pub implementation_slot: Option<usize>,
    /// Pattern type: "transparent_proxy", "uups", "beacon", "generic_delegatecall".
    pub pattern_type: String,
}

/// A protocol-level vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolVulnerability {
    /// Vulnerability type.
    pub vuln_type: String,
    /// Severity.
    pub severity: digger_ir::Severity,
    /// Affected contracts.
    pub affected_contracts: Vec<String>,
    /// Human-readable description.
    pub description: String,
    /// Evidence: specific slots, variables, or patterns.
    pub evidence: Vec<String>,
}
