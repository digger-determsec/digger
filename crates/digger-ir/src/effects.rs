/// Observable side-effects of an executable unit.
///
/// Populated by the graph builder during pattern matching on function bodies.
/// The hypothesis engine uses these flags to identify reentrancy, access-control,
/// and value-transfer patterns.
#[derive(Debug, Clone, Default)]
pub struct Effects {
    pub state_mutation: bool,
    pub external_call: bool,
    pub authority_required: bool,
    pub value_transfer: bool,
    /// Function body contains arithmetic operators (*, /, %) — used by oracle
    /// manipulation detector to distinguish rate-computation from simple transfers.
    pub has_arithmetic: bool,
    /// Function body contains temporal guard patterns (block.number/timestamp
    /// comparisons, require/assert with time conditions, timelock/delay/snapshot
    /// state variables, or known guard modifiers like nonReentrant/whenNotPaused).
    /// TEXT/SUBSTRING signal — detects presence of guard syntax, not semantic
    /// sufficiency. Absence of this flag is the vulnerability indicator.
    pub has_temporal_guard: bool,
    /// Structured value-flow representation computed from AST walking.
    /// Populated by the Solidity parser; None for Rust/Anchor (text fallback).
    /// Replaces the boolean has_arithmetic with data-flow-aware signals.
    pub value_flow: Option<ValueFlow>,
    /// Arithmetic expressions inside Solidity `unchecked {}` blocks.
    /// Detects overflow-prone math that the compiler won't check. AST-derived:
    /// solang Statement::Block { unchecked: true } contains multiply/divide/modulo.
    pub has_unchecked_arithmetic: bool,
    /// Whether any state-mutating write targets a mapping indexed by msg.sender
    /// (caller-scoped state). AST-derived: ArraySubscript whose index contains
    /// the Solidity keyword `msg.sender`. Does NOT fire for global/other-account writes.
    pub writes_caller_scoped_state: bool,
    /// Division-before-multiplication ordering within a single expression.
    /// Detects precision-loss pattern: `a / b * c` where the Divide is a direct
    /// child of Multiply. AST-derived from Expression::Multiply(Divide(a,b), c).
    /// Cross-statement case (`uint x=a/b; y=x*c`) requires SSA — deferred.
    pub has_precision_loss_ordering: bool,
}

/// Structured value-flow representation for a function, computed from AST.
///
/// Captures which state variables participate in arithmetic and whether
/// the result flows into a value transfer. This is the substrate that
/// replaces text-flag `has_arithmetic` with real data-flow awareness.
///
/// The oracle detector uses `state_reads_in_arithmetic` + `value_transfer`
/// instead of the flat `has_arithmetic` flag. The flash-loan detector
/// can distinguish "balance-derived transfer" from "arbitrary transfer."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueFlow {
    /// State variables that are READ by this function.
    pub state_reads: Vec<String>,
    /// State variables that are WRITTEN by this function.
    pub state_writes: Vec<String>,
    /// State variables whose values flow into arithmetic operations.
    /// If a function reads `balances[addr]` and computes `balances[addr] * rate / 1000`,
    /// this set contains "balances".
    pub state_reads_in_arithmetic: Vec<String>,
    /// Whether any arithmetic result flows into a value-transfer amount.
    /// True when: arithmetic_output → transfer(msg.sender, amount) pattern exists.
    pub arithmetic_feeds_value_transfer: bool,
    /// Whether the function reads a balance/reserve-like variable
    /// (balanceOf, totalSupply, reserve, deposit, staked) through arithmetic.
    pub reads_balance_through_arithmetic: bool,
}

use serde::{Deserialize, Serialize};
