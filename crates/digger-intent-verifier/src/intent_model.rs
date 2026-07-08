use serde::{Deserialize, Serialize};

/// Overall risk classification of a decoded intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// No risk signals detected.
    Safe,
    /// One or more risk flags present.
    Suspicious,
    /// Critical risk indicators (unlimited approval, authority transfer, etc.).
    Dangerous,
}

/// Top-level result of intent analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAnalysis {
    /// Chain this analysis applies to.
    pub chain: String,
    /// Target address if provided.
    pub to: Option<String>,
    /// Expected address from UI (for mismatch detection).
    pub expected: Option<String>,
    /// Per-call decoded intent entries.
    pub calls: Vec<DecodedCall>,
    /// Plain-English summary.
    pub summary: String,
    /// Overall risk level.
    pub risk_level: RiskLevel,
    /// True if is_finding should be false in all output.
    pub is_finding: bool,
}

/// A single decoded calldata or instruction call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedCall {
    /// 4-byte selector hex (EVM) or 8-byte discriminator hex (Solana).
    pub selector: String,
    /// Human-readable function name (if known), or "unknown".
    pub function_name: String,
    /// Decoded arguments (key-value pairs where possible).
    pub decoded_args: Vec<ArgValue>,
    /// Plain-English description of what this call does.
    pub effect: String,
    /// Risk flags triggered by this call.
    pub risk_flags: Vec<String>,
    /// True if spender/recipient/operator differs from --to or --expected.
    pub target_mismatch: bool,
}

/// A decoded argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgValue {
    pub name: String,
    pub value: String,
    pub kind: String,
}

impl IntentAnalysis {
    pub fn new(chain: &str, to: Option<String>, expected: Option<String>) -> Self {
        Self {
            chain: chain.to_string(),
            to,
            expected,
            calls: Vec::new(),
            summary: String::new(),
            risk_level: RiskLevel::Safe,
            is_finding: false,
        }
    }

    pub fn add_call(&mut self, call: DecodedCall) {
        if call.target_mismatch {
            self.risk_level = RiskLevel::Dangerous;
        } else if !call.risk_flags.is_empty() && self.risk_level != RiskLevel::Dangerous {
            self.risk_level = RiskLevel::Suspicious;
        }
        self.calls.push(call);
    }

    pub fn finalize_summary(&mut self) {
        let call_count = self.calls.len();
        let risk_count = self
            .calls
            .iter()
            .filter(|c| !c.risk_flags.is_empty() || c.target_mismatch)
            .count();

        self.summary = format!(
            "Decoded {} call(s). {} with risk signals. Overall risk: {:?}.",
            call_count, risk_count, self.risk_level
        );
    }
}
