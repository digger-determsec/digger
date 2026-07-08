use crate::intent_model::{ArgValue, DecodedCall, IntentAnalysis, RiskLevel};
use serde_json::Value;

/// Known 4-byte selectors for dangerous-intent detection.
struct KnownSelector {
    selector: &'static str,
    name: &'static str,
}

const KNOWN_SELECTORS: &[KnownSelector] = &[
    KnownSelector {
        selector: "095ea7b3",
        name: "approve",
    },
    KnownSelector {
        selector: "a22cb465",
        name: "setApprovalForAll",
    },
    KnownSelector {
        selector: "d505accf",
        name: "permit",
    },
    KnownSelector {
        selector: "a9059cbb",
        name: "transfer",
    },
    KnownSelector {
        selector: "23b872dd",
        name: "transferFrom",
    },
    KnownSelector {
        selector: "b65d0947",
        name: "increaseAllowance",
    },
    KnownSelector {
        selector: "39509351",
        name: "decreaseAllowance",
    },
    KnownSelector {
        selector: "fc0c546a",
        name: "multicall",
    },
    KnownSelector {
        selector: "5ae401dc",
        name: "multicall",
    },
    KnownSelector {
        selector: "472b43f3",
        name: "delegatecall",
    },
];

/// EIP-712 type hashes for known permit-related messages.
const ERC2612_PERMIT_TYPEHASH: &str =
    "6e71edae12b1b97f4d1f60370fef10105ff2fa7323137014f608c4a92b14a203";

/// Permit2 PermitSingle domain separator type prefix (Uniswap Permit2).
const PERMIT2_PERMITSINGLE_DOMAIN: &str = "PermitSingle";

const UINT256_MAX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn is_unlimited_or_large(hex_value: &str) -> bool {
    let val = hex_value.trim_start_matches('0');
    if val.is_empty() {
        return false;
    }
    val == UINT256_MAX || val.len() >= 60
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()
}

// ── Calldata decoder ──────────────────────────────────────────

pub fn decode_evm_calldata(
    calldata_hex: &str,
    to: Option<&str>,
    expected: Option<&str>,
) -> IntentAnalysis {
    let hex_str = calldata_hex.trim_start_matches("0x").trim();
    let bytes = match hex_decode(hex_str) {
        Some(b) => b,
        None => {
            let mut result =
                IntentAnalysis::new("evm", to.map(String::from), expected.map(String::from));
            result.add_call(DecodedCall {
                selector: "invalid".into(),
                function_name: "unknown".into(),
                decoded_args: vec![],
                effect: "Invalid hex in calldata".into(),
                risk_flags: vec!["invalid_input".into()],
                target_mismatch: false,
            });
            result.risk_level = RiskLevel::Suspicious;
            result.finalize_summary();
            return result;
        }
    };

    let mut result = IntentAnalysis::new("evm", to.map(String::from), expected.map(String::from));

    if bytes.len() < 4 {
        result.add_call(DecodedCall {
            selector: hex_str.to_string(),
            function_name: "unknown".into(),
            decoded_args: vec![],
            effect: format!("Calldata too short ({} bytes)", bytes.len()),
            risk_flags: vec!["malformed_calldata".into()],
            target_mismatch: false,
        });
        result.risk_level = RiskLevel::Suspicious;
        result.finalize_summary();
        return result;
    }

    let selector_hex = hex::encode(&bytes[0..4]);
    let arg_words: Vec<String> = bytes[4..].chunks(32).map(hex::encode).collect();

    let known = KNOWN_SELECTORS.iter().find(|s| s.selector == selector_hex);
    let function_name = known.map(|k| k.name).unwrap_or("unknown");

    let mut decoded_args = Vec::new();
    let mut risk_flags = Vec::new();
    let mut target_mismatch = false;
    let mut effect = String::new();

    match selector_hex.as_str() {
        "095ea7b3" => {
            if arg_words.len() >= 2 {
                let spender = &arg_words[0];
                let amount = &arg_words[1];
                decoded_args.push(ArgValue {
                    name: "spender".into(),
                    value: format!("0x{spender}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "amount".into(),
                    value: format!("0x{amount}"),
                    kind: "uint256".into(),
                });
                if is_unlimited_or_large(amount) {
                    risk_flags.push("unlimited_approval".into());
                    effect = format!("Grants spender 0x{spender} UNLIMITED approval.");
                } else {
                    effect = format!("Grants spender 0x{spender} approval for {amount} tokens.");
                }
                if let Some(exp) = expected {
                    let exp_clean = exp.trim_start_matches("0x").to_lowercase();
                    let spender_clean = spender.trim_start_matches("0x").to_lowercase();
                    if exp_clean != spender_clean {
                        target_mismatch = true;
                        risk_flags.push("target_mismatch".into());
                        effect.push_str(&format!(" WARNING: spender differs from expected {exp}"));
                    }
                }
            }
        }
        "b65d0947" => {
            if arg_words.len() >= 2 {
                let spender = &arg_words[0];
                let amount = &arg_words[1];
                decoded_args.push(ArgValue {
                    name: "spender".into(),
                    value: format!("0x{spender}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "amount".into(),
                    value: format!("0x{amount}"),
                    kind: "uint256".into(),
                });
                risk_flags.push("allowance_increase".into());
                effect = format!("Increases allowance for 0x{spender} by {amount}.");
            }
        }
        "a22cb465" => {
            if arg_words.len() >= 2 {
                let operator = &arg_words[0];
                let approved = arg_words[1].trim_start_matches('0') != "0";
                decoded_args.push(ArgValue {
                    name: "operator".into(),
                    value: format!("0x{operator}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "approved".into(),
                    value: approved.to_string(),
                    kind: "bool".into(),
                });
                if approved {
                    risk_flags.push("nft_drainer".into());
                    effect = format!("Grants operator 0x{operator} FULL approval over all NFTs.");
                } else {
                    effect = format!("Revokes operator 0x{operator} NFT approval.");
                }
                if let Some(exp) = expected {
                    let exp_clean = exp.trim_start_matches("0x").to_lowercase();
                    let op_clean = operator.trim_start_matches("0x").to_lowercase();
                    if exp_clean != op_clean {
                        target_mismatch = true;
                        risk_flags.push("target_mismatch".into());
                    }
                }
            }
        }
        "d505accf" => {
            if arg_words.len() >= 2 {
                let owner = &arg_words[0];
                let spender = &arg_words[1];
                let amount = if arg_words.len() > 2 {
                    &arg_words[2]
                } else {
                    "unknown"
                };
                decoded_args.push(ArgValue {
                    name: "owner".into(),
                    value: format!("0x{owner}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "spender".into(),
                    value: format!("0x{spender}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "amount".into(),
                    value: format!("0x{amount}"),
                    kind: "uint256".into(),
                });
                risk_flags.push("permit_phishing".into());
                effect = format!(
                    "Off-chain signed approval: 0x{owner} grants 0x{spender} {amount} tokens."
                );
                if is_unlimited_or_large(amount) {
                    risk_flags.push("unlimited_approval".into());
                    effect.push_str(" UNLIMITED.");
                }
                if let Some(exp) = expected {
                    let exp_clean = exp.trim_start_matches("0x").to_lowercase();
                    let owner_clean = owner.trim_start_matches("0x").to_lowercase();
                    if exp_clean != owner_clean {
                        target_mismatch = true;
                        risk_flags.push("target_mismatch".into());
                    }
                }
            }
        }
        "a9059cbb" => {
            if arg_words.len() >= 2 {
                let to_addr = &arg_words[0];
                let amount = &arg_words[1];
                decoded_args.push(ArgValue {
                    name: "to".into(),
                    value: format!("0x{to_addr}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "amount".into(),
                    value: format!("0x{amount}"),
                    kind: "uint256".into(),
                });
                effect = format!("Transfers {amount} tokens to 0x{to_addr}.");
                if let Some(exp) = expected {
                    let exp_clean = exp.trim_start_matches("0x").to_lowercase();
                    let to_clean = to_addr.trim_start_matches("0x").to_lowercase();
                    if exp_clean != to_clean {
                        target_mismatch = true;
                        risk_flags.push("target_mismatch".into());
                        effect
                            .push_str(&format!(" WARNING: recipient differs from expected {exp}"));
                    }
                }
            }
        }
        "23b872dd" => {
            if arg_words.len() >= 3 {
                let from = &arg_words[0];
                let to_addr = &arg_words[1];
                let amount = &arg_words[2];
                decoded_args.push(ArgValue {
                    name: "from".into(),
                    value: format!("0x{from}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "to".into(),
                    value: format!("0x{to_addr}"),
                    kind: "address".into(),
                });
                decoded_args.push(ArgValue {
                    name: "amount".into(),
                    value: format!("0x{amount}"),
                    kind: "uint256".into(),
                });
                effect = format!("Transfers {amount} from 0x{from} to 0x{to_addr}.");
                if let Some(exp) = expected {
                    let exp_clean = exp.trim_start_matches("0x").to_lowercase();
                    let to_clean = to_addr.trim_start_matches("0x").to_lowercase();
                    if exp_clean != to_clean {
                        target_mismatch = true;
                        risk_flags.push("target_mismatch".into());
                    }
                }
            }
        }
        "fc0c546a" | "5ae401dc" => {
            risk_flags.push("batch_operation".into());
            effect = "Batch/multicall — inner calls require separate decoding.".into();
        }
        "472b43f3" => {
            risk_flags.push("delegatecall".into());
            risk_flags.push("code_execution".into());
            effect = "DELEGATECALL — executes arbitrary code in this contract's context.".into();
        }
        _ => {
            effect = format!("Unknown selector 0x{selector_hex}.");
            if arg_words.is_empty() {
                effect.push_str(" No argument data.");
            } else {
                effect.push_str(&format!(" {} argument word(s) present.", arg_words.len()));
            }
        }
    }

    result.add_call(DecodedCall {
        selector: format!("0x{selector_hex}"),
        function_name: function_name.into(),
        decoded_args,
        effect,
        risk_flags,
        target_mismatch,
    });

    result.finalize_summary();
    result
}

// ── EIP-712 decoder ──────────────────────────────────────────

/// Decode an EIP-712 typed data JSON into an IntentAnalysis.
/// Supports ERC-2612 permit and Permit2 PermitSingle/PermitBatch.
pub fn decode_eip712(
    typed_data: &Value,
    to: Option<&str>,
    expected: Option<&str>,
) -> IntentAnalysis {
    let mut result = IntentAnalysis::new("evm", to.map(String::from), expected.map(String::from));

    let primary_type = typed_data
        .get("primaryType")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let message = typed_data.get("message");

    match primary_type {
        "Permit" => decode_erc2612_permit(message, to, expected, &mut result),
        "PermitSingle" => decode_permit2_single(message, to, expected, &mut result),
        "PermitBatch" => decode_permit2_batch(message, to, expected, &mut result),
        _ => {
            result.add_call(DecodedCall {
                selector: "eip712".into(),
                function_name: primary_type.into(),
                decoded_args: vec![],
                effect: format!(
                    "EIP-712 typed message with primaryType={primary_type}. No specific handler."
                ),
                risk_flags: vec![],
                target_mismatch: false,
            });
        }
    }

    result.finalize_summary();
    result
}

fn decode_erc2612_permit(
    message: Option<&Value>,
    _to: Option<&str>,
    expected: Option<&str>,
    result: &mut IntentAnalysis,
) {
    let msg = match message {
        Some(m) => m,
        None => {
            result.add_call(DecodedCall {
                selector: "eip712-permit".into(),
                function_name: "permit".into(),
                decoded_args: vec![],
                effect: "EIP-712 Permit message with missing 'message' field.".into(),
                risk_flags: vec!["malformed_eip712".into()],
                target_mismatch: false,
            });
            return;
        }
    };

    let owner = msg.get("owner").and_then(|v| v.as_str()).unwrap_or("");
    let spender = msg.get("spender").and_then(|v| v.as_str()).unwrap_or("");
    let value = msg.get("value").and_then(|v| v.as_str()).unwrap_or("0");
    let nonce = msg.get("nonce").and_then(|v| v.as_str()).unwrap_or("0");
    let deadline = msg.get("deadline").and_then(|v| v.as_str()).unwrap_or("0");

    let decoded_args = vec![
        ArgValue {
            name: "owner".into(),
            value: format!("0x{owner}"),
            kind: "address".into(),
        },
        ArgValue {
            name: "spender".into(),
            value: format!("0x{spender}"),
            kind: "address".into(),
        },
        ArgValue {
            name: "value".into(),
            value: format!("0x{value}"),
            kind: "uint256".into(),
        },
        ArgValue {
            name: "nonce".into(),
            value: nonce.to_string(),
            kind: "uint256".into(),
        },
        ArgValue {
            name: "deadline".into(),
            value: deadline.to_string(),
            kind: "uint256".into(),
        },
    ];

    let mut risk_flags = vec!["permit_phishing".into()];
    let mut target_mismatch = false;
    let mut effect = format!("ERC-2612 Permit: 0x{owner} grants 0x{spender} {value} tokens (off-chain gasless approval).");

    if is_unlimited_or_large(value) {
        risk_flags.push("unlimited_approval".into());
        effect.push_str(" UNLIMITED amount.");
    }

    if let Some(exp) = expected {
        let exp_clean = exp.trim_start_matches("0x").to_lowercase();
        let owner_clean = owner.trim_start_matches("0x").to_lowercase();
        if exp_clean != owner_clean {
            target_mismatch = true;
            risk_flags.push("target_mismatch".into());
        }
    }

    result.add_call(DecodedCall {
        selector: ERC2612_PERMIT_TYPEHASH.into(),
        function_name: "permit".into(),
        decoded_args,
        effect,
        risk_flags,
        target_mismatch,
    });
}

fn decode_permit2_single(
    message: Option<&Value>,
    _to: Option<&str>,
    expected: Option<&str>,
    result: &mut IntentAnalysis,
) {
    let msg = match message {
        Some(m) => m,
        None => {
            result.add_call(DecodedCall {
                selector: "permit2".into(),
                function_name: "PermitSingle".into(),
                decoded_args: vec![],
                effect: "Permit2 PermitSingle with missing 'message' field.".into(),
                risk_flags: vec!["malformed_eip712".into()],
                target_mismatch: false,
            });
            return;
        }
    };

    let owner = msg.get("owner").and_then(|v| v.as_str()).unwrap_or("");
    let spender = msg.get("spender").and_then(|v| v.as_str()).unwrap_or("");
    let amount = msg.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
    let token = msg.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let sig_deadline = msg
        .get("sigDeadline")
        .and_then(|v| v.as_str())
        .unwrap_or("0");

    let decoded_args = vec![
        ArgValue {
            name: "owner".into(),
            value: format!("0x{owner}"),
            kind: "address".into(),
        },
        ArgValue {
            name: "spender".into(),
            value: format!("0x{spender}"),
            kind: "address".into(),
        },
        ArgValue {
            name: "amount".into(),
            value: format!("0x{amount}"),
            kind: "uint256".into(),
        },
        ArgValue {
            name: "token".into(),
            value: format!("0x{token}"),
            kind: "address".into(),
        },
        ArgValue {
            name: "sigDeadline".into(),
            value: sig_deadline.to_string(),
            kind: "uint256".into(),
        },
    ];

    let mut risk_flags = vec!["permit2_phishing".into()];
    let mut target_mismatch = false;
    let mut effect =
        format!("Permit2 PermitSingle: 0x{owner} grants 0x{spender} {amount} tokens of 0x{token}.");

    if is_unlimited_or_large(amount) {
        risk_flags.push("unlimited_approval".into());
        effect.push_str(" UNLIMITED amount.");
    }

    if let Some(exp) = expected {
        let exp_clean = exp.trim_start_matches("0x").to_lowercase();
        let owner_clean = owner.trim_start_matches("0x").to_lowercase();
        if exp_clean != owner_clean {
            target_mismatch = true;
            risk_flags.push("target_mismatch".into());
        }
    }

    result.add_call(DecodedCall {
        selector: PERMIT2_PERMITSINGLE_DOMAIN.into(),
        function_name: "PermitSingle".into(),
        decoded_args,
        effect,
        risk_flags,
        target_mismatch,
    });
}

fn decode_permit2_batch(
    message: Option<&Value>,
    _to: Option<&str>,
    expected: Option<&str>,
    result: &mut IntentAnalysis,
) {
    let msg = match message {
        Some(m) => m,
        None => {
            result.add_call(DecodedCall {
                selector: "permit2".into(),
                function_name: "PermitBatch".into(),
                decoded_args: vec![],
                effect: "Permit2 PermitBatch with missing 'message' field.".into(),
                risk_flags: vec!["malformed_eip712".into()],
                target_mismatch: false,
            });
            return;
        }
    };

    let owner = msg.get("owner").and_then(|v| v.as_str()).unwrap_or("");
    let spender = msg.get("spender").and_then(|v| v.as_str()).unwrap_or("");

    let mut decoded_args = vec![
        ArgValue {
            name: "owner".into(),
            value: format!("0x{owner}"),
            kind: "address".into(),
        },
        ArgValue {
            name: "spender".into(),
            value: format!("0x{spender}"),
            kind: "address".into(),
        },
    ];

    let mut risk_flags = vec!["permit2_phishing".into()];
    let mut target_mismatch = false;
    let mut effect =
        format!("Permit2 PermitBatch: 0x{owner} grants multi-token approval to 0x{spender}.");

    // Check individual amounts
    if let Some(amounts) = msg.get("amounts").and_then(|v| v.as_array()) {
        for (i, amt) in amounts.iter().enumerate() {
            let amt_str = amt.as_str().unwrap_or("0");
            decoded_args.push(ArgValue {
                name: format!("amount[{i}]"),
                value: format!("0x{amt_str}"),
                kind: "uint256".into(),
            });
            if is_unlimited_or_large(amt_str) {
                risk_flags.push("unlimited_approval".into());
                effect.push_str(" Contains UNLIMITED amount.");
                break;
            }
        }
    }

    if let Some(exp) = expected {
        let exp_clean = exp.trim_start_matches("0x").to_lowercase();
        let owner_clean = owner.trim_start_matches("0x").to_lowercase();
        if exp_clean != owner_clean {
            target_mismatch = true;
            risk_flags.push("target_mismatch".into());
        }
    }

    result.add_call(DecodedCall {
        selector: "permit2-batch".into(),
        function_name: "PermitBatch".into(),
        decoded_args,
        effect,
        risk_flags,
        target_mismatch,
    });
}

// ── Transaction JSON decoder ──────────────────────────────────

/// Decode a standard Ethereum transaction JSON.
pub fn decode_tx_json(tx: &Value, to: Option<&str>, expected: Option<&str>) -> IntentAnalysis {
    let calldata = tx
        .get("input")
        .or_else(|| tx.get("data"))
        .and_then(|v| v.as_str());
    let tx_to = tx.get("to").and_then(|v| v.as_str()).or(to);
    let value = tx.get("value").and_then(|v| v.as_str());

    let mut result =
        IntentAnalysis::new("evm", tx_to.map(String::from), expected.map(String::from));

    // Check ETH value transfer
    if let Some(val) = value {
        let val_clean = val.trim_start_matches("0x");
        if !val_clean.is_empty() && val_clean != "0" {
            let is_large = is_unlimited_or_large(val_clean);
            result.add_call(DecodedCall {
                selector: "eth-value".into(),
                function_name: "value_transfer".into(),
                decoded_args: vec![ArgValue {
                    name: "value".into(),
                    value: format!("0x{val_clean}"),
                    kind: "uint256".into(),
                }],
                effect: format!("Transaction carries {val_clean} wei of ETH."),
                risk_flags: if is_large {
                    vec!["large_eth_value".into()]
                } else {
                    vec![]
                },
                target_mismatch: false,
            });
            if is_large {
                result.risk_level = RiskLevel::Dangerous;
            }
        }
    }

    // Decode calldata if present
    if let Some(cd) = calldata {
        let inner = decode_evm_calldata(cd, tx_to, expected);
        for call in inner.calls {
            result.add_call(call);
        }
    } else {
        result.add_call(DecodedCall {
            selector: "none".into(),
            function_name: "no_calldata".into(),
            decoded_args: vec![],
            effect: "Transaction has no calldata (pure ETH transfer or creation).".into(),
            risk_flags: vec![],
            target_mismatch: false,
        });
    }

    result.finalize_summary();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_basic() {
        let to_addr = "0000000000000000000000000000000000000000000000000000000000000abc";
        let amount = "00000000000000000000000000000000000000000000000000000000000003e8";
        let calldata = format!("a9059cbb{to_addr}{amount}");
        let result = decode_evm_calldata(&calldata, None, None);
        assert_eq!(result.calls.len(), 1);
        assert_eq!(result.calls[0].function_name, "transfer");
        assert_eq!(result.risk_level, RiskLevel::Safe);
    }

    #[test]
    fn unlimited_approve() {
        let spender = "000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let amount = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let calldata = format!("095ea7b3{spender}{amount}");
        let result = decode_evm_calldata(&calldata, None, None);
        assert_eq!(result.calls[0].function_name, "approve");
        assert!(result.calls[0]
            .risk_flags
            .contains(&"unlimited_approval".to_string()));
        assert_eq!(result.risk_level, RiskLevel::Suspicious);
    }

    #[test]
    fn set_approval_for_all_drainer() {
        let operator = "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let approved = "0000000000000000000000000000000000000000000000000000000000000001";
        let calldata = format!("a22cb465{operator}{approved}");
        let result = decode_evm_calldata(&calldata, None, None);
        assert_eq!(result.calls[0].function_name, "setApprovalForAll");
        assert!(result.calls[0]
            .risk_flags
            .contains(&"nft_drainer".to_string()));
    }

    #[test]
    fn permit_phishing() {
        let owner = "0000000000000000000000001111111111111111111111111111111111111111";
        let spender = "0000000000000000000000002222222222222222222222222222222222222222";
        let amount = "000000000000000000000000000000000000000000000000000000000000ffff";
        let calldata = format!("d505accf{owner}{spender}{amount}");
        let result = decode_evm_calldata(&calldata, None, None);
        assert_eq!(result.calls[0].function_name, "permit");
        assert!(result.calls[0]
            .risk_flags
            .contains(&"permit_phishing".to_string()));
    }

    #[test]
    fn transfer_to_attacker() {
        let target = "1111111111111111111111111111111111111111";
        let to_addr = "000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let amount = "0000000000000000000000000000000000000000000000000000000000000001";
        let calldata = format!("a9059cbb{to_addr}{amount}");
        let result = decode_evm_calldata(&calldata, None, Some(target));
        assert!(result.calls[0].target_mismatch);
        assert!(result.calls[0]
            .risk_flags
            .contains(&"target_mismatch".to_string()));
    }

    #[test]
    fn unknown_selector() {
        let result = decode_evm_calldata("deadbeef", None, None);
        assert_eq!(result.calls[0].function_name, "unknown");
        assert!(result.calls[0].effect.contains("Unknown selector"));
    }

    #[test]
    fn erc2612_permit_unlimited() {
        let typed_data = serde_json::json!({
            "primaryType": "Permit",
            "message": {
                "owner": "1111111111111111111111111111111111111111",
                "spender": "2222222222222222222222222222222222222222",
                "value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "nonce": "0",
                "deadline": "1234567890"
            }
        });
        let result = decode_eip712(&typed_data, None, None);
        assert_eq!(result.calls.len(), 1);
        assert_eq!(result.calls[0].function_name, "permit");
        assert!(result.calls[0]
            .risk_flags
            .contains(&"permit_phishing".to_string()));
        assert!(result.calls[0]
            .risk_flags
            .contains(&"unlimited_approval".to_string()));
        assert_eq!(result.risk_level, RiskLevel::Suspicious);
    }

    #[test]
    fn permit2_single_unlimited() {
        let typed_data = serde_json::json!({
            "primaryType": "PermitSingle",
            "message": {
                "owner": "1111111111111111111111111111111111111111",
                "spender": "2222222222222222222222222222222222222222",
                "amount": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sigDeadline": "9999999999"
            }
        });
        let result = decode_eip712(&typed_data, None, None);
        assert_eq!(result.calls[0].function_name, "PermitSingle");
        assert!(result.calls[0]
            .risk_flags
            .contains(&"permit2_phishing".to_string()));
        assert!(result.calls[0]
            .risk_flags
            .contains(&"unlimited_approval".to_string()));
    }

    #[test]
    fn permit2_batch_multi_token() {
        let typed_data = serde_json::json!({
            "primaryType": "PermitBatch",
            "message": {
                "owner": "1111111111111111111111111111111111111111",
                "spender": "2222222222222222222222222222222222222222",
                "amounts": ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffff", "ffff"]
            }
        });
        let result = decode_eip712(&typed_data, None, None);
        assert_eq!(result.calls[0].function_name, "PermitBatch");
        assert!(result.calls[0]
            .risk_flags
            .contains(&"permit2_phishing".to_string()));
        assert!(result.calls[0]
            .risk_flags
            .contains(&"unlimited_approval".to_string()));
    }

    #[test]
    fn eip712_target_mismatch() {
        let typed_data = serde_json::json!({
            "primaryType": "PermitSingle",
            "message": {
                "owner": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "spender": "2222222222222222222222222222222222222222",
                "amount": "ffff",
                "token": "0000000000000000000000000000000000000000",
                "sigDeadline": "123"
            }
        });
        let result = decode_eip712(
            &typed_data,
            None,
            Some("1111111111111111111111111111111111111111"),
        );
        assert!(result.calls[0].target_mismatch);
        assert_eq!(result.risk_level, RiskLevel::Dangerous);
    }

    #[test]
    fn tx_json_with_eth_value() {
        let tx = serde_json::json!({
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "value": "0x56bc75e2d63100000",
            "input": "095ea7b3000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000000000000000000000000000000000000000000000000000000000064"
        });
        let result = decode_tx_json(&tx, None, None);
        assert_eq!(result.calls.len(), 2);
        assert_eq!(result.calls[0].function_name, "value_transfer");
        assert_eq!(result.calls[1].function_name, "approve");
    }
}
