use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Curated per-rule content: beginner-friendly explanations.
///
/// **URL Policy:** Every `reference` URL in [`PrecedentEntry`] must be manually verified
/// as a real page for the correct incident before being committed. No URL may be
/// generated, guessed, or fabricated. URLs are validated at compile time by checking
/// they are non-empty and well-formed (start with `https://`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleContent {
    pub rule_id: String,
    pub display_name: String,
    pub what_this_is: String,
    pub why_dangerous: String,
    pub how_to_fix: String,
    pub precedents: Vec<PrecedentEntry>,
}

/// A precedent citation for a known-vulnerable pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrecedentEntry {
    pub name: String,
    pub reference: String,
    pub note: String,
}

/// Build content library keyed by rule_id.
pub fn content_library() -> BTreeMap<String, RuleContent> {
    let mut m = BTreeMap::new();
    for entry in rule_entries() {
        m.insert(entry.rule_id.clone(), entry);
    }
    m
}

fn rule_entries() -> Vec<RuleContent> {
    vec![
        RuleContent {
            rule_id: "authority_bypass".into(),
            display_name: "Authority Bypass".into(),
            what_this_is: "A function that can modify critical state without proper access control.".into(),
            why_dangerous:
                "An attacker can call this function directly, bypassing ownership or admin checks, \
                 and drain funds, pause the protocol, or corrupt state.".into(),
            how_to_fix:
                "Add an ownership check (e.g., require(msg.sender == owner)) or use a modifier \
                 like onlyOwner before any state-changing logic.".into(),
            precedents: vec![
                PrecedentEntry {
                    name: "Poly Network (2021)".into(),
                    reference: "https://medium.com/poly-network/the-root-cause-of-poly-network-being-hacked-e30cf27468f0".into(),
                    note: "Attacker abused the privileged EthCrossChainManager to replace keeper public keys via putCurEpochConPubKeyBytes, enabling arbitrary cross-chain withdrawals (~$610M).".into(),
                },
                PrecedentEntry {
                    name: "Wormhole Bridge (2022)".into(),
                    reference: "https://kudelskisecurity.com/research/quick-analysis-of-the-wormhole-attack".into(),
                    note: "Signature verification bypass on Solana VAA allowed minting 120k unbacked ETH ($326M). Kudelski Security technical analysis of the exploit.".into(),
                },
            ],
        },
        RuleContent {
            rule_id: "state_corruption".into(),
            display_name: "State Corruption".into(),
            what_this_is: "A function that writes to storage in a way that can be exploited to corrupt protocol state.".into(),
            why_dangerous:
                "Corrupted state can lead to incorrect balances, broken invariants, or loss of funds. \
                 The damage may be irreversible once committed on-chain.".into(),
            how_to_fix:
                "Validate all state transitions with explicit invariants. Use checks-effects-interactions \
                 pattern. Add reentrancy guards where external calls precede state writes.".into(),
            precedents: vec![
                PrecedentEntry {
                    name: "Parity Multisig Library Self-Destruct (2017)".into(),
                    reference: "https://medium.com/paritytech/a-postmortem-on-the-parity-multi-sig-library-self-destruct-63daca3a4cf7".into(),
                    note: "Delegatecall to shared library contract allowed unintended self-destruct, permanently freezing $150M in ETH across 587 wallets.".into(),
                },
            ],
        },
        RuleContent {
            rule_id: "readonly_reentrancy".into(),
            display_name: "Read-Only Reentrancy".into(),
            what_this_is: "A view/pure function that reads state that can be manipulated during a reentrant call.".into(),
            why_dangerous:
                "Protocols relying on this function for pricing, accounting, or access decisions \
                 will read corrupted state mid-reentrancy, leading to incorrect behavior.".into(),
            how_to_fix:
                "Use a reentrancy lock on state-modifying functions that affect the data read by \
                 view functions. Alternatively, use a snapshot pattern (e.g., cached values in storage).".into(),
            precedents: vec![
                PrecedentEntry {
                    name: "Curve/Vyper Reentrancy (2023)".into(),
                    reference: "https://hackmd.io/@LlamaRisk/BJzSKHNjn".into(),
                    note: "Vyper compiler bug (CVE-2023-39363) caused reentrancy guards to malfunction across Curve pools, draining $70M. Cross-function reentrancy on view functions was the attack vector.".into(),
                },
                PrecedentEntry {
                    name: "Vyper Compiler Advisory".into(),
                    reference: "https://github.com/vyperlang/vyper/security/advisories/GHSA-5824-cm3x-3c38".into(),
                    note: "CVE-2023-39363: Incorrectly allocated named re-entrancy locks in Vyper 0.2.15, 0.2.16, and 0.3.0.".into(),
                },
            ],
        },
        RuleContent {
            rule_id: "price_manipulation".into(),
            display_name: "Price Manipulation".into(),
            what_this_is: "A function that derives pricing from on-chain data that can be manipulated.".into(),
            why_dangerous:
                "An attacker can use flash loans or sandwich attacks to manipulate the oracle price, \
                 extracting more value than intended during swaps or liquidations.".into(),
            how_to_fix:
                "Use time-weighted average prices (TWAP), multiple oracle sources, or \
                 circuit breakers that halt trading when price moves beyond a threshold.".into(),
            precedents: vec![
                PrecedentEntry {
                    name: "Mango Markets (2022)".into(),
                    reference: "https://www.chainalysis.com/blog/oracle-manipulation-attacks-rising/".into(),
                    note: "Attacker inflated MNGO token price via wash trading on Mango's own order book, then used inflated collateral to borrow all available funds ($114M). Chainalysis analysis of the oracle manipulation pattern.".into(),
                },
            ],
        },
        RuleContent {
            rule_id: "oracle_manipulation".into(),
            display_name: "Oracle Manipulation".into(),
            what_this_is: "A function that trusts a single on-chain price feed without validation.".into(),
            why_dangerous:
                "A compromised or manipulated oracle can feed incorrect prices to the protocol, \
                 enabling theft of funds or insolvency.".into(),
            how_to_fix:
                "Use a robust oracle (e.g., Chainlink with deviation checks), implement \
                 price freshness checks, and add circuit breakers for anomalous prices.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "access_control".into(),
            display_name: "Access Control".into(),
            what_this_is: "A privileged operation that lacks proper authorization checks.".into(),
            why_dangerous:
                "Without access control, any address can execute privileged operations like \
                 minting tokens, pausing the protocol, or upgrading contracts.".into(),
            how_to_fix:
                "Implement role-based access control (RBAC), use multi-sig for admin operations, \
                 and restrict sensitive functions with appropriate modifiers.".into(),
            precedents: vec![
                PrecedentEntry {
                    name: "Parity Multisig (2017)".into(),
                    reference: "https://www.openzeppelin.com/news/on-the-parity-wallet-multisig-hack-405a8c12e8f7".into(),
                    note: "Unprotected initWallet function on Parity multisig library contract allowed attacker to claim ownership of 587 wallets, freezing $150M in ETH.".into(),
                },
            ],
        },
        RuleContent {
            rule_id: "unchecked_external_call".into(),
            display_name: "Unchecked External Call".into(),
            what_this_is: "The return value of an external call is not checked, ignoring potential failures.".into(),
            why_dangerous:
                "Silent failures can leave the protocol in an inconsistent state. For example, \
                 a failed token transfer will not revert, but the protocol will act as if it succeeded.".into(),
            how_to_fix:
                "Always check return values of low-level calls (call, send, transfer). Use \
                 SafeERC20 or the Checked math pattern. Prefer high-level calls that revert on failure.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "unchecked_owner".into(),
            display_name: "Unchecked Account Owner".into(),
            what_this_is: "A token account or PDA that should be verified as owned by the expected program but is not checked.".into(),
            why_dangerous:
                "An attacker can pass a fake account owned by a different program, \
                 spoofing identity and stealing funds or corrupting state.".into(),
            how_to_fix:
                "Always verify account ownership with assert!(account.owner == expected_owner) \
                 or use Anchor's has_one constraint.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "type_cosplay".into(),
            display_name: "Type Cosplay".into(),
            what_this_is: "An account deserialization that does not verify the account type/discriminator.".into(),
            why_dangerous:
                "An attacker can deserialize a different account type (e.g., a TokenAccount \
                 where a VaultAccount is expected), bypassing type-specific security checks.".into(),
            how_to_fix:
                "Verify account discriminators after deserialization. Use Anchor's #[account] \
                 attribute which enforces discriminator checks automatically.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "unvalidated_cpi".into(),
            display_name: "Unvalidated CPI".into(),
            what_this_is: "A cross-program invocation (CPI) that does not validate the target program or accounts.".into(),
            why_dangerous:
                "An attacker can redirect CPI calls to a malicious program, which can \
                 return fake success signals or manipulate state.".into(),
            how_to_fix:
                "Validate all CPI targets against known program IDs. Use Anchor's \
                 Program<'info, T> type which enforces program ID checks.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "missing_signer".into(),
            display_name: "Missing Signer".into(),
            what_this_is: "A privileged Solana instruction that does not require a signer.".into(),
            why_dangerous:
                "Without a required signer, anyone can invoke this instruction, \
                 potentially draining funds or modifying protected state.".into(),
            how_to_fix:
                "Add the account to the instruction's signer constraints. In Anchor, \
                 use #[account(constraint = account.is_signer)] or Seeds constraint.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "missing_owner".into(),
            display_name: "Missing Owner Check".into(),
            what_this_is: "A Solana account modification that does not verify the owner of the account being modified.".into(),
            why_dangerous:
                "An attacker can pass an account owned by a different program, \
                 and the instruction will modify it, leading to cross-program state corruption.".into(),
            how_to_fix:
                "Assert account ownership: assert!(account.owner == ctx.program_id). \
                 In Anchor, use the has_one constraint on the account.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "missing_access_control".into(),
            display_name: "Missing Access Control".into(),
            what_this_is: "A function that modifies state without verifying caller authorization.".into(),
            why_dangerous:
                "Any address can call this function to modify state that should be restricted, \
                 potentially causing privilege escalation or fund theft.".into(),
            how_to_fix:
                "Add authorization checks (owner, signer, role-based) before state modifications. \
                 Use OpenZeppelin's Ownable or AccessControl for standardized patterns.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "access_control_bypass".into(),
            display_name: "Access Control Bypass".into(),
            what_this_is: "A code path that circumvents an existing access control mechanism.".into(),
            why_dangerous:
                "Even though access control exists on the main path, the bypass allows \
                 unauthorized callers to reach the same privileged operation.".into(),
            how_to_fix:
                "Ensure ALL code paths to privileged operations go through the same \
                 access control check. Use a single modifier or guard function.".into(),
            precedents: vec![],
        },
        RuleContent {
            rule_id: "storage_collision".into(),
            display_name: "Storage Collision".into(),
            what_this_is: "A proxy upgrade pattern where the new implementation's storage layout overlaps with the proxy.".into(),
            why_dangerous:
                "Storage variables in the proxy and implementation will overwrite each other, \
                 corrupting critical state like balances, ownership, and configuration.".into(),
            how_to_fix:
                "Use unstructured storage (EIP-1967 slots) or the diamond pattern (EIP-2535). \
                 Always run storage layout verification before deploying upgrades.".into(),
            precedents: vec![
                PrecedentEntry {
                    name: "EIP-1967 Storage Slots (2018)".into(),
                    reference: "https://eips.ethereum.org/EIPS/eip-1967".into(),
                    note: "Standardized random storage slots for proxy implementations specifically to prevent storage collisions between proxy and logic contracts.".into(),
                },
            ],
        },
    ]
}

/// Look up content for a rule_id, or return the fallback.
pub fn lookup_rule(rule_id: &str) -> RuleContent {
    let lib = content_library();
    lib.get(rule_id)
        .cloned()
        .unwrap_or_else(|| fallback_content(rule_id))
}

fn fallback_content(rule_id: &str) -> RuleContent {
    let display = prettify_rule_id(rule_id);
    RuleContent {
        rule_id: "unknown".into(),
        display_name: display,
        what_this_is: "A security finding flagged by the analysis engine.".into(),
        why_dangerous: "This finding requires manual review to determine its severity and impact. \
             The automated analysis flagged a potential pattern that may indicate a vulnerability."
            .into(),
        how_to_fix: "Review the flagged code location manually. Consult the security audit report \
             for detailed analysis and recommended remediation."
            .into(),
        precedents: vec![],
    }
}

/// Convert a snake_case rule_id to a human-readable display name.
fn prettify_rule_id(rule_id: &str) -> String {
    if rule_id.is_empty() || rule_id == "unknown" {
        return "Unknown Rule".into();
    }
    rule_id
        .replace('_', " ")
        .split(' ')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_known_rules_have_entries() {
        let known_rules = [
            "authority_bypass",
            "state_corruption",
            "readonly_reentrancy",
            "price_manipulation",
            "oracle_manipulation",
            "access_control",
            "unchecked_external_call",
            "unchecked_owner",
            "type_cosplay",
            "unvalidated_cpi",
            "missing_signer",
            "missing_owner",
            "missing_access_control",
            "access_control_bypass",
            "storage_collision",
        ];
        for rule_id in &known_rules {
            let content = lookup_rule(rule_id);
            assert_eq!(
                content.rule_id.as_str(),
                *rule_id,
                "Entry for {rule_id} has wrong rule_id"
            );
            assert!(
                !content.display_name.is_empty(),
                "Entry for {rule_id} has empty display_name"
            );
            assert!(
                !content.what_this_is.is_empty(),
                "Entry for {rule_id} has empty what_this_is"
            );
        }
    }

    #[test]
    fn unknown_rule_returns_fallback_with_pretty_name() {
        let content = lookup_rule("totally_unknown_rule_xyz");
        assert_eq!(content.rule_id, "unknown");
        assert_eq!(content.display_name, "Totally Unknown Rule Xyz");
        assert!(!content.why_dangerous.is_empty());
    }

    #[test]
    fn content_library_is_deterministic() {
        let lib1 = content_library();
        let lib2 = content_library();
        let keys1: Vec<_> = lib1.keys().collect();
        let keys2: Vec<_> = lib2.keys().collect();
        assert_eq!(keys1, keys2);
    }

    #[test]
    fn authority_bypass_has_precedents() {
        let content = lookup_rule("authority_bypass");
        assert!(!content.precedents.is_empty());
    }

    /// CI check: every precedent URL must be non-empty and start with https://.
    /// URLs must be manually verified as real pages for the correct incident.
    /// No URL may be generated, guessed, or fabricated.
    #[test]
    fn all_precedent_urls_are_well_formed() {
        let lib = content_library();
        for (rule_id, content) in &lib {
            for prec in &content.precedents {
                assert!(
                    prec.reference.starts_with("https://"),
                    "Precedent '{}' under rule '{}' has invalid URL (must start with https://): {}",
                    prec.name,
                    rule_id,
                    prec.reference,
                );
                assert!(
                    !prec.reference.is_empty(),
                    "Precedent '{}' under rule '{}' has empty URL",
                    prec.name,
                    rule_id,
                );
            }
        }
    }
}
