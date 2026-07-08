use crate::analysis::authority_model::*;
/// Authority Analyzer — deterministic authority detection and classification.
///
/// Replaces substring-based authority detection with structural analysis.
/// Distinguishes genuine authorization checks from generic invariant checks.
///
/// # Rules
///
/// 1. Deterministic: same inputs → same output
/// 2. No AI, no heuristics, no probabilistic reasoning
/// 3. No symbolic execution or path-sensitive analysis
/// 4. All outputs sorted for deterministic serialization
use digger_parser::model::*;

/// Analyze authority relationships in a program.
///
/// Returns a complete AuthorityGraph with per-function authority analysis.
pub fn analyze_authority(program: &RawProgram) -> AuthorityGraph {
    let mut relations = vec![];
    let mut enforced_functions = vec![];
    let mut missing_authority = vec![];
    let mut invariant_only = vec![];
    let mut propagation_chains = vec![];

    // Build modifier → authority source mapping
    let modifier_authority = build_modifier_authority_map(program);

    for func in &program.functions {
        let relation = analyze_function_authority(func, program, &modifier_authority);
        let func_name = func.name.clone();

        // Track propagation chains from modifiers
        for modifier in &relation.modifiers {
            if let Some(source) = modifier_authority.get(modifier) {
                if source != &AuthoritySource::Unknown {
                    propagation_chains.push((modifier.clone(), func_name.clone()));
                }
            }
        }

        if relation.enforced && !relation.is_invariant {
            enforced_functions.push(func_name.clone());
        } else if relation.is_invariant {
            invariant_only.push(func_name.clone());
        } else {
            missing_authority.push(func_name.clone());
        }

        relations.push(relation);
    }

    // Sort for deterministic output
    relations.sort_by(|a, b| a.function.cmp(&b.function));
    enforced_functions.sort();
    missing_authority.sort();
    invariant_only.sort();
    propagation_chains.sort();

    let total = relations.len();
    let enforced_count = enforced_functions.len();
    let missing_count = missing_authority.len();
    let invariant_count = invariant_only.len();
    let enforcement_rate = if total > 0 {
        enforced_count as f64 / total as f64
    } else {
        0.0
    };

    AuthorityGraph {
        relations,
        enforced_functions,
        missing_authority,
        invariant_only,
        propagation_chains,
        summary: AuthoritySummary {
            total_functions: total,
            enforced_count,
            missing_count,
            invariant_count,
            enforcement_rate,
        },
    }
}

/// Analyze authority for a single function.
fn analyze_function_authority(
    func: &RawFunction,
    program: &RawProgram,
    modifier_authority: &std::collections::BTreeMap<String, AuthoritySource>,
) -> AuthorityRelation {
    let body = &func.body;

    // Extract modifiers from metadata
    let modifiers = program
        .metadata
        .function_details
        .get(&func.name)
        .map(|m| m.modifiers.clone())
        .unwrap_or_default();

    // Check if any modifier provides authority
    let modifier_source = modifiers
        .iter()
        .filter_map(|m| modifier_authority.get(m))
        .find(|s| **s != AuthoritySource::Unknown)
        .cloned();

    // Analyze the function body for authority patterns
    let body_analysis = analyze_body_authority(body);

    // Determine the final authority relation
    let (source, check_type, enforced, is_invariant) = match (modifier_source, body_analysis) {
        // Modifier provides genuine authority
        (Some(mod_source), _) => {
            let check = classify_source_to_check(&mod_source);
            (mod_source, check, true, false)
        }
        // Body has genuine authority check
        (None, Some((src, check, inv))) => (src, check, !inv, inv),
        // No authority found
        (None, None) => (
            AuthoritySource::Unknown,
            AuthorityCheckType::Missing,
            false,
            false,
        ),
    };

    AuthorityRelation {
        function: func.name.clone(),
        source,
        check_type,
        enforced,
        is_invariant,
        modifiers,
    }
}

/// Analyze a function body for authority patterns.
///
/// Returns (source, check_type, is_invariant) if a check is found.
fn analyze_body_authority(body: &str) -> Option<(AuthoritySource, AuthorityCheckType, bool)> {
    // Check for Solana/Anchor authority patterns first (most specific)
    if let Some(result) = check_solana_authority(body) {
        return Some(result);
    }

    // Check for Solidity authority patterns
    if let Some(result) = check_solidity_authority(body) {
        return Some(result);
    }

    // Check for generic require/assert — these are invariants, not authority
    if has_require_or_assert(body) {
        return Some((
            AuthoritySource::Unknown,
            AuthorityCheckType::Invariant,
            true, // is_invariant
        ));
    }

    None
}

/// Check for Solana/Anchor authority patterns.
fn check_solana_authority(body: &str) -> Option<(AuthoritySource, AuthorityCheckType, bool)> {
    // Signer checks: specific patterns to avoid false positives
    // "Signer" alone matches comments and variable names like "UnauthorizedSigner"
    // Valid patterns: Signer<'info>, is_signer(), Signer::from_account_info
    if body.contains("Signer<")
        || body.contains("is_signer()")
        || body.contains("Signer::from_account_info")
    {
        return Some((
            AuthoritySource::Signer,
            AuthorityCheckType::SignerValidation,
            false,
        ));
    }

    // PDA authority: has_one = authority, has_one = admin
    if body.contains("has_one") {
        return Some((
            AuthoritySource::PdaAuthority,
            AuthorityCheckType::PdaValidation,
            false,
        ));
    }

    // Constraint-based authority: #[account(constraint = ...)]
    if body.contains("constraint") && (body.contains("authority") || body.contains("admin")) {
        return Some((
            AuthoritySource::PdaAuthority,
            AuthorityCheckType::PdaValidation,
            false,
        ));
    }

    None
}

/// Check for Solidity authority patterns.
fn check_solidity_authority(body: &str) -> Option<(AuthoritySource, AuthorityCheckType, bool)> {
    // msg.sender patterns
    if body.contains("msg.sender") {
        // Ownership check: msg.sender == owner / owner == msg.sender
        if body.contains("msg.sender == owner")
            || body.contains("owner == msg.sender")
            || body.contains("msg.sender == _owner")
            || body.contains("_owner == msg.sender")
        {
            return Some((
                AuthoritySource::MsgSender,
                AuthorityCheckType::Ownership,
                false,
            ));
        }

        // Admin check: msg.sender == admin
        if body.contains("msg.sender == admin") || body.contains("admin == msg.sender") {
            return Some((
                AuthoritySource::MsgSender,
                AuthorityCheckType::Ownership,
                false,
            ));
        }

        // Role-based: hasRole(ROLE, msg.sender) or role[msg.sender] or signers[msg.sender]
        if body.contains("hasRole")
            || body.contains("roles[msg.sender]")
            || body.contains("role[msg.sender]")
            || body.contains("signers[msg.sender]")
            || body.contains("whitelist[msg.sender]")
            || body.contains("isWhitelisted[msg.sender]")
        {
            return Some((
                AuthoritySource::RoleMapping,
                AuthorityCheckType::Role,
                false,
            ));
        }

        // Generic msg.sender comparison — still authority but less specific
        if (body.contains("require") || body.contains("assert"))
            && body.contains("msg.sender")
            && (body.contains("==") || body.contains("!="))
        {
            return Some((
                AuthoritySource::MsgSender,
                AuthorityCheckType::Ownership,
                false,
            ));
        }
    }

    // tx.origin patterns
    if body.contains("tx.origin") {
        return Some((
            AuthoritySource::TxOrigin,
            AuthorityCheckType::Ownership,
            false,
        ));
    }

    // Multisig patterns — require both "multisig" AND "threshold" to avoid false positives
    // e.g., require(threshold >= min) alone is NOT multisig
    if body.contains("multisig")
        && body.contains("threshold")
        && (body.contains("require") || body.contains("assert"))
    {
        return Some((
            AuthoritySource::Multisig,
            AuthorityCheckType::MultisigValidation,
            false,
        ));
    }

    // Governance patterns — require context to avoid false positives
    // "proposal" alone is too broad (e.g., require(proposals[id]) is a state guard)
    // Real governance authority: require(msg.sender == governor), timelock checks, etc.
    if (body.contains("governance") || body.contains("timelock"))
        && (body.contains("require") || body.contains("assert"))
    {
        return Some((
            AuthoritySource::Governance,
            AuthorityCheckType::GovernanceValidation,
            false,
        ));
    }
    // "proposal" + "executed" pattern (governance proposal execution)
    // Must co-occur in a require/assert context
    if body.contains("proposal")
        && body.contains("executed")
        && (body.contains("require") || body.contains("assert"))
        && !body.contains("proposalExecuted")
    // exclude boolean variable names
    {
        return Some((
            AuthoritySource::Governance,
            AuthorityCheckType::GovernanceValidation,
            false,
        ));
    }

    None
}

/// Check if a body has require/assert but no authority pattern.
fn has_require_or_assert(body: &str) -> bool {
    body.contains("require") || body.contains("assert")
}

/// Classify an AuthoritySource to its corresponding AuthorityCheckType.
fn classify_source_to_check(source: &AuthoritySource) -> AuthorityCheckType {
    match source {
        AuthoritySource::MsgSender => AuthorityCheckType::Ownership,
        AuthoritySource::TxOrigin => AuthorityCheckType::Ownership,
        AuthoritySource::Signer => AuthorityCheckType::SignerValidation,
        AuthoritySource::PdaAuthority => AuthorityCheckType::PdaValidation,
        AuthoritySource::OwnerVariable => AuthorityCheckType::Ownership,
        AuthoritySource::RoleMapping => AuthorityCheckType::Role,
        AuthoritySource::Multisig => AuthorityCheckType::MultisigValidation,
        AuthoritySource::Governance => AuthorityCheckType::GovernanceValidation,
        AuthoritySource::Unknown => AuthorityCheckType::Unknown,
    }
}

/// Build a mapping of modifier names to their authority sources.
///
/// Uses the canonical `analyze_body_authority()` — the same analysis
/// used for function bodies. This ensures modifier and function bodies
/// produce consistent authority classification for identical source code.
fn build_modifier_authority_map(
    program: &RawProgram,
) -> std::collections::BTreeMap<String, AuthoritySource> {
    let mut map = std::collections::BTreeMap::new();

    // Build inheritance map: contract_name -> set of ancestor names (transitive)
    let inheritance_map = build_inheritance_map(program);

    // Find modifier definitions in metadata
    for (func_name, func_meta) in &program.metadata.function_details {
        if func_meta.fn_type == "modifier" {
            // Find the modifier's body
            if let Some(func) = program.functions.iter().find(|f| &f.name == func_name) {
                // Use the canonical body analyzer — same as function bodies
                let source = match analyze_body_authority(&func.body) {
                    // Genuine authority: extract the source
                    Some((src, _check_type, false)) => src,
                    // Invariant or missing: try 1-level call follow (scoped to contract + inheritance)
                    _ => follow_modifier_call_chain(func, program, &inheritance_map),
                };
                map.insert(func_name.clone(), source);
            }
        }
    }

    map
}

/// Build a map of contract_name -> all ancestor names (transitive closure of inheritance).
fn build_inheritance_map(
    program: &RawProgram,
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    let mut direct: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for contract in &program.metadata.contracts {
        direct.insert(contract.name.clone(), contract.inheritance.clone());
    }

    let mut result: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();

    // Transitive closure: walk each contract's inheritance chain
    for name in direct.keys() {
        let mut ancestors = std::collections::BTreeSet::new();
        let mut stack: Vec<String> = direct.get(name).cloned().unwrap_or_default();
        while let Some(base) = stack.pop() {
            if ancestors.insert(base.clone()) {
                if let Some(grandparents) = direct.get(&base) {
                    stack.extend(grandparents.iter().cloned());
                }
            }
        }
        result.insert(name.clone(), ancestors);
    }

    result
}

/// When a modifier body delegates to a helper function (e.g. `_ownerOnly()` which
/// contains `require(msg.sender == _owner)`), follow the call 1 level to find
/// the authority check. Resolution is scoped to the modifier's own contract and
/// its transitive inheritance chain — NOT a global first-match.
fn follow_modifier_call_chain(
    modifier_func: &RawFunction,
    program: &RawProgram,
    inheritance_map: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
) -> AuthoritySource {
    let body = &modifier_func.body;
    let modifier_contract = &modifier_func.contract;

    // Build the set of contracts to search: self + transitive ancestors
    let mut search_contracts: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    search_contracts.insert(modifier_contract.clone());
    if let Some(ancestors) = inheritance_map.get(modifier_contract) {
        search_contracts.extend(ancestors.iter().cloned());
    }

    // Extract function call names from the modifier body.
    // Look for patterns like `_ownerOnly()` or `someFunc(arg)`.
    let candidate_calls: Vec<String> = body
        .split('(')
        .filter_map(|segment| {
            // The identifier before '(' is the callee — walk backwards through
            // the segment to find the identifier start.
            let trimmed = segment.trim_end();
            if trimmed.is_empty() {
                return None;
            }
            // Find the last identifier-like token
            let name: String = trimmed
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if name.is_empty() || name == "_" {
                return None;
            }
            // Skip known non-function tokens
            if matches!(
                name.as_str(),
                "require" | "assert" | "if" | "else" | "return" | "emit"
            ) {
                return None;
            }
            Some(name)
        })
        .collect();

    // Try each candidate — look it up within the scoped contract set first,
    // then fall back to library/free functions (empty contract name).
    for call_name in &candidate_calls {
        // Priority 1: same contract or ancestor in inheritance chain
        if let Some(callee) = program
            .functions
            .iter()
            .find(|f| &f.name == call_name && search_contracts.contains(&f.contract))
        {
            if let Some((src, _check_type, false)) = analyze_body_authority(&callee.body) {
                return src;
            }
        }
        // Priority 2: library/free function (empty contract name, only if not found in chain)
        if let Some(callee) = program
            .functions
            .iter()
            .find(|f| &f.name == call_name && f.contract.is_empty())
        {
            if let Some((src, _check_type, false)) = analyze_body_authority(&callee.body) {
                return src;
            }
        }
    }

    AuthoritySource::Unknown
}
