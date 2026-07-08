use crate::types::*;

pub fn parse_op_program(source: &str) -> OpProgram {
    let mut handlers = Vec::new();
    for (line_no, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if is_handler_start(trimmed) {
            if let Some(handler) = extract_handler(trimmed, line_no, source) {
                handlers.push(handler);
            }
        }
    }
    handlers.sort_by(|a, b| a.name.cmp(&b.name));
    let source_hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        source.hash(&mut h);
        format!("{:016x}", h.finish())
    };
    OpProgram {
        handlers,
        source_hash,
    }
}

fn is_handler_start(line: &str) -> bool {
    line.starts_with("export ")
        || line.starts_with("async ")
        || (line.contains("function ") && !line.starts_with("//"))
        || (line.contains("=> {") && line.contains("("))
}

fn extract_handler(header: &str, _line_no: usize, source: &str) -> Option<Handler> {
    let name = extract_function_name(header)?;
    let params = extract_params(header);
    let body_start = source
        .find(&format!("function {}", name))
        .or_else(|| source.find(&format!("{}(", name)))
        .and_then(|p| {
            let after = &source[p..];
            after.find('{').map(|b| p + b + 1)
        })?;
    let body_end = find_matching_brace(source, body_start);
    let body = &source[body_start..body_end];
    let stripped = strip_comments_and_strings(body);

    let mut external_reads = Vec::new();
    let mut verification_checks = Vec::new();
    let mut privileged_sinks = Vec::new();
    let mut allowlist_checks = Vec::new();
    let mut safety_gate_checks = Vec::new();
    let mut permissive_returns = Vec::new();
    let mut threshold_adjustments = Vec::new();
    let mut init_guard_checks = Vec::new();

    let mut seen_read_vars = std::collections::BTreeSet::new();
    for (trigger, source_desc, category) in &[
        ("get_price", "external_price_feed", ReadCategory::ValueFeed),
        ("get_feed", "external_price_feed", ReadCategory::ValueFeed),
        ("hermes", "hermes_attestation", ReadCategory::ValueFeed),
        ("pyth", "pyth_oracle", ReadCategory::ValueFeed),
        ("wormhole", "wormhole_vaa", ReadCategory::ValueFeed),
        ("oracle", "oracle_source", ReadCategory::ValueFeed),
        (
            "get_account_info",
            "rpc_account_read",
            ReadCategory::ValueFeed,
        ),
        (
            "fetchconfig",
            "offchain_config_read",
            ReadCategory::RoutingConfig,
        ),
        (
            "fetch_config",
            "offchain_config_read",
            ReadCategory::RoutingConfig,
        ),
        (
            "getconfig",
            "offchain_config_read",
            ReadCategory::RoutingConfig,
        ),
        (
            "get_config",
            "offchain_config_read",
            ReadCategory::RoutingConfig,
        ),
        ("db.query", "database_read", ReadCategory::RoutingConfig),
        ("db.get", "database_read", ReadCategory::RoutingConfig),
        ("process.env", "env_var_read", ReadCategory::RoutingConfig),
        ("req.body", "request_param", ReadCategory::RoutingConfig),
        ("req.query", "request_param", ReadCategory::RoutingConfig),
        ("req.params", "request_param", ReadCategory::RoutingConfig),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            if let Some(var) = extract_var_from_span(body, absolute) {
                if seen_read_vars.insert(var.clone()) {
                    let line = byte_offset_to_line(body, absolute);
                    external_reads.push(DataRead {
                        variable: var,
                        source: source_desc.to_string(),
                        category: category.clone(),
                        line,
                    });
                }
            }
            start = absolute + trigger.len();
        }
    }

    let mut seen_check_keys = std::collections::BTreeSet::new();
    for (trigger, kind) in &[
        ("verify", "signature_verification"),
        ("check_signature", "signature_verification"),
        ("validate_vaa", "vaa_validation"),
        ("assert_attestation", "attestation_validation"),
        ("verify_attestation", "attestation_validation"),
        ("check_owner", "ownership_verification"),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            let target = extract_verification_target_from_span(body, absolute, trigger);
            let key = format!("{}:{}", kind, target);
            if seen_check_keys.insert(key) {
                verification_checks.push(VerificationCheck {
                    kind: kind.to_string(),
                    target,
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Allowlist / owner-check guards
    let mut seen_al_keys = std::collections::BTreeSet::new();
    for (trigger, kind) in &[
        (".includes", "includes_guard"),
        (".contains", "contains_guard"),
        ("allowlist", "allowlist_check"),
        ("whitelist", "allowlist_check"),
        ("== expected", "equality_guard"),
        ("owner ==", "owner_guard"),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            let target = extract_verification_target_from_span(body, absolute, trigger);
            let key = format!("{}:{}", kind, target);
            if seen_al_keys.insert(key) {
                allowlist_checks.push(AllowlistCheck {
                    kind: kind.to_string(),
                    target,
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Safety-gate state reads — boolean state checks (isReady, initialized, etc.)
    let mut seen_sg_keys = std::collections::BTreeSet::new();
    for (trigger, kind) in &[
        ("initialized", "initialization"),
        ("isready", "readiness"),
        ("isactive", "health"),
        ("ishealthy", "health"),
        ("lastupdate", "freshness"),
        ("ispaused", "operational_state"),
        ("isrunning", "operational_state"),
        ("isoperational", "operational_state"),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            // Extract the full identifier around the trigger match
            let var = extract_identifier_at_offset(body, absolute, trigger);
            let key = format!("{}:{}", kind, var);
            if seen_sg_keys.insert(key) {
                safety_gate_checks.push(SafetyGateCheck {
                    variable: var,
                    kind: kind.to_string(),
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Permissive default returns — "return true" / "return false" / "return 0"
    let mut seen_pr_lines = std::collections::BTreeSet::new();
    let lower_full = stripped.to_lowercase();
    for (trigger, value) in &[
        ("return true", "true"),
        ("return false", "false"),
        ("return 0", "0"),
        ("return !", "negated"),
    ] {
        let mut start = 0;
        while let Some(pos) = lower_full[start..].find(trigger) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            if seen_pr_lines.insert(line) {
                permissive_returns.push(PermissiveReturn {
                    value: value.to_string(),
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Failover source reads — REAL FALLBACK-TO-SOURCE SHAPE required:
    // catch(...) counts ONLY when the catch arg/body contains a data-source call.
    // ?? counts ONLY when the RHS is a source call, not a literal default.
    // Variable = LHS binding; empty variable = reject (no tracked failover).
    const SOURCE_CALL_VOCAB: &[&str] = &[
        "get_price",
        "get_feed",
        "hermes",
        "pyth",
        "wormhole",
        "oracle",
        "get_account_info",
        "fetchconfig",
        "fetch_config",
        "getconfig",
        "get_config",
        "db.query",
        "db.get",
        "getcachedprice",
        "getcoingeckoprice",
        "getdexscreenerprice",
        "getprice",
        "getfeed",
        "getaccountinfo",
    ];

    let mut seen_fo_keys = std::collections::BTreeSet::new();
    for (trigger, source_desc) in &[
        ("catch(", "error_catch_fallback"),
        ("?? ", "nullish_coalesce_fallback"),
        ("fallback", "explicit_fallback"),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            let var = extract_var_from_span(body, absolute).unwrap_or_default();

            // Reject empty-variable reads (no const/let/var binding)
            if var.is_empty() {
                start = absolute + trigger.len();
                continue;
            }

            // Verify the fallback actually targets a second source call:
            // search the text AFTER the trigger match (to end of statement)
            // for any source-call vocabulary token.
            let after_text = &lower[absolute + trigger.len()..];
            let statement_end = after_text.find(';').unwrap_or(after_text.len().min(200));
            let search_zone = &after_text[..statement_end];
            let has_source_call = SOURCE_CALL_VOCAB.iter().any(|sc| search_zone.contains(sc));

            if !has_source_call {
                start = absolute + trigger.len();
                continue;
            }

            let key = format!("{}:{}", source_desc, absolute);
            if seen_fo_keys.insert(key) {
                external_reads.push(DataRead {
                    variable: var,
                    source: source_desc.to_string(),
                    category: ReadCategory::FailoverSource,
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Threshold adjustments — tightened: only target-bearing triggers,
    // dropped name-only triggers (threshold, stricter) that cause over-suppression.
    // For prefix-call triggers, target = function argument via extract_verification_target_from_span.
    // For method-clamp triggers (.min/.max), target = receiver (walk left from dot).
    let mut seen_ta_keys = std::collections::BTreeSet::new();
    for (trigger, kind) in &[
        ("tighten(", "threshold_tighten"),
        ("re_validat(", "re_validation"),
        ("cross_check(", "cross_validation"),
        ("recheck(", "re_validation"),
        (".min(", "threshold_clamp"),
        (".max(", "threshold_clamp"),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            // Method-clamp: extract receiver (walk left from dot position)
            // Prefix-call: extract function argument — use trigger WITHOUT
            // trailing `(` so extract_verification_target_from_span can find the parens.
            let var = if trigger.starts_with('.') {
                extract_receiver_from_method(body, absolute)
            } else {
                let bare = &trigger[..trigger.len() - 1];
                extract_verification_target_from_span(body, absolute, bare)
            };
            let key = format!("{}:{}", kind, var);
            if seen_ta_keys.insert(key) {
                threshold_adjustments.push(ThresholdAdjustment {
                    kind: kind.to_string(),
                    target: var,
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Init-guard checks — dedicated FOB suppressor (NOT borrowed from verify/allowlist).
    // require() / assert() / if (!var) patterns → extract the guarded variable.
    let mut seen_ig_keys = std::collections::BTreeSet::new();
    for (trigger, kind) in &[("require(", "require_guard"), ("assert(", "assert_guard")] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            let var = {
                let bare = &trigger[..trigger.len() - 1];
                extract_verification_target_from_span(body, absolute, bare)
            };
            let key = format!("{}:{}", kind, var);
            if seen_ig_keys.insert(key) {
                init_guard_checks.push(InitGuardCheck {
                    variable: var,
                    kind: kind.to_string(),
                    line,
                });
            }
            start = absolute + trigger.len();
        }
    }

    // Privileged sinks — dedup by call-site identity (offset), not kind
    let mut seen_sink_keys = std::collections::BTreeSet::new();
    for (trigger, kind) in &[
        ("token::transfer", "token_transfer"),
        ("system_program::transfer", "token_transfer"),
        (".transfer(", "token_transfer"),
        ("createTransferInstruction", "token_transfer"),
        ("sendtransaction", "transaction_submission"),
        ("invoke(", "cpi_call"),
        ("invoke_signed(", "cpi_call"),
        (".call(", "cpi_call"),
        ("program.methods.", "cpi_call"),
        (".write(", "state_write"),
        (".mut(", "state_write"),
    ] {
        let lower = stripped.to_lowercase();
        let needle = trigger.to_lowercase();
        let mut start = 0;
        while let Some(pos) = lower[start..].find(&needle) {
            let absolute = start + pos;
            let line = byte_offset_to_line(body, absolute);
            let key = format!("{}:{}", kind, absolute);
            let is_new = seen_sink_keys.insert(key);
            if is_new {
                // Check if any external-read variable appears in the sink's call args
                let sink_arg_text = extract_sink_arg_text(body, absolute);
                let target_var = external_reads
                    .iter()
                    .filter(|r| r.category == ReadCategory::RoutingConfig)
                    .find_map(|r| {
                        if sink_arg_text.contains(&r.variable) {
                            Some(r.variable.clone())
                        } else {
                            None
                        }
                    });
                privileged_sinks.push(PrivilegedSink {
                    kind: kind.to_string(),
                    line,
                    target_variable: target_var,
                });
            }
            start = absolute + trigger.len();
        }
    }

    Some(Handler {
        name,
        params,
        external_reads,
        verification_checks,
        allowlist_checks,
        safety_gate_checks,
        permissive_returns,
        privileged_sinks,
        threshold_adjustments,
        init_guard_checks,
    })
}

fn extract_function_name(header: &str) -> Option<String> {
    let patterns = ["function ", "async "];
    let mut rest = header;
    for pat in &patterns {
        if let Some(pos) = rest.find(pat) {
            rest = &rest[pos + pat.len()..];
        }
    }
    if let Some(end) = rest.find('(') {
        let name = rest[..end].trim();
        if !name.is_empty() && !name.contains(' ') {
            return Some(name.to_string());
        }
    }
    None
}

fn extract_params(header: &str) -> Vec<String> {
    if let Some(start) = header.find('(') {
        if let Some(end) = header[start..].find(')') {
            let params_str = &header[start + 1..start + end];
            return params_str
                .split(',')
                .map(|p| p.split_whitespace().last().unwrap_or("").to_string())
                .filter(|p| !p.is_empty())
                .collect();
        }
    }
    Vec::new()
}

fn find_matching_brace(source: &str, start: usize) -> usize {
    let mut depth = 1i32;
    for (i, ch) in source[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return start + i + 1;
                }
            }
            _ => {}
        }
    }
    source.len()
}

fn strip_comments_and_strings(body: &str) -> String {
    // LENGTH-PRESERVING: every stripped byte becomes a space; every newline is
    // preserved at its original byte position. This keeps `stripped` byte-aligned
    // with `body`, so any offset found by scanning `stripped` is ALSO a valid
    // offset into `body`. All consumers must keep indexing `body`.
    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut out = vec![b' '; len];
    let mut i = 0;
    while i < len {
        match bytes[i] {
            b'/' if i + 1 < len && bytes[i + 1] == b'/' => {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                if i < len {
                    out[i] = b'\n';
                    i += 1;
                }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    if bytes[i] == b'\n' {
                        out[i] = b'\n';
                    }
                    i += 1;
                }
                i += 2;
            }
            b'\'' | b'"' | b'`' => {
                let q = bytes[i];
                i += 1;
                while i < len && bytes[i] != q {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else {
                        if bytes[i] == b'\n' {
                            out[i] = b'\n';
                        }
                        i += 1;
                    }
                }
                i += 1;
            }
            _ => {
                out[i] = bytes[i];
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| body.to_string())
}

fn byte_offset_to_line(body: &str, offset: usize) -> usize {
    body[..offset].chars().filter(|&c| c == '\n').count() + 1
}

fn extract_sink_arg_text(body: &str, sink_offset: usize) -> String {
    let after = &body[sink_offset..];
    if let Some(paren) = after.find('(') {
        let inner = &after[paren + 1..];
        if let Some(close) = inner.find(')') {
            return inner[..close].to_string();
        }
    }
    String::new()
}

fn extract_var_from_span(body: &str, offset: usize) -> Option<String> {
    let before = &body[..offset];
    for prefix in &["const ", "let ", "var "] {
        if let Some(pos) = before.rfind(prefix) {
            let rest = &before[pos + prefix.len()..];
            if let Some(eq_pos) = rest.find('=') {
                let name = rest[..eq_pos].trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

fn extract_identifier_at_offset(body: &str, offset: usize, trigger: &str) -> String {
    let bytes = body.as_bytes();
    let end = offset + trigger.len();
    let mut start = offset;
    while start > 0 && ((bytes[start - 1] as char).is_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    let mut end_pos = end;
    while end_pos < bytes.len()
        && ((bytes[end_pos] as char).is_alphanumeric() || bytes[end_pos] == b'_')
    {
        end_pos += 1;
    }
    body[start..end_pos].trim().to_string()
}

fn extract_verification_target_from_span(body: &str, offset: usize, trigger: &str) -> String {
    let after = &body[offset + trigger.len()..];
    let trimmed = after.trim_start();
    if let Some(paren) = trimmed.find('(') {
        let inner = &trimmed[paren + 1..];
        if let Some(close) = inner.find(')') {
            return inner[..close].trim().to_string();
        }
    }
    trimmed
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn extract_receiver_from_method(body: &str, dot_offset: usize) -> String {
    // Walk left from the dot to find the receiver identifier (e.g., `price` in `price.max(...)`)
    let bytes = body.as_bytes();
    let mut end = dot_offset;
    while end > 0 && bytes[end - 1] == b' ' {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && ((bytes[start - 1] as char).is_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    if start < end {
        body[start..end].to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_detects_handler() {
        let src = r#"
            export async function handleFeed(ctx) {
                const price = pyth.get_price();
                const verified = verify(price);
                token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
            }
        "#;
        let prog = parse_op_program(src);
        let h = &prog.handlers[0];
        assert_eq!(h.name, "handleFeed");
        assert!(!h.external_reads.is_empty());
        assert!(!h.verification_checks.is_empty());
        assert!(!h.privileged_sinks.is_empty());
    }

    #[test]
    fn deterministic_output() {
        let src = "export async function foo(a) { const x = pyth.get_price(); }";
        let a = parse_op_program(src);
        let b = parse_op_program(src);
        assert_eq!(a, b);
    }

    #[test]
    fn fixture_shape_detected() {
        let src = "export async function handleFeedUpdate(ctx: any, feedAccount: PublicKey) {\n    const price = pyth.get_price(feedAccount);\n    const transferIx = createTransferInstruction(\n        ctx.accounts.vault,\n        ctx.accounts.recipient,\n        ctx.accounts.owner,\n        price.amount,\n    );\n    await sendTransaction(ctx.connection, transferIx);\n}";
        let prog = parse_op_program(src);
        let h = &prog.handlers[0];
        assert_eq!(h.name, "handleFeedUpdate");
        assert_eq!(h.params.len(), 2);
        assert_eq!(h.external_reads.len(), 1, "must detect pyth.get_price");
        assert_eq!(h.external_reads[0].source, "external_price_feed");
        assert!(
            h.privileged_sinks
                .iter()
                .any(|s| s.kind == "token_transfer"),
            "must detect createTransferInstruction"
        );
        assert!(
            h.privileged_sinks
                .iter()
                .any(|s| s.kind == "transaction_submission"),
            "must detect sendTransaction"
        );
    }

    #[test]
    fn single_read_with_multiple_source_keywords() {
        let src = "export async function handleHermesFeedUpdate(ctx: any) {\n    const feedPrice = hermes.get_price();\n    token::transfer(ctx.accounts.vault, ctx.accounts.user, feedPrice);\n}";
        let prog = parse_op_program(src);
        let h = &prog.handlers[0];
        assert_eq!(h.external_reads.len(), 1);
        assert_eq!(h.external_reads[0].variable, "feedPrice");
    }

    #[test]
    fn case_insensitive_trigger_matching() {
        let src = "export async function handler(ctx: any) {\n    const tx = createTransferInstruction(ctx.accounts.a, ctx.accounts.b, ctx.accounts.c, 100);\n}";
        let prog = parse_op_program(src);
        let h = &prog.handlers[0];
        assert!(
            h.privileged_sinks
                .iter()
                .any(|s| s.kind == "token_transfer"),
            "camelCase createTransferInstruction must match case-insensitively"
        );
    }

    #[test]
    fn two_distinct_sinks_collected() {
        let src = "export async function handler(ctx: any) {\n    const ix1 = createTransferInstruction(ctx.accounts.a, ctx.accounts.b, ctx.accounts.c, 100);\n    const ix2 = createTransferInstruction(ctx.accounts.d, ctx.accounts.e, ctx.accounts.f, 200);\n}";
        let prog = parse_op_program(src);
        let h = &prog.handlers[0];
        assert_eq!(
            h.privileged_sinks.len(),
            2,
            "two distinct sink calls must produce two entries"
        );
    }
}
