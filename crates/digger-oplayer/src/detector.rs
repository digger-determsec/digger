use crate::types::*;

/// Detect unverified external attestation: handlers that consume
/// ValueFeed data (oracle prices, attestation signatures, VAA values)
/// and route it to privileged sinks WITHOUT a verification check.
///
/// Scoped to ValueFeed reads only — RoutingConfig reads are the
/// domain of `detect_control_plane_authority`.
pub fn detect_unverified_attestation(program: &OpProgram) -> Vec<OpViolation> {
    let mut violations = Vec::new();

    for handler in &program.handlers {
        let value_feed_reads: Vec<&DataRead> = handler
            .external_reads
            .iter()
            .filter(|r| r.category == ReadCategory::ValueFeed)
            .collect();
        if value_feed_reads.is_empty() || handler.privileged_sinks.is_empty() {
            continue;
        }

        let verified_vars: std::collections::BTreeSet<&str> = handler
            .verification_checks
            .iter()
            .map(|c| c.target.as_str())
            .collect();

        for read in &value_feed_reads {
            if !verified_vars.contains(read.variable.as_str()) {
                let id =
                    OpViolation::make_id(&handler.name, "UnverifiedAttestation", &read.variable);
                violations.push(OpViolation {
                    id,
                    function_id: handler.name.clone(),
                    violation_kind: "UnverifiedAttestation".into(),
                    suppressed: false,
                    suppression_reason: None,
                    provenance: format!(
                        "external_read:{}@line:{} -> privileged_sink (no verification)",
                        read.source, read.line
                    ),
                });
            }
        }
    }

    violations
}

/// Detect control-plane authority violations: privileged sinks whose
/// routing target derives from a RoutingConfig read (DB row, env var,
/// off-chain config, request param) WITHOUT an allowlist/owner check.
///
/// Scoped to RoutingConfig reads only — ValueFeed reads are the
/// domain of `detect_unverified_attestation`.
///
/// Fires when:
/// 1. A sink's target_variable traces to a RoutingConfig read
/// 2. No AllowlistCheck covers that target
///
/// Does NOT suppress on verify() — attestation is not an allowlist.
pub fn detect_control_plane_authority(program: &OpProgram) -> Vec<OpViolation> {
    let mut violations = Vec::new();

    for handler in &program.handlers {
        if handler.privileged_sinks.is_empty() {
            continue;
        }
        let guarded_vars: std::collections::BTreeSet<&str> = handler
            .allowlist_checks
            .iter()
            .map(|a| a.target.as_str())
            .collect();

        // Build a set of variables that come from RoutingConfig reads
        let routing_vars: std::collections::BTreeSet<&str> = handler
            .external_reads
            .iter()
            .filter(|r| r.category == ReadCategory::RoutingConfig)
            .map(|r| r.variable.as_str())
            .collect();

        for sink in &handler.privileged_sinks {
            if let Some(ref var) = sink.target_variable {
                // Only fire if the target variable is from a RoutingConfig read
                if routing_vars.contains(var.as_str()) && !guarded_vars.contains(var.as_str()) {
                    let id =
                        OpViolation::make_id(&handler.name, "UnauthorizedControlPlaneRouting", var);
                    violations.push(OpViolation {
                        id,
                        function_id: handler.name.clone(),
                        violation_kind: "UnauthorizedControlPlaneRouting".into(),
                        suppressed: false,
                        suppression_reason: None,
                        provenance: format!(
                            "routing_config:{}@sink:{} (no allowlist guard)",
                            var, sink.kind
                        ),
                    });
                }
            }
        }
    }

    violations
}

/// Detect fail-open bootstrap: safety-gate predicates that return the
/// permissive result on a default/zero/uninitialized state with no
/// explicit initialized-guard.
///
/// Operates on SafetyGateState reads and PermissiveReturns — a
/// disjoint input domain from ValueFeed (attestation) and
/// RoutingConfig (control-plane).
///
/// Fires when ALL hold:
/// 1. A handler has safety-gate state checks
/// 2. The handler has at least one fail-OPEN permissive return
///    (return true / return 0 / return ! — NOT return false)
/// 3. The handler has privileged sinks
/// 4. No initialization guard covers the gate variable
pub fn detect_fail_open_bootstrap(program: &OpProgram) -> Vec<OpViolation> {
    let mut violations = Vec::new();

    for handler in &program.handlers {
        if handler.safety_gate_checks.is_empty() || handler.privileged_sinks.is_empty() {
            continue;
        }

        // Fail-OPEN polarity: the default return must be permissive
        // ("true", "0", or negated). "false" is fail-CLOSED and must NOT trigger.
        let has_fail_open_return = handler
            .permissive_returns
            .iter()
            .any(|pr| pr.value == "true" || pr.value == "0" || pr.value == "negated");
        if !has_fail_open_return {
            continue;
        }

        // Dedicated init-guard suppressor: only FOB's own init_guard_checks
        // (NOT borrowed from verification_checks or allowlist_checks)
        let fob_guarded_vars: std::collections::BTreeSet<&str> = handler
            .init_guard_checks
            .iter()
            .map(|g| g.variable.as_str())
            .collect();

        for gate in &handler.safety_gate_checks {
            if !fob_guarded_vars.contains(gate.variable.as_str()) {
                let id = OpViolation::make_id(&handler.name, "FailOpenBootstrap", &gate.variable);
                violations.push(OpViolation {
                    id,
                    function_id: handler.name.clone(),
                    violation_kind: "FailOpenBootstrap".into(),
                    suppressed: false,
                    suppression_reason: None,
                    provenance: format!(
                        "safety_gate:{}@line:{} (fail-open default, no init guard)",
                        gate.variable, gate.line
                    ),
                });
            }
        }
    }

    violations
}

/// Detect silent failover: a handler falls back from a primary data source
/// to a weaker/secondary source but reuses the same unadjusted threshold,
/// so a sub-threshold manipulation that the primary would catch now passes.
///
/// Operates on FailoverSource reads ONLY — a disjoint input domain from
/// ValueFeed (attestation), RoutingConfig (control-plane), and
/// SafetyGateState (fail-open).
///
/// Fires when ALL hold:
/// 1. A handler has FailoverSource reads (fallback data paths)
/// 2. The handler has privileged sinks
/// 3. No threshold adjustment / source-appropriate re-validation exists
///    (dedicated suppressor — NOT borrowed from verify/allowlist/FOB guard)
pub fn detect_silent_failover(program: &OpProgram) -> Vec<OpViolation> {
    let mut violations = Vec::new();

    for handler in &program.handlers {
        let fo_reads: Vec<&DataRead> = handler
            .external_reads
            .iter()
            .filter(|r| r.category == ReadCategory::FailoverSource)
            .collect();
        if fo_reads.is_empty() || handler.privileged_sinks.is_empty() {
            continue;
        }

        // Collect failover read variable names
        let fo_vars: std::collections::BTreeSet<&str> =
            fo_reads.iter().map(|r| r.variable.as_str()).collect();

        // Dedicated suppressor: only suppress when a ThresholdAdjustment
        // targets a failover read variable (not any .max()/.min() anywhere)
        let fo_suppressed_vars: std::collections::BTreeSet<&str> = handler
            .threshold_adjustments
            .iter()
            .filter(|ta| fo_vars.contains(ta.target.as_str()))
            .map(|ta| ta.target.as_str())
            .collect();

        for read in &fo_reads {
            if fo_suppressed_vars.contains(read.variable.as_str()) {
                continue;
            }
            let id = OpViolation::make_id(
                &handler.name,
                "SilentFailover",
                &format!("{}:{}", read.source, read.line),
            );
            violations.push(OpViolation {
                id,
                function_id: handler.name.clone(),
                violation_kind: "SilentFailover".into(),
                suppressed: false,
                suppression_reason: None,
                provenance: format!(
                    "failover_source:{}@line:{} (unadjusted threshold, no source-specific re-validation)",
                    read.source, read.line
                ),
            });
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_op_program;

    // ── Attestation tests ──

    #[test]
    fn fires_on_unverified_attribution() {
        let src = r#"
            export async function feedKeeper(ctx) {
                const price = pyth.get_price();
                token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_unverified_attestation(&prog);
        assert_eq!(violations.len(), 1, "should catch unverified pyth read");
        assert_eq!(violations[0].violation_kind, "UnverifiedAttestation");
        assert!(!violations[0].suppressed);
    }

    #[test]
    fn silent_on_verified_attribution() {
        let src = r#"
            export async function feedKeeper(ctx) {
                const price = pyth.get_price();
                const sig = verify(price);
                token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_unverified_attestation(&prog);
        assert!(violations.is_empty(), "verified attestation must not fire");
    }

    #[test]
    fn two_unverified_reads_yield_distinct_ids() {
        let src = r#"
            export async function handler(ctx) {
                const price = pyth.get_price();
                const feed = hermes.get_feed();
                token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
                sendTransaction(ctx.connection, feed);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_unverified_attestation(&prog);
        assert_eq!(violations.len(), 2, "must detect two unverified reads");
        assert_ne!(
            violations[0].id, violations[1].id,
            "two unverified reads must have distinct ids"
        );
    }

    #[test]
    fn attestation_silent_on_routing_config_only() {
        let src = r#"
            export async function handler(ctx) {
                const programId = fetchConfig("routing");
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, programId, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_unverified_attestation(&prog);
        assert!(
            violations.is_empty(),
            "attestation must NOT fire on RoutingConfig reads"
        );
    }

    // ── Control-plane tests ──

    #[test]
    fn cp_fires_on_unguarded_routing_config() {
        let src = r#"
            export async function handleRoute(ctx) {
                const programId = fetchConfig("routing");
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, programId, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_control_plane_authority(&prog);
        assert!(
            !violations.is_empty(),
            "must fire on unguarded RoutingConfig-derived target"
        );
        assert_eq!(
            violations[0].violation_kind,
            "UnauthorizedControlPlaneRouting"
        );
    }

    #[test]
    fn cp_silent_when_allowlisted() {
        let src = r#"
            export async function handleRoute(ctx) {
                const programId = fetchConfig("routing");
                if (ALLOWED_PROGRAMS.includes(programId)) {
                    const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, programId, 100);
                    sendTransaction(ctx.connection, tx);
                }
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_control_plane_authority(&prog);
        assert!(
            violations.is_empty(),
            "must be silent when allowlist guard covers the target"
        );
    }

    #[test]
    fn cp_still_fires_when_verify_present() {
        let src = r#"
            export async function handleRoute(ctx) {
                const programId = fetchConfig("routing");
                const sig = verify(programId);
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, programId, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_control_plane_authority(&prog);
        assert!(
            !violations.is_empty(),
            "CP detector must NOT be suppressed by verify() — attestation is not an allowlist"
        );
    }

    #[test]
    fn cp_two_unguarded_yield_distinct_ids() {
        let src = r#"
            export async function handler(ctx) {
                const programA = fetchConfig("a");
                const programB = fetchConfig("b");
                invoke(programA, ctx.accounts);
                invoke_signed(programB, ctx.accounts);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_control_plane_authority(&prog);
        assert_eq!(
            violations.len(),
            2,
            "two unguarded RoutingConfig sinks must produce two violations"
        );
        assert_ne!(
            violations[0].id, violations[1].id,
            "distinct sinks must have distinct ids"
        );
    }

    #[test]
    fn cp_silent_on_hardcoded_target() {
        let src = r#"
            export async function handler(ctx) {
                const dest = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
                const tx = createTransferInstruction(ctx.accounts.vault, dest, ctx.accounts.owner, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_control_plane_authority(&prog);
        assert!(
            violations.is_empty(),
            "CP detector must NOT fire on hardcoded (non-external) targets"
        );
    }

    // ── Fail-open bootstrap tests ──

    #[test]
    fn fob_fires_on_fail_open_breaker() {
        let src = r#"
            export async function handlePrice(ctx) {
                if (isReady) {
                    const price = pyth.get_price();
                    token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
                }
                return true;
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert!(
            !violations.is_empty(),
            "must fire on fail-open safety gate (return true = permissive)"
        );
        assert_eq!(violations[0].violation_kind, "FailOpenBootstrap");
    }

    #[test]
    fn fob_silent_on_fail_closed_polarity() {
        // Same structure as the positive, but return false (fail-CLOSED)
        let src = r#"
            export async function handlePrice(ctx) {
                if (isReady) {
                    const price = pyth.get_price();
                    token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
                }
                return false;
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert!(
            violations.is_empty(),
            "must be silent when polarity is fail-CLOSED (return false)"
        );
    }

    #[test]
    fn fob_silent_when_fail_closed_with_guard() {
        let src = r#"
            export async function handlePrice(ctx) {
                require(isReady);
                if (isReady) {
                    const price = pyth.get_price();
                    token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
                }
                return false;
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert!(
            violations.is_empty(),
            "must be silent when dedicated init guard (require) covers the gate variable"
        );
    }

    #[test]
    fn fob_polarity_flip_proof() {
        // Flip proof: positive fires, same code with return false goes silent
        let src_open = r#"
            export async function handler(ctx) {
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                return true;
            }
        "#;
        let src_closed = r#"
            export async function handler(ctx) {
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                return false;
            }
        "#;
        assert!(
            !detect_fail_open_bootstrap(&parse_op_program(src_open)).is_empty(),
            "return true must fire"
        );
        assert!(
            detect_fail_open_bootstrap(&parse_op_program(src_closed)).is_empty(),
            "return false must be silent (polarity flip)"
        );
    }

    #[test]
    fn fob_polarity_guard_removal_proof() {
        // Remove require() but keep return false → still silent (polarity is load-bearing)
        let src_guarded = r#"
            export async function handler(ctx) {
                require(isReady);
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                return false;
            }
        "#;
        let src_unguarded_closed = r#"
            export async function handler(ctx) {
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                return false;
            }
        "#;
        // Both silent — polarity (false) is load-bearing, not require()
        assert!(
            detect_fail_open_bootstrap(&parse_op_program(src_guarded)).is_empty(),
            "guarded + return false must be silent"
        );
        assert!(
            detect_fail_open_bootstrap(&parse_op_program(src_unguarded_closed)).is_empty(),
            "unguarded + return false must be silent (polarity not guard)"
        );
    }

    #[test]
    fn fob_two_gates_yield_distinct_ids() {
        let src = r#"
            export async function handler(ctx) {
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                if (isHealthy) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 200); }
                return true;
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert_eq!(
            violations.len(),
            2,
            "two unguarded gates must produce two violations"
        );
        assert_ne!(
            violations[0].id, violations[1].id,
            "distinct gates must have distinct ids"
        );
    }

    #[test]
    fn fob_silent_on_bare_sink_no_gate() {
        let src = r#"
            export async function handler(ctx) {
                const price = pyth.get_price();
                token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert!(
            violations.is_empty(),
            "must NOT fire on bare sink with no safety gate (attestation's domain)"
        );
    }

    #[test]
    fn fob_verify_does_not_suppress() {
        // verify() must NOT suppress FOB — the init-guard is dedicated
        let src = r#"
            export async function handler(ctx) {
                const sig = verify(isReady);
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                return true;
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert!(
            !violations.is_empty(),
            "verify() must NOT suppress FOB — only dedicated init_guard_checks suppress"
        );
    }

    #[test]
    fn fob_require_does_suppress() {
        // require() IS a dedicated init guard → must suppress
        let src = r#"
            export async function handler(ctx) {
                require(isReady);
                if (isReady) { token::transfer(ctx.accounts.vault, ctx.accounts.user, 100); }
                return true;
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_fail_open_bootstrap(&prog);
        assert!(
            violations.is_empty(),
            "require() is a dedicated init guard — must suppress FOB"
        );
    }

    // ── Silent-failover tests ──

    #[test]
    fn sf_fires_on_unadjusted_fallback() {
        let src = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, price, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_silent_failover(&prog);
        assert!(
            !violations.is_empty(),
            "must fire on unadjusted fallback path"
        );
        assert_eq!(violations[0].violation_kind, "SilentFailover");
    }

    #[test]
    fn sf_silent_when_threshold_tightened() {
        let src = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const adjusted = tighten(price);
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, adjusted, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_silent_failover(&prog);
        assert!(
            violations.is_empty(),
            "must be silent when threshold is tightened on fallback"
        );
    }

    #[test]
    fn sf_silent_when_revalidated() {
        let src = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const checked = re_validat(price);
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, checked, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_silent_failover(&prog);
        assert!(
            violations.is_empty(),
            "must be silent when source-appropriate re-validation exists"
        );
    }

    #[test]
    fn sf_two_fallbacks_yield_distinct_ids() {
        let src = r#"
            export async function handler(ctx) {
                const priceA = catch(getDexScreenerPrice());
                const priceB = catch(getCoingeckoPrice());
                const tx1 = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, priceA, 100);
                const tx2 = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, priceB, 200);
                sendTransaction(ctx.connection, tx1);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_silent_failover(&prog);
        assert_eq!(
            violations.len(),
            2,
            "two unadjusted fallbacks must produce two violations"
        );
        assert_ne!(
            violations[0].id, violations[1].id,
            "distinct fallback sites must have distinct ids"
        );
    }

    #[test]
    fn sf_flip_proof() {
        // Same structure: positive fires, add tighten() → goes silent
        let src_open = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, price, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let src_fixed = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const adjusted = tighten(price);
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, adjusted, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        assert!(
            !detect_silent_failover(&parse_op_program(src_open)).is_empty(),
            "unadjusted fallback must fire"
        );
        assert!(
            detect_silent_failover(&parse_op_program(src_fixed)).is_empty(),
            "adjusted fallback must be silent (flip-proof)"
        );
    }

    #[test]
    fn sf_suppressor_is_dedicated_not_borrowed() {
        // Handler has verify() + allowlist, but NO threshold adjustment.
        // Must STILL fire — the suppressor is dedicated, not borrowed.
        let src = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const sig = verify(price);
                if (ALLOWED_PROGRAMS.includes(price)) {
                    const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, price, 100);
                    sendTransaction(ctx.connection, tx);
                }
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_silent_failover(&prog);
        assert!(
            !violations.is_empty(),
            "verify()/allowlist must NOT suppress failover — dedicated suppressor only"
        );
    }

    #[test]
    fn sf_silent_on_bare_sink_no_failover() {
        let src = r#"
            export async function handler(ctx) {
                const price = pyth.get_price();
                token::transfer(ctx.accounts.vault, ctx.accounts.user, price);
            }
        "#;
        let prog = parse_op_program(src);
        let violations = detect_silent_failover(&prog);
        assert!(
            violations.is_empty(),
            "must NOT fire on bare sink with no FailoverSource read (other detector's domain)"
        );
    }

    #[test]
    fn sf_cross_class_no_contamination() {
        // Failover fixture must NOT trigger attestation, CP, or FOB detectors
        let src = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, price, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        let prog = parse_op_program(src);
        assert!(
            detect_unverified_attestation(&prog).is_empty(),
            "attestation must NOT fire on failover fixture"
        );
        assert!(
            detect_control_plane_authority(&prog).is_empty(),
            "CP must NOT fire on failover fixture"
        );
        assert!(
            detect_fail_open_bootstrap(&prog).is_empty(),
            "FOB must NOT fire on failover fixture"
        );
        assert!(
            !detect_silent_failover(&prog).is_empty(),
            "silent_failover MUST fire on failover fixture"
        );
    }

    #[test]
    fn sf_flip_proof_nullish_literal_silent() {
        // ?? with a literal default (no source call) must be SILENT now.
        // Before narrowing, this would have fired SF.
        let src_benign = r#"
            export async function handler(ctx) {
                const slippage = cfg.slippage ?? 0.5;
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, slippage, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        assert!(
            detect_silent_failover(&parse_op_program(src_benign)).is_empty(),
            "?? with literal default must NOT fire SF (narrowed trigger)"
        );
    }

    #[test]
    fn sf_flip_proof_catch_logger_silent() {
        // catch(e) with only a logger (no source call) must be SILENT now.
        let src_benign = r#"
            export async function handler(ctx) {
                let result;
                try {
                    result = ctx.accounts.data;
                } catch (e) {
                    logger.error(e);
                }
                sendTransaction(ctx.connection, result);
            }
        "#;
        assert!(
            detect_silent_failover(&parse_op_program(src_benign)).is_empty(),
            "catch(e) with only logger must NOT fire SF (narrowed trigger)"
        );
    }

    #[test]
    fn sf_genuine_fallback_to_source_still_fires() {
        // A catch wrapping a REAL source call must still fire.
        let src = r#"
            export async function handler(ctx) {
                const price = catch(getDexScreenerPrice());
                const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, price, 100);
                sendTransaction(ctx.connection, tx);
            }
        "#;
        assert!(
            !detect_silent_failover(&parse_op_program(src)).is_empty(),
            "catch wrapping a source call must still fire SF"
        );
    }
}
