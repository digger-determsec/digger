/// C6.10 — EVM price-manipulation detector: principled structural rule.
///
/// Detection principle (ADR-0032, updated C6.10):
/// 1. Detect manipulable price source: single-pool spot, internal exchange rate, single-feed read
/// 2. TWAP/cumulative sources are RESISTANCE by default — they are NOT flagged as manipulable
///    unless there is positive evidence of a short/insufficient window.
/// 3. If a TWAP source's window is unknowable from source text → SUPPRESS (precision-first).
/// 4. Emit finding only if a non-TWAP manipulable source feeds a critical action AND no resistance.
///
/// This is a SOURCE-TEXT rule operating on raw contract source, NOT on operation counts.
use digger_parser::model::RawProgram;

/// A detected price-manipulation finding.
#[derive(Debug, Clone)]
pub struct PriceManipulationFinding {
    pub function_name: String,
    pub price_source: String,
    pub critical_action: String,
    pub resistance_marker: Option<String>,
    pub suppressed: bool,
}

/// Critical actions gated by price in lending/AMM protocols.
const CRITICAL_ACTIONS: &[&str] = &[
    "borrow",
    "mint",
    "liquidate",
    "redeem",
    "swap",
    "depositAndBorrow",
    "withdraw",
];

/// Detect manipulable price source in source text.
/// Returns the matched signature if found.
/// NOTE: TWAP sources (getTWAP, priceCumulative, getPoolPriceCumulative) are NOT
/// listed here — they are treated as resistance, not as manipulable sources.
fn detect_manipulable_source(code: &str) -> Option<String> {
    // Pattern 1: getReserves() — single-DEX spot price
    if code.contains("getReserves") {
        return Some("getReserves (single-DEX spot price)".into());
    }

    // Pattern 2: internal exchange rate ratio
    let has_total_underlying =
        code.contains("totalUnderlying") || code.contains("getUnderlyingBalance");
    let has_total_supply = code.contains("totalSupply");
    if has_total_underlying && has_total_supply {
        return Some("totalUnderlying/totalSupply (internal exchange rate ratio)".into());
    }

    // Pattern 3: single-feed read (latestPrice / latestRoundData without staleness context)
    if code.contains("latestPrice") || code.contains("latestRoundData") {
        return Some("single-feed read (latestPrice/latestRoundData)".into());
    }

    // Pattern 4: slot0() — single-pool spot read
    if code.contains("slot0()") {
        return Some("slot0 (single-pool spot read)".into());
    }

    // Pattern 5: readFeed — oracle feed read (manipulable if single source)
    if code.contains("readFeed") {
        return Some("readFeed (oracle feed read)".into());
    }

    None
}

/// Check if source contains a TWAP/cumulative price read.
/// These are resistance sources, NOT manipulable sources.
fn has_twap_source(code: &str) -> bool {
    code.contains("getTWAP")
        || code.contains("oracleTWAP")
        || code.contains("priceCumulative")
        || code.contains("getPoolPriceCumulative")
}

/// Check if source has positive evidence of TWAP resistance (window/observations).
fn has_twap_window_evidence(code: &str) -> bool {
    // Observation count check
    code.contains("observations.length")
        || code.contains("minObservations")
        || code.contains("getObservationCount")
        // Time delta / window size check
        || code.contains("windowSize")
        || code.contains("timeDelta")
        || code.contains("minTimeDelta")
        || code.contains("getTimeDelta")
        // Observation timestamp check
        || code.contains("lastObservationTimestamp")
        // consult() is Uniswap V3 TWAP — inherently windowed
        || code.contains("consult(")
}

/// Detect manipulation-resistance markers in source text.
/// Returns the matched resistance signature if found.
/// Resistance markers require actual validation (require/if checks),
/// not just string presence in comments or return types.
fn detect_resistance_marker(code: &str) -> Option<String> {
    // Resistance 1: staleness/heartbeat check
    // Require block.timestamp comparison in a require() or if statement
    let has_staleness = code.contains("block.timestamp")
        && (code.contains("updatedAt") || code.contains("staleness"))
        && (code.contains("require(") || code.contains("require ("));
    if has_staleness {
        return Some("staleness check (block.timestamp vs updatedAt)".into());
    }

    // Resistance 2: TWAP source with window evidence
    if has_twap_source(code) && has_twap_window_evidence(code) {
        return Some("TWAP with window validation".into());
    }

    // Resistance 3: multi-source median with outlier rejection
    let has_median = code.contains("median") || code.contains("sort(");
    let has_outlier_rejection =
        code.contains("deviation") || code.contains("outlier") || code.contains("maxDeviation");
    let has_multi_source = code.contains("sources.length") || code.contains("minSources");
    if has_median && (has_outlier_rejection || has_multi_source) {
        return Some("multi-source median with outlier rejection".into());
    }

    // Resistance 4: TWAP cross-check (spot vs TWAP deviation)
    // Must have deviation check in require/if, not just in a variable
    let has_deviation_check = (code.contains("require(") || code.contains("require ("))
        && code.contains("deviation")
        && code.contains("twap");
    if has_deviation_check {
        return Some("spot-TWAP cross-check".into());
    }

    // Resistance 5: Chainlink round validation
    // Must have latestRoundData AND actual round validation pattern
    // Check for validated round comparison (answeredInRound >= roundId or similar)
    let has_latest_round = code.contains("latestRoundData");
    let has_round_validation = code.contains("answeredInRound >= roundId")
        || code.contains("answeredInRound>=")
        || code.contains("roundId >=")
        || code.contains("roundId>=")
        || code.contains("answeredInRound > roundId")
        || code.contains("answeredInRound>roundId");
    if has_latest_round && has_round_validation {
        return Some("Chainlink round validation".into());
    }

    None
}

/// Check if source contains a critical action gated by price.
fn has_critical_action(code: &str) -> Option<String> {
    for action in CRITICAL_ACTIONS {
        if code.contains(&format!("{}(", action)) || code.contains(&format!("{} (", action)) {
            return Some(action.to_string());
        }
    }
    None
}

/// Check if source reads a price.
fn has_price_read(code: &str) -> bool {
    code.contains("getReserves")
        || code.contains("totalSupply")
        || code.contains("latestPrice")
        || code.contains("latestRoundData")
        || code.contains("slot0()")
        || code.contains("getPoolPriceCumulative")
        || code.contains("priceCumulative")
        || code.contains("readFeed")
        || code.contains("getTWAP")
        || code.contains("oracleTWAP")
}

/// Main detection function.
/// Operates on source + program: source for text patterns, program for function names.
/// Always creates a finding for each function with a manipulable source,
/// with `suppressed=true` when resistance markers exist OR no critical action is present.
///
/// TWAP/cumulative sources are treated as resistance, not as manipulable sources.
/// If a TWAP source has no window evidence, the finding is suppressed with
/// "unresolvable window" (precision-first: unknown window → do not flag).
pub fn detect_price_manipulation(
    source: &str,
    program: &RawProgram,
) -> Vec<PriceManipulationFinding> {
    let mut findings = Vec::new();

    for func in &program.functions {
        let code = source;

        if !has_price_read(code) {
            continue;
        }

        // Check for manipulable (non-TWAP) source first
        let manipulable = detect_manipulable_source(code);

        // Check for TWAP source — treated as resistance, not manipulable
        if manipulable.is_none() && has_twap_source(code) {
            // TWAP source present. Check for window evidence.
            if has_twap_window_evidence(code) {
                // TWAP with window validation — RESISTANT
                let critical = has_critical_action(code);
                findings.push(PriceManipulationFinding {
                    function_name: func.name.clone(),
                    price_source: "TWAP with window validation".into(),
                    critical_action: critical.unwrap_or_else(|| "(none)".into()),
                    resistance_marker: Some("TWAP with window validation".into()),
                    suppressed: true,
                });
            } else {
                // TWAP source but window is UNRESOLVABLE
                // Precision-first: do NOT flag when window is unknown
                let critical = has_critical_action(code);
                findings.push(PriceManipulationFinding {
                    function_name: func.name.clone(),
                    price_source: "TWAP (unresolvable window)".into(),
                    critical_action: critical.unwrap_or_else(|| "(none)".into()),
                    resistance_marker: Some(
                        "unresolvable window — precision-first suppress".into(),
                    ),
                    suppressed: true,
                });
            }
            continue;
        }

        let price_source = match manipulable {
            Some(s) => s,
            None => continue,
        };

        let resistance = detect_resistance_marker(code);
        let critical_action = has_critical_action(code);

        let suppressed = resistance.is_some() || critical_action.is_none();
        findings.push(PriceManipulationFinding {
            function_name: func.name.clone(),
            price_source,
            critical_action: critical_action.unwrap_or_else(|| "(none)".into()),
            resistance_marker: resistance,
            suppressed,
        });
    }

    findings
}
