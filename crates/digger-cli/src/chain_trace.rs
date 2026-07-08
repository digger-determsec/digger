use serde_json::Value;

/// Enrich a serialized artifact JSON with correlation_id and audit_events.
/// This threads the chain trace through every stage of the pipeline.
pub fn enrich_with_trace(
    artifact: Value,
    correlation_id: &str,
    stage_name: &str,
    input_refs: Vec<String>,
) -> Value {
    let mut enriched = artifact.clone();

    enriched["correlation_id"] = serde_json::json!(correlation_id);

    let event = serde_json::json!({
        "event_id": format!("ae-{}-{}", stage_name, &format!("{:x}", djbx33a(correlation_id.as_bytes()))),
        "event_type": format!("{}_completed", stage_name),
        "actor": "digger-cli",
        "action_summary": format!("{} stage completed", stage_name),
        "input_refs": input_refs,
        "output_refs": [correlation_id.to_string()],
        "approval_required": false,
        "approval_status": "not_required".to_string(),
        "policy_decision": "allowed".to_string(),
        "is_mutating": false,
        "is_finding": false,
    });

    let events = enriched["audit_events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut new_events = events;
    new_events.push(event);
    enriched["audit_events"] = serde_json::json!(new_events);

    enriched
}

fn djbx33a(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}
