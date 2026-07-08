use digger_hypothesis::HypothesisResult;

pub fn to_json(result: &HypothesisResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}
