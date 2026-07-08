/// DeFiLlama source fetcher and normalizer.
///
/// Fetches from DefiLlama's public hacks API (551+ incidents).
/// Each entry: date, name, classification, technique, amount, chain.
use crate::fetcher;
use crate::IngestionError;
use digger_knowledge::defillama;
use digger_knowledge_models::NormalizedKnowledge;

/// Ingest DeFiLlama hack disclosures.
pub fn ingest() -> Result<Vec<NormalizedKnowledge>, IngestionError> {
    let result = fetcher::fetch_defillama()?;

    let mut items = Vec::new();
    if let Some(content) = result.items.get("hacks.json") {
        let hacks = defillama::parse_hacks_json(content);
        for hack in &hacks {
            let knowledge = defillama::ingest_defillama_hack(hack);
            items.push(knowledge);
        }
    }

    Ok(items)
}
