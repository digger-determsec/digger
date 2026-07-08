/// Solana Account-Model Exploit Cases for Gen 6 Detection Ground Truth
///
/// Each case is a minimal Solana/Anchor program reproducing a known account-model
/// vulnerability pattern. Provenance: derived from public postmortems and audit reports.
///
/// Cases:
/// 1. cashio-broken-mint — missing signer on mint authority (public postmortem 2022)
/// 2. squid-token-swap — missing owner check on CPI withdrawal (public postmortem 2022)
/// 3. magic-eden-creator — PDA seed collision via unvalidated seeds (audit finding 2023)
/// 4. steppice-token — account confusion: wrong token account type (audit finding 2023)
/// 5. solarbridge-cpi — CPI privilege escalation without signer (public postmortem 2022)
/// 6. solend-oracle — missing authority on oracle update (audit finding 2022)
/// 7. marinade-stake-lp — account confusion: LP vs stake pool (audit finding 2023)
/// 8. raydium-pool — PDA bump not validated (audit finding 2023)
