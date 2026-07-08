# Composability: Read-Only Reentrancy GT (C6.13)

## Positives (5 cases)

| Case | Protocol | Date | Loss | Citation | Pattern |
|------|----------|------|------|----------|---------|
| sentiment-2023 | Sentiment | Apr 4 2023 | $1M | https://hackmd.io/@sentimentxyz/SJCySo1z2 | Balancer BPT price read after transfer callback |
| conic-finance-2023 | Conic Finance | Jul 21 2023 | $3.2M | https://rekt.news/conic-finance-rekt/ | Curve pool balance read after ETH callback |
| dforce-2023 | dForce | Feb 9-10 2023 | $3.65M | https://rekt.news/dforce-network-rekt/ | Curve LP price read after transfer callback |
| sturdy-finance-2023 | Sturdy Finance | Jun 12 2023 | $800K | https://rekt.news/sturdy-rekt/ | Balancer B-stETH price during flash-loan (cross-contract) |
| midas-capital-2023 | Midas Capital | Jan 15 2023 | $660K | https://rekt.news/midas-capital-rekt/ | Curve WMATIC-stMATIC LP price after transfer |

## Negatives (5 cases)

| Case | Pattern | Guard | Why safe |
|------|---------|-------|----------|
| safe-view-reentrancy-check | ExternalCall->StateRead | View checks reentrancy lock (OZ #4422) | Reverts if called during reentrancy window |
| safe-callback-no-state-read | ExternalCall (no StateRead after) | CEI pattern | State reads before external call |
| safe-checks-effects | ExternalCall (no StateRead after) | State write before call | State finalized before interaction |
| safe-benign-call-then-read | ExternalCall->StateRead | Read is benign (logging/display) | Not security-critical |
| safe-view-only-callback | ExternalCall->StateRead (compound assign) | Read flows to += operation, not valuation | StateRead is compound-assignment artifact, not price/balance for collateral |

## Known limitations

- sturdy-finance: cross-contract callback (Balancer flash-loan) not visible in per-function IR. Structural FN. Max recall ceiling = 4/5 = 80%.
- safe-benign-call-then-read + safe-view-only-callback: test the security-criticality filter. Both have ExternalCall->StateRead but reads are not price/balance used for valuation.
