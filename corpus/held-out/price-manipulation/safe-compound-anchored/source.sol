// SAFE: Compound-style anchored oracle with TWAP + spot cross-check.
// Uses priceCumulative for TWAP base (detected by priceCumulative pattern),
// plus a deviation cross-check between spot and TWAP.
contract SafeCompoundAnchored {
    address public uniswapPool;
    uint256 public maxDeviation;  // e.g., 10%
    uint256 public twapWindow;

    // SAFE: TWAP + spot cross-check - manipulation diluted by TWAP
    function getPrice() public view returns (uint256) {
        uint256 spotPrice = getSpotPrice(uniswapPool);
        uint256 twapPrice = getTWAPPrice(uniswapPool, twapWindow);

        uint256 deviation;
        if (spotPrice > twapPrice) {
            deviation = (spotPrice - twapPrice) * 100 / twapPrice;
        } else {
            deviation = (twapPrice - spotPrice) * 100 / spotPrice;
        }

        if (deviation > maxDeviation) {
            return twapPrice;  // fallback to TWAP
        }
        return spotPrice;
    }

    function getSpotPrice(address pool_) internal view returns (uint256);
    function getTWAPPrice(address pool_, uint256 window) internal view returns (uint256);
}
