// SAFE: Bounded Curve pool oracle with min/max price checks.
// Uses getReserves (detected!) but with price bounds enforcement.
// This is a genuine hard negative - getReserves IS the manipulable pattern,
// but the bounds make manipulation ineffective within the allowed range.
contract SafeBoundedCurve {
    address public curvePool;
    uint256 public minPrice;
    uint256 public maxPrice;
    uint256 public maxDeviation;  // max deviation from TWAP

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // SAFE: getReserves with bounds + cross-check against TWAP
    function getPrice() public view returns (uint256) {
        (uint256 reserve0, uint256 reserve1) = getReserves(curvePool);
        uint256 spotPrice = (reserve0 * 1e18) / reserve1;

        // Bounds check
        require(spotPrice >= minPrice, "below min price");
        require(spotPrice <= maxPrice, "above max price");

        // Cross-check against TWAP (priceCumulative)
        uint256 twapPrice = getTWAPPrice(curvePool);
        uint256 deviation;
        if (spotPrice > twapPrice) {
            deviation = (spotPrice - twapPrice) * 100 / twapPrice;
        } else {
            deviation = (twapPrice - spotPrice) * 100 / spotPrice;
        }
        require(deviation <= maxDeviation, "spot-TWAP deviation too large");

        return spotPrice;
    }

    function borrow(address user, uint256 amount) external {
        uint256 price = getPrice();
        uint256 value = collateral[user] * price / 1e18;
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
    function getTWAPPrice(address pool) internal view returns (uint256);
}
