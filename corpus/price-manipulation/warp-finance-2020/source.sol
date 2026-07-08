// Minimal reproducer of Warp Finance flash-loan + Uniswap V2 oracle manipulation (Dec 2020).
// Source: https://rekt.news/warp-finance-rekt/ - "Warp Finance loses $8M to flash loan attack"
//
// Key pattern: Uniswap V2 TWAP oracle used for collateral valuation, but the TWAP window
// was too short - effectively spot price. Attacker flash-loaned large amount, moved
// Uniswap price, then used inflated collateral to borrow from Warp.
contract WarpLending {
    address public uniswapPool;
    uint256 public twapWindow;  // short window - makes TWAP ≈ spot

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: TWAP with too-short window - effectively spot price
    function getCollateralValue(address user) public view returns (uint256) {
        // TWAP read via cumulative price, but window is too short
        uint256 price = getTWAP(uniswapPool, twapWindow);
        return collateral[user] * price / 1e18;
    }

    function borrow(address user, uint256 amount) external {
        uint256 value = getCollateralValue(user);
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    function getTWAP(address pool, uint256 window) internal view returns (uint256);
}
