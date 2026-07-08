// Minimal reproducer of Mango Markets price oracle manipulation (Oct 2022).
// Source: https://rekt.news/mango-rekt/ - "Mango Markets loses $114M to oracle manipulation"
// The attacker manipulated MNGO token price on a low-liquidity DEX to inflate their
// collateral value, then borrowed against the inflated position across all pools.
//
// Key pattern: single-DEX spot price used as collateral valuation oracle.
contract MangoOracle {
    struct Market {
        address token;
        address dexPool;      // single-DEX pool used as price source
    }

    mapping(address => Market) public markets;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    // BUG: uses single DEX spot price as oracle - manipulable via flash-loan
    function getCollateralValue(address user) public view returns (uint256) {
        address market = markets[user].token;
        address pool = markets[user].dexPool;

        // Single-DEX spot price: getReserves() from the pool
        uint256 reserve0;
        uint256 reserve1;
        (reserve0, reserve1) = getReserves(pool);

        uint256 price = (reserve1 * 1e18) / reserve0; // spot price
        return deposits[user] * price / 1e18;
    }

    // BUG: allows borrow up to collateral value - attacker inflates collateral first
    function borrow(address user, uint256 amount) external {
        uint256 collateral = getCollateralValue(user);
        require(collateral >= amount, "insufficient collateral");
        borrows[user] += amount;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
}
