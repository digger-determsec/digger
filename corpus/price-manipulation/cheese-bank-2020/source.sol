// Minimal reproducer of Cheese Bank flash-loan + Uniswap V2 spot price manipulation (Nov 2020).
// Source: https://rekt.news/cheesebank-rekt/ - "Cheese Bank loses $3.3M to flash loan attack"
//
// Key pattern: Uniswap V2 getReserves used as single-DEX spot oracle for lending collateral.
// Attacker flash-loaned ETH, swapped on Uniswap to move spot price, then used inflated
// collateral to borrow all available funds.
contract CheeseLending {
    address public uniswapPool;  // Uniswap V2 pool as single price source

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;
    uint256 public totalDeposits;

    // BUG: Uniswap V2 spot price as oracle - trivially manipulable
    function getCollateralValue(address user) public view returns (uint256) {
        (uint256 reserveIn, uint256 reserveOut) = getReserves(uniswapPool);
        uint256 spotPrice = (reserveOut * 1e18) / reserveIn;
        return collateral[user] * spotPrice / 1e18;
    }

    function borrow(address user, uint256 amount) external {
        uint256 value = getCollateralValue(user);
        require(value >= amount, "insufficient");
        borrowed[user] += amount;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
}
