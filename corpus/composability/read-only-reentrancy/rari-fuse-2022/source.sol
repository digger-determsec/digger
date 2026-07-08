// Minimal reproducer of Rari Fuse read-only reentrancy (May 2022).
// Source: https://rekt.news/rari-rekt/ -- Rari Fuse pools lose ~$80M
// via Compound-fork reentrancy during ERC20 transfer callback.
//
// Key pattern: pool exchange rate read AFTER external call -- stale during
// reentrancy. The Fuse pool reads the cToken exchange rate to compute
// collateral value, but the rate can be inflated during the callback window.
contract RariFusePool {
    address public cToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: reads exchange rate AFTER external call -- stale during callback
    function deposit(uint256 amount) external {
        // External call -- attacker reenters during ERC20 transfer callback
        IERC20(cToken).transferFrom(msg.sender, address(this), amount);

        // State read AFTER external call -- reads stale exchange rate
        uint256 rate = getExchangeRate(cToken);
        uint256 collateralValue = (amount * rate) / 1e18;
        collateral[msg.sender] += collateralValue;
    }

    function borrow(address user, uint256 amount) external {
        uint256 value = collateral[user];
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    function getExchangeRate(address token) internal view returns (uint256);
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
