// Minimal reproducer of Harvest Finance read-only reentrancy (Oct 18 2020).
// Source: https://rekt.news/harvest-finance-rekt/ -- Harvest Finance loses $34M
// via Curve pool price manipulation during flash-loan callback.
//
// Key pattern: Curve pool price read AFTER ERC20 transfer -- stale during
// reentrancy callback. The vault reads the Curve Y pool price to compute
// share value, but the price can be temporarily skewed by a large deposit.
contract HarvestVault {
    address public curvePool;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalUnderlying;

    // BUG: reads Curve pool price AFTER external call -- stale during callback
    function deposit(uint256 amount) external {
        // External call -- attacker reenters during ERC20 transfer callback
        IERC20(msg.sender).transferFrom(msg.sender, address(this), amount);

        // State read AFTER external call -- reads stale Curve pool price
        uint256 price = getCurvePoolPrice(curvePool);
        uint256 assets = (amount * price) / 1e18;

        // Shares computed from stale price
        uint256 shareAmount = (assets * 1e18) / getSharePrice();
        shares[msg.sender] += shareAmount;
        totalShares += shareAmount;
        totalUnderlying += assets;
    }

    function getSharePrice() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalUnderlying * 1e18) / totalShares;
    }

    function getCurvePoolPrice(address pool) internal view returns (uint256);
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
