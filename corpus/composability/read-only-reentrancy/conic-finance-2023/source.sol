// Minimal reproducer of Conic Finance read-only reentrancy (July 2023).
// Source: https://rekt.news/conic-finance-rekt/ - "Conic Finance loses $6.5M to read-only reentrancy"
//
// Key pattern: Curve pool price read during ETH transfer callback.
// Attacker reenters during ETH transfer, reading stale Curve pool balance
// to inflate their deposit share price.
contract ConicVault {
    address public curvePool;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // BUG: reads Curve pool balance AFTER external call - stale during callback
    function deposit(uint256 amount) external {
        // External call - attacker can reenter during ETH receive
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);

        // State read AFTER external call - reads stale Curve pool balance
        uint256 poolBalance = getPoolBalance(curvePool);
        uint256 sharePrice = (poolBalance * 1e18) / totalShares;

        uint256 sharesToMint = (amount * 1e18) / sharePrice;
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
    }

    function getPoolBalance(address pool) internal view returns (uint256);
}
