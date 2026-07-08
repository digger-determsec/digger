// Minimal reproducer of Sturdy Finance read-only reentrancy (Jun 12 2023).
// Source: https://rekt.news/sturdy-rekt/ - "Sturdy Finance loses 442 ETH to read-only reentrancy"
//
// Key pattern: Balancer B-stETH price read during flash-loan callback.
// Attacker flash-loans via Balancer, reenters during callback, reads stale
// B-stETH price, then borrows against inflated collateral.
contract SturdyLending {
    address public balancerPool;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: reads Balancer pool price AFTER flash-loan callback - stale
    function borrow(uint256 amount) external {
        // State read AFTER potential callback context
        uint256 price = getBalancerPrice(balancerPool);
        uint256 value = collateral[msg.sender] * price / 1e18;
        require(value >= amount, "undercollateralized");
        borrowed[msg.sender] += amount;
    }

    function getBalancerPrice(address pool) internal view returns (uint256);
}
