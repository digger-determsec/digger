// Minimal reproducer of dForce read-only reentrancy (Feb 9-10 2023).
// Source: https://rekt.news/dforce-network-rekt/ - "dForce loses $3.65M to read-only reentrancy"
// Source: https://skynet.certik.com/ - CertiK analysis
//
// Key pattern: Curve LP price read during token transfer callback.
// Attacker reenters during ERC20 transfer callback, reading stale Curve pool
// balance to inflate their deposit value on Arbitrum and Optimism.
contract DForceVault {
    address public curvePool;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;

    // BUG: reads Curve LP price AFTER external call - stale during callback
    function deposit(uint256 amount) external {
        // External call - attacker reenters during transfer callback
        IERC20(msg.sender).transferFrom(msg.sender, address(this), amount);

        // State read AFTER external call - reads stale Curve LP price
        uint256 lpPrice = getCurveLPCurvePrice(curvePool);
        deposits[msg.sender] += (amount * lpPrice) / 1e18;
    }

    function getCurveLPCurvePrice(address pool) internal view returns (uint256);
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
