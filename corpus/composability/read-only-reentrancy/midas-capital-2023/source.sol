// Minimal reproducer of Midas Capital read-only reentrancy (Jan 15 2023).
// Source: https://rekt.news/midas-capital-rekt/ - "Midas Capital loses $660K to read-only reentrancy"
//
// Key pattern: Curve WMATIC-stMATIC LP price read during token transfer callback.
// Attacker reenters during ERC20 transfer, reading stale Curve pool price,
// then borrows against inflated collateral.
contract MidasLending {
    address public curvePool;  // Curve WMATIC-stMATIC pool
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: reads Curve LP price AFTER external call - stale during callback
    function depositAndBorrow(uint256 depositAmount, uint256 borrowAmount) external {
        // External call - attacker reenters during transfer
        IERC20(msg.sender).transferFrom(msg.sender, address(this), depositAmount);

        // State read AFTER external call - reads stale Curve LP price
        uint256 lpPrice = getCurveLPPrice(curvePool);
        collateral[msg.sender] += (depositAmount * lpPrice) / 1e18;

        uint256 value = collateral[msg.sender];
        require(value >= borrowAmount, "undercollateralized");
        borrowed[msg.sender] += borrowAmount;
    }

    function getCurveLPPrice(address pool) internal view returns (uint256);
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
