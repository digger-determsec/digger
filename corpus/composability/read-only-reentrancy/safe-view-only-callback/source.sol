// SAFE: View-only callback - the callback function only reads state, never mutates.
// No ExternalCall in the price-reading function - state reads happen in a pure view.
// The external call (deposit) is in a separate function that doesn't read the shared state.
contract SafeViewOnlyCallback {
    address public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // SAFE: this function only reads - no ExternalCall, so no reentrancy risk
    function getCollateralValue(address user) public view returns (uint256) {
        uint256 price = getOraclePrice(oracle);
        return collateral[user] * price / 1e18;
    }

    function borrow(address user, uint256 amount) external {
        // State read - but no external call in this path
        uint256 value = getCollateralValue(user);
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    // This function has the external call, but no state read after it
    function supply(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function getOraclePrice(address oracle_) internal view returns (uint256);
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
