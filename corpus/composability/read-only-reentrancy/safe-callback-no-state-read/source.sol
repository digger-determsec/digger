// SAFE: External call with no state read after - the state read happens BEFORE.
// The Checks-Effects-Interactions pattern is followed correctly.
// ExternalCall exists but there is no StateRead after it in the same function.
contract SafeChecksEffects {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public debt;

    // SAFE: all state reads happen BEFORE the external call (CEI pattern)
    function repay(address token, uint256 amount) external {
        // State reads BEFORE external call
        uint256 currentDebt = debt[msg.sender];
        require(amount <= currentDebt, "overpay");

        // Effects BEFORE interactions
        debt[msg.sender] -= amount;
        balances[msg.sender] -= amount;

        // External call LAST
        IERC20(token).transfer(msg.sender, amount);
    }
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}
