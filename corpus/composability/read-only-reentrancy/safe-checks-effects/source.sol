// SAFE: Checks-Effects-Interactions with state mutation before external call.
// State is finalized (written) BEFORE the external call, so any state read
// during the callback will see the updated value.
contract SafeChecksEffectsWrite {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public shares;
    uint256 public totalDeposited;

    function deposit(uint256 amount) external {
        // Effects FIRST - state finalized before external call
        deposits[msg.sender] += amount;
        shares[msg.sender] = (amount * 1e18) / totalDeposited;
        totalDeposited += amount;

        // External call AFTER state finalization
        IERC20(msg.sender).transferFrom(msg.sender, address(this), amount);
    }

    function getSharePrice() public view returns (uint256) {
        if (totalDeposited == 0) return 1e18;
        return (totalDeposited * 1e18) / totalDeposited; // simplified
    }
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
