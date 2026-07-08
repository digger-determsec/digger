// SAFE: External call followed by state read, but the read value is NOT
// security-critical. This is the #1 false-positive source for a naive
// ExternalCall->StateRead detector. The detector must NOT fire because
// the read value doesn't gate any security-sensitive action.
contract SafeBenignCallThenRead {
    address public admin;
    uint256 public lastActivityTime;
    uint256 public totalDeposited;

    // SAFE: external call followed by state read, but the read is just
    // for logging/display - not used for any security-critical decision
    function deposit(uint256 amount) external {
        // External call - ERC20 transfer
        IERC20(msg.sender).transferFrom(msg.sender, address(this), amount);

        // State read AFTER external call - but this is just for logging
        uint256 currentBalance = getBalance();
        lastActivityTime = block.timestamp;

        // State write - uses the EXTERNAL amount parameter, NOT the stale read
        totalDeposited += amount;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
