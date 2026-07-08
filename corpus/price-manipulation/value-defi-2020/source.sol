// Minimal reproducer of Value DeFi flash-loan + Uniswap V2 spot price manipulation (Nov 2020).
// Source: https://rekt.news/value-defi-rekt/ - "Value DeFi loses $6M to flash loan attack"
//
// Key pattern: Uniswap V2 getReserves() used as spot price oracle for gUSD vault.
// Attacker flash-loaned, swapped on Uniswap to move the spot price, then called
// claim + deposit at the inflated price to extract value.
contract ValueDefiVault {
    address public uniswapPool;  // single DEX pool as price source

    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // BUG: Uniswap V2 spot as oracle - trivially manipulable
    function getPrice() public view returns (uint256) {
        (uint256 reserve0, uint256 reserve1) = getReserves(uniswapPool);
        return (reserve0 * 1e18) / reserve1;
    }

    function claimAndDeposit(uint256 amount) external {
        uint256 price = getPrice();
        uint256 assets = (amount * price) / 1e18;
        shares[msg.sender] += assets;
        totalShares += assets;
    }

    function redeem(uint256 shareAmt) external {
        uint256 price = getPrice();
        uint256 assets = (shareAmt * price) / 1e18;
        shares[msg.sender] -= shareAmt;
        totalShares -= shareAmt;
    }

    function getReserves(address pool) internal view returns (uint256, uint256);
}
