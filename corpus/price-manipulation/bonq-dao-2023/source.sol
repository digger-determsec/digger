// Minimal reproducer of Bonq DAO oracle manipulation (Feb 2023).
// Source: https://rekt.news/bonq-dao-rekt/ - "Bonq DAO loses $120M to oracle manipulation"
//
// Key pattern: single Chainlink feed used as price oracle with no staleness/round checks.
// Attacker manipulated the underlying asset price that the Chainlink feed reported,
// then used inflated collateral to borrow stablecoins.
contract BonqLending {
    address public priceFeed;   // single Chainlink feed
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    // BUG: reads single Chainlink feed with no staleness or round validation
    function getPrice() public view returns (uint256) {
        (, int256 answer, , , ) = getRoundData(priceFeed);
        require(answer > 0, "invalid price");
        return uint256(answer);
    }

    function borrow(address user, uint256 amount) external {
        uint256 price = getPrice();
        uint256 value = collateral[user] * price / 1e18;
        require(value >= amount, "undercollateralized");
        borrowed[user] += amount;
    }

    function getRoundData(
        address feed
    ) internal view returns (
        uint80,
        int256,
        uint256,
        uint256,
        uint80
    );
}
