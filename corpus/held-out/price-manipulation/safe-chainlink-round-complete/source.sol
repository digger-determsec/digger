// SAFE: Chainlink with answeredInRound completeness check.
// The answeredInRound check ensures the oracle has returned the latest round data,
// not stale data from a previous round. This is the full Chainlink best practice.
contract SafeChainlinkRoundComplete {
    AggregatorV3Interface internal priceFeed;
    uint256 public maxStaleness;

    constructor(address feed, uint256 staleness) {
        priceFeed = AggregatorV3Interface(feed);
        maxStaleness = staleness;
    }

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // Staleness check
        require(block.timestamp - updatedAt <= maxStaleness, "stale");

        // Round completeness: answer was computed in this round, not carried over
        require(answeredInRound >= roundId, "round incomplete");

        // Extra: answer must be positive
        require(answer > 0, "invalid price");

        return uint256(answer);
    }
}

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}
