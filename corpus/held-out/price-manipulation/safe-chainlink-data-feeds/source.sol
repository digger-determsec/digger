// SAFE: Chainlink Data Feeds with multi-feed aggregation + staleness.
// Uses latestRoundData (detected) with staleness check + answeredInRound.
contract SafeChainlinkDataFeeds {
    address[] public feeds;  // multiple Chainlink feeds for same asset
    uint256 public maxStaleness;

    // SAFE: reads from multiple feeds, requires freshness
    function getPrice() public view returns (uint256) {
        uint256 total = 0;
        uint256 count = 0;

        for (uint256 i = 0; i < feeds.length; i++) {
            (
                uint80 roundId,
                int256 answer,
                ,
                uint256 updatedAt,
                uint80 answeredInRound
            ) = getRoundData(feeds[i]);

            // Staleness check
            require(block.timestamp - updatedAt <= maxStaleness, "stale price");

            // Round completeness
            require(answeredInRound >= roundId, "round incomplete");

            require(answer > 0, "invalid price");
            total += uint256(answer);
            count++;
        }

        require(count > 0, "no feeds");
        return total / count;
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
