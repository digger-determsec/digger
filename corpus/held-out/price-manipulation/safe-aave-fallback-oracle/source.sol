// SAFE: Aave-style fallback oracle using latestRoundData with round validation + staleness.
// Price read IS detected (latestRoundData), and resistance IS recognized (roundId + staleness).
contract SafeAaveFallbackOracle {
    address public primaryOracle;
    address public fallbackOracle;

    function getPrice(address asset) public view returns (uint256) {
        uint256 price = getAggregatedPrice(primaryOracle, asset);
        return price;
    }

    function getAggregatedPrice(
        address oracle,
        address asset
    ) internal view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = getRoundData(oracle, asset);

        // Staleness check
        require(block.timestamp - updatedAt <= 3600, "stale price");

        // Round completeness
        require(answeredInRound >= roundId, "round incomplete");

        require(answer > 0, "invalid price");
        return uint256(answer);
    }

    function getRoundData(
        address oracle_,
        address asset_
    ) internal view returns (
        uint80,
        int256,
        uint256,
        uint256,
        uint80
    );
}
