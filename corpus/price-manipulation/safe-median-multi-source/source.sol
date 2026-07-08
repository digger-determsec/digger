// SAFE: Multi-source median oracle with outlier rejection.
// NOT manipulable: requires compromising N/2+ independent oracle sources
// simultaneously to influence the median. Outlier rejection further
// protects against a single compromised source.
contract SafeMedianOracle {
    address[] public sources;        // multiple independent oracle feeds
    uint256 public minSources;
    uint256 public maxDeviation;     // basis points

    constructor(address[] memory feeds, uint256 minSrc, uint256 dev) {
        sources = feeds;
        minSources = minSrc;
        maxDeviation = dev;
    }

    // SAFE: reads from multiple sources, takes median, rejects outliers
    function getPrice() public view returns (uint256) {
        uint256[] memory prices = new uint256[](sources.length);
        for (uint256 i = 0; i < sources.length; i++) {
            prices[i] = readFeed(sources[i]);
        }

        require(
            sources.length >= minSources,
            "insufficient sources"
        );

        // Sort and take median
        sort(prices);
        uint256 median = prices[prices.length / 2];

        // Reject outliers: each source must be within maxDeviation of median
        for (uint256 i = 0; i < prices.length; i++) {
            uint256 deviation = absDiff(prices[i], median) * 10000 / median;
            require(deviation <= maxDeviation, "outlier rejected");
        }

        return median;
    }

    function readFeed(address) internal view returns (uint256);
    function sort(uint256[] memory arr) internal pure;
    function absDiff(uint256 a, uint256 b) internal pure returns (uint256);
}
