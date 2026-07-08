// SAFE: TWAP oracle over N blocks with minimum observation window.
// NOT manipulable: the time-weighted average smooths out single-block
// price manipulations. The minimum window (e.g., 30 minutes) ensures
// no single transaction can dominate the average.
contract SafeTWAPOracle {
    address public pool;
    uint256 public immutable minObservations;
    uint256 public immutable windowSize;

    struct Observation {
        uint256 timestamp;
        uint256 priceCumulative;
    }

    Observation[] public observations;

    constructor(address uniswapPool, uint256 minObs, uint256 window) {
        pool = uniswapPool;
        minObservations = minObs;
        windowSize = window;
    }

    function record() external {
        observations.push(
            Observation({
                timestamp: block.timestamp,
                priceCumulative: getPoolPriceCumulative(pool)
            })
        );
    }

    // SAFE: TWAP with long window - single-block manipulation diluted
    function getPrice() public view returns (uint256) {
        require(
            observations.length >= minObservations,
            "insufficient observations"
        );

        Observation memory first = observations[
            observations.length - minObservations
        ];
        Observation memory last = observations[observations.length - 1];

        uint256 timeDelta = last.timestamp - first.timestamp;
        require(timeDelta >= windowSize, "window too short");

        uint256 priceCumDelta = last.priceCumulative
            - first.priceCumulative;

        return priceCumDelta / timeDelta;
    }

    function getPoolPriceCumulative(
        address pool_
    ) internal view returns (uint256);
}
