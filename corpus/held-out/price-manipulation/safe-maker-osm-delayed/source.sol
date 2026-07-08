// SAFE: MakerDAO OSM-like oracle using priceCumulative with observation window.
// The price read IS detected (priceCumulative), and the resistance IS recognized
// (observations.length + timeDelta checks).
contract SafeMakerDelayedOracle {
    address public pool;
    uint256 public immutable minObservations;
    uint256 public immutable minTimeDelta;

    struct Observation {
        uint256 timestamp;
        uint256 priceCumulative;
    }
    Observation[] public observations;

    function getPrice() public view returns (uint256) {
        require(observations.length >= minObservations, "insufficient observations");

        Observation memory first = observations[observations.length - minObservations];
        Observation memory last = observations[observations.length - 1];

        uint256 timeDelta = last.timestamp - first.timestamp;
        require(timeDelta >= minTimeDelta, "time window too short");

        uint256 priceCumDelta = last.priceCumulative - first.priceCumulative;
        return priceCumDelta / timeDelta;
    }

    function record() external {
        observations.push(
            Observation({
                timestamp: block.timestamp,
                priceCumulative: getPoolPriceCumulative(pool)
            })
        );
    }

    function getPoolPriceCumulative(
        address pool_
    ) internal view returns (uint256);
}
