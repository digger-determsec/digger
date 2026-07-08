// SAFE: getTWAP with proper long window and observation count.
// The TWAP source IS detected by name (getTWAP), but the resistance is
// genuinely present: minimum observations enforced, sufficient time delta.
// This contract uses the TWAP to price collateral for borrowing.
contract SafeLongWindowTWAPOracle {
    address public pool;
    uint256 public immutable minObservations;
    uint256 public immutable minTimeDelta;  // e.g., 1800s = 30 minutes

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    function getPrice() public view returns (uint256) {
        uint256 observationCount = getObservationCount(pool);
        require(observationCount >= minObservations, "insufficient observations");

        uint256 timeDelta = getTimeDelta(pool);
        require(timeDelta >= minTimeDelta, "time window too short");

        return getTWAP(pool, minObservations);
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 value = collateral[msg.sender] * price / 1e18;
        require(value >= amount, "undercollateralized");
        borrowed[msg.sender] += amount;
    }

    function getTWAP(
        address pool_,
        uint256 observations_
    ) internal view returns (uint256);
    function getObservationCount(address pool_) internal view returns (uint256);
    function getTimeDelta(address pool_) internal view returns (uint256);
}
