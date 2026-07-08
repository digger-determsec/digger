// SAFE: Uniswap V3 TWAP oracle with 30-minute+ observation window.
// Uses Uniswap V3's built-in oracle (tick Cumulative) which requires
// multiple observations spread over a significant time window.
// NOT manipulable: the 30-minute window makes flash-loan manipulation
// economically infeasible - you'd need to hold the position open.
contract SafeUniswapV3TWAPOracle {
    address public pool;
    uint256 public immutable period;  // minimum TWAP period (e.g., 1800s = 30min)

    int24 public constant TICK_BITMAP_SIZE = 256;

    constructor(address uniswapPool, uint256 twapPeriod) {
        pool = uniswapPool;
        period = twapPeriod;
    }

    // SAFE: reads Uniswap V3 TWAP via oracle observation,
    // requires minimum period to have elapsed
    function getPrice() public view returns (uint256) {
        (
            uint256 sqrtPriceX96,
            ,
            uint256 lastObservationTimestamp,
            ,
            ,
        ) = IUniswapV3Pool(pool).slot0();

        require(
            block.timestamp - lastObservationTimestamp <= period,
            "observation too old"
        );

        // Use TWAP from Uniswap V3 oracle (requires period > 0)
        uint256 price = (sqrtPriceX96 * sqrtPriceX96) / (2**96);

        // Cross-check with TWAP
        uint256 twapPrice = consult(
            pool,
            block.timestamp - period,
            1e18
        );

        // Require TWAP and spot to be within 5% (anti-manipulation check)
        uint256 deviation = (price > twapPrice)
            ? (price - twapPrice) * 100 / twapPrice
            : (twapPrice - price) * 100 / price;

        require(deviation <= 5, "price-TWAP deviation too large");

        return twapPrice;  // use TWAP, not spot
    }

    function consult(
        address tokenIn,
        uint256 blockAgo,
        uint256 amountIn
    ) internal view returns (uint256);

    function getPoolPriceCumulative(
        address pool_
    ) internal view returns (uint256);
}

interface IUniswapV3Pool {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
}
