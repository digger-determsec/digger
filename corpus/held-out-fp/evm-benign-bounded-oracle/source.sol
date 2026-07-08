// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BoundedOracle {
    uint256 public lastPrice;
    uint256 public constant MAX_DEVIATION_BPS = 500;
    uint256 public constant BPS_DENOMINATOR = 10000;

    function updatePrice(uint256 newPrice) external {
        if (lastPrice > 0) {
            uint256 diff = newPrice > lastPrice
                ? newPrice - lastPrice
                : lastPrice - newPrice;
            require(
                diff * BPS_DENOMINATOR / lastPrice <= MAX_DEVIATION_BPS,
                "Price deviation too large"
            );
        }
        lastPrice = newPrice;
    }
}
