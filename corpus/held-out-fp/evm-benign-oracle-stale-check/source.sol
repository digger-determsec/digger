// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OracleStaleCheck {
    struct PriceData {
        uint256 price;
        uint256 timestamp;
    }

    PriceData public latestPrice;
    uint256 public constant STALENESS_THRESHOLD = 3600;

    function updatePrice(uint256 _price) external {
        latestPrice = PriceData(_price, block.timestamp);
    }

    function getStablePrice() public view returns (uint256) {
        require(
            block.timestamp - latestPrice.timestamp <= STALENESS_THRESHOLD,
            "Price oracle stale"
        );
        return latestPrice.price;
    }
}
