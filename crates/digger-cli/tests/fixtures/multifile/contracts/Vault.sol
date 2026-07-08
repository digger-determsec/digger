// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IERC20.sol";

contract ReadReentrancyVault {
    mapping(address => uint256) public reserves;
    uint256 public price;

    function swap(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        uint256 currentPrice = price;
        uint256 output = (amount * currentPrice) / 1e18;
        reserves[token] += amount;
    }

    function setPrice(uint256 newPrice) external {
        price = newPrice;
    }
}
