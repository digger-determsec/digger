// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Vault {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function deposit(uint256 amount) external {
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }
}
