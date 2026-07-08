// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Staking {
    mapping(address => uint256) public stakes;
    bool public paused;

    function withdraw(uint256 amount) external {
        require(!paused, "paused");
        require(stakes[msg.sender] >= amount, "insufficient stake");
        stakes[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function stake() external payable {
        stakes[msg.sender] += msg.value;
    }

    function pause() external {
        paused = true;
    }
}
