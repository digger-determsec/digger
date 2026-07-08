// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).call{value: amount}("");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
