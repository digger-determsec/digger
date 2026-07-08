// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vulnerable Vault — DO NOT DEPLOY
/// @notice Intentionally vulnerable for Digger testing
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // BUG: Reentrancy — external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;  // State update AFTER external call
    }

    // BUG: Missing authority — anyone can set owner
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // BUG: Missing authority — anyone can drain
    function emergencyDrain() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
