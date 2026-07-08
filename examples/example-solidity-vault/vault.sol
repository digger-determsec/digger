// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vulnerable Vault — Digger Test Example
/// @notice Intentionally vulnerable for demonstration

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    bool public paused;

    constructor() {
        owner = msg.sender;
        paused = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    function deposit() public payable whenNotPaused {
        balances[msg.sender] += msg.value;
    }

    // BUG: Reentrancy — external call before state update
    function withdraw(uint256 amount) public whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    // BUG: Missing authority — anyone can set owner
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // BUG: Missing authority — anyone can drain
    function emergencyDrain() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function unpause() public onlyOwner {
        paused = false;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
