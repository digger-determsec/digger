// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vulnerable Vault — DO NOT DEPLOY
/// @notice Multiple vulnerability patterns for Digger testing
contract VulnerableVault {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    address public owner;
    address public pendingOwner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: Missing authority — anyone can deposit
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

    // BUG: Unchecked arithmetic (pre-0.8 would overflow)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;  // Safe in 0.8+, but pattern is risky
    }

    // BUG: Delegatecall to user-controlled address
    function execute(address target, bytes memory data) public returns (bytes memory) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success);
        return result;
    }

    // BUG: Missing approval check
    function transferFrom(address from, address to, uint256 amount) public {
        require(balances[from] >= amount);
        balances[from] -= amount;
        balances[to] += amount;
        // Missing: require(allowances[from][msg.sender] >= amount)
    }
}
