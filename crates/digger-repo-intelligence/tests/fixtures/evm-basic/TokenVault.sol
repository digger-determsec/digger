// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TokenVault {
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner());
        _;
    }

    function owner() public view returns (address) {
        return address(0x1);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }

    function getOraclePrice() external view returns (uint256) {
        return 1000;
    }

    event Deposit(address indexed user, uint256 amount);
}
