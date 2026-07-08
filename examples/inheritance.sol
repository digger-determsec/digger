// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Inheritance test — exercises base contracts, override, virtual

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

abstract contract ERC20Base is IERC20 {
    mapping(address => uint256) internal _balances;
    uint256 internal _totalSupply;

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual returns (uint256) {
        return _balances[account];
    }
}

contract MyToken is ERC20Base {
    address public owner;

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        _totalSupply = initialSupply;
        _balances[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        require(_balances[msg.sender] >= amount, "Insufficient");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        return true;
    }
}
