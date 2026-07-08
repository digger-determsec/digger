// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Simple Multisig — Digger Test Example
/// @notice Multi-signature wallet with intentional issues

contract SimpleMultisig {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public required;

    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 confirmations;
    }

    Transaction[] public transactions;
    mapping(uint256 => mapping(address => bool)) public confirmed;

    event TransactionSubmitted(uint256 indexed txId);
    event TransactionConfirmed(uint256 indexed txId, address indexed owner);
    event TransactionExecuted(uint256 indexed txId);

    constructor(address[] memory _owners, uint256 _required) {
        require(_owners.length > 0, "No owners");
        require(_required > 0 && _required <= _owners.length, "Invalid required");

        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "Zero address");
            require(!isOwner[owner], "Duplicate owner");

            isOwner[owner] = true;
            owners.push(owner);
        }
        required = _required;
    }

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not owner");
        _;
    }

    function submitTransaction(address _to, uint256 _value, bytes memory _data) public onlyOwner {
        uint256 txId = transactions.length;
        transactions.push(Transaction({
            to: _to,
            value: _value,
            data: _data,
            executed: false,
            confirmations: 0
        }));
        emit TransactionSubmitted(txId);
    }

    function confirmTransaction(uint256 _txId) public onlyOwner {
        require(_txId < transactions.length, "Invalid tx");
        require(!confirmed[_txId][msg.sender], "Already confirmed");

        Transaction storage transaction = transactions[_txId];
        transaction.confirmations += 1;
        confirmed[_txId][msg.sender] = true;

        emit TransactionConfirmed(_txId, msg.sender);
    }

    // BUG: Anyone can execute after enough confirmations (no owner check on execute)
    function executeTransaction(uint256 _txId) public {
        require(_txId < transactions.length, "Invalid tx");

        Transaction storage transaction = transactions[_txId];
        require(transaction.confirmations >= required, "Not enough confirmations");
        require(!transaction.executed, "Already executed");

        transaction.executed = true;
        (bool success, ) = transaction.to.call{value: transaction.value}(transaction.data);
        require(success, "Execution failed");

        emit TransactionExecuted(_txId);
    }

    // BUG: Missing authority — anyone can add owners
    function addOwner(address _owner) public {
        require(!isOwner[_owner], "Already owner");
        require(_owner != address(0), "Zero address");
        isOwner[_owner] = true;
        owners.push(_owner);
    }

    // BUG: Missing authority — anyone can change threshold
    function changeRequirement(uint256 _required) public {
        require(_required > 0 && _required <= owners.length, "Invalid required");
        required = _required;
    }

    function getTransactionCount() public view returns (uint256) {
        return transactions.length;
    }

    function getOwners() public view returns (address[] memory) {
        return owners;
    }
}
