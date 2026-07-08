// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Modifiers test — exercises modifier definitions and associations

contract Governance {
    address public admin;
    uint256 public proposalCount;

    mapping(uint256 => Proposal) public proposals;

    struct Proposal {
        address proposer;
        string description;
        uint256 votes;
        bool executed;
    }

    event ProposalCreated(uint256 indexed id, address indexed proposer);
    event ProposalExecuted(uint256 indexed id);

    error NotAdmin();
    error ProposalAlreadyExecuted(uint256 id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier proposalExists(uint256 id) {
        require(id < proposalCount, "Proposal not found");
        _;
    }

    modifier notExecuted(uint256 id) {
        require(!proposals[id].executed, "Already executed");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createProposal(string calldata description) external {
        proposals[proposalCount] = Proposal({
            proposer: msg.sender,
            description: description,
            votes: 0,
            executed: false
        });
        emit ProposalCreated(proposalCount, msg.sender);
        proposalCount++;
    }

    function vote(uint256 id) external proposalExists(id) notExecuted(id) {
        proposals[id].votes++;
    }

    function execute(uint256 id) external onlyAdmin proposalExists(id) notExecuted(id) {
        proposals[id].executed = true;
        emit ProposalExecuted(id);
    }
}
