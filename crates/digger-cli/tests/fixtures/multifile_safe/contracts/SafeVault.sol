// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ISecurity.sol";

contract SafeVault {
    uint256 private _locked;

    modifier nonReentrant() {
        require(_locked == 0, "reentrant");
        _locked = 1;
        _;
        _locked = 0;
    }

    function withdraw() external nonReentrant {
        uint256 bal = address(this).balance;
        payable(msg.sender).transfer(bal);
    }
}
