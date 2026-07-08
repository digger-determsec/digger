// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract BrokenContract {
    function doStuff() external {
        // This import cannot be resolved -- lib/openzeppelin-contracts/ does not exist
    }
}
