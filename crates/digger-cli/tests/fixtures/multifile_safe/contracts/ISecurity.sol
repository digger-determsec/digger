// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ISecurity {
    function check(address) external returns (bool);
}
