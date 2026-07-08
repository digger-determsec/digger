// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// VULN: unchecked overflow — multiplication inside unchecked{} can silently wrap.
/// The attacker can supply values that overflow, silently producing a smaller result.
contract UncheckedOverflowVuln {
    mapping(address => uint256) public balances;

    function calculateReward(uint256 shares, uint256 rate) public view returns (uint256) {
        uint256 reward;
        unchecked {
            // BUG: shares * rate can overflow silently — no compiler check
            reward = shares * rate;
        }
        return reward;
    }
}
