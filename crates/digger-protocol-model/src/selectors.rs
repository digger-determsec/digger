//! Well-known DETERMINISTIC function selectors (EVM 4-byte). These are public,
//! standardized selectors (the keccak prefix of a fixed canonical signature) --
//! FACTS about an interface, not heuristic guesses. Matching a selector that a
//! contract demonstrably dispatches is an observation, never an inference about
//! intent. Selectors are one-way hashes, so we never fabricate a human name;
//! we only recognize standardized signatures.

// --- Upgrade ---
pub const UPGRADE_TO: &str = "0x3659cfe6"; // upgradeTo(address)
pub const UPGRADE_TO_AND_CALL: &str = "0x4f1ef286"; // upgradeToAndCall(address,bytes)

// --- Mint / Burn (supply) ---
pub const MINT_ADDR_UINT: &str = "0x40c10f19"; // mint(address,uint256)
pub const MINT_UINT: &str = "0xa0712d68"; // mint(uint256)
pub const BURN_UINT: &str = "0x42966c68"; // burn(uint256)
pub const BURN_ADDR_UINT: &str = "0x9dc29fac"; // burn(address,uint256)

// --- Pause / Unpause ---
pub const PAUSE: &str = "0x8456cb59"; // pause()
pub const UNPAUSE: &str = "0x3f4ba83a"; // unpause()

// --- Initialization ---
pub const INITIALIZE: &str = "0x8129fc1c"; // initialize()
pub const INITIALIZE_ADDR: &str = "0xc4d66de8"; // initialize(address)

// --- Flash loans (ERC-3156 + common) ---
pub const FLASH_LOAN_3156: &str = "0x5cffe9de"; // flashLoan(address,address,uint256,bytes)
pub const FLASH_LOAN_POOL: &str = "0xab9c4b5d"; // flashLoan(address,uint256,bytes)

// --- Governance ---
pub const PROPOSE: &str = "0xda95691a"; // propose(address[],uint256[],bytes[],string)
pub const CAST_VOTE: &str = "0x56781388"; // castVote(uint256,uint8)

// --- Treasury / asset movement ---
pub const WITHDRAW_UINT: &str = "0x2e1a7d4d"; // withdraw(uint256)
pub const WITHDRAW_ADDR: &str = "0x51cff8d9"; // withdraw(address)

/// True if `sel` (lower-case `0x`-prefixed hex) is any initializer selector.
pub fn is_initializer(sel: &str) -> bool {
    sel == INITIALIZE || sel == INITIALIZE_ADDR
}
