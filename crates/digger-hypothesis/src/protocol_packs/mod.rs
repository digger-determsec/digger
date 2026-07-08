pub mod aave;
pub mod compound;
pub mod eigenlayer;
pub mod erc4626;
pub mod lido;
pub mod morpho;
/// Protocol Semantic Packs.
///
/// Each pack encodes protocol-specific security knowledge:
/// - Protocol invariants
/// - Accounting rules
/// - Lifecycle phases
/// - Trust boundaries
/// - Privileged actors
/// - Protocol-specific attack surfaces
/// - Common exploit patterns
///
/// All packs are deterministic and evidence-backed.
pub mod pack;
pub mod uniswap;

pub use pack::ProtocolPack;
