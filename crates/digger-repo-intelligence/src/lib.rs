#![forbid(unsafe_code)]

pub mod scan;
pub mod types;

pub use scan::scan_repo;
pub use types::*;
