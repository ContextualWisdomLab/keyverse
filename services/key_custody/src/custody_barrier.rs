//! Test-first scaffold for the independent custody barrier. Never a release.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Initialization is unavailable until the cryptographic implementation lands.
#[derive(Debug)]
pub struct CustodyUnavailable;

/// Internal custody barrier, not a network authentication endpoint.
pub struct CustodyBarrier;

impl CustodyBarrier {
    /// Initialize a sealed custody barrier without a remote identity service.
    pub fn initialize(
        _required_shares: u8,
        _total_shares: u8,
    ) -> Result<Self, CustodyUnavailable> {
        Err(CustodyUnavailable)
    }
}
