//! The owner can initialize its root without dotenv, Keycloak, DB, or another KMS.
use keyverse_custody::CustodyBarrier;

#[test]
fn initializes_without_external_secret_authority() {
    assert!(
        CustodyBarrier::initialize(2, 3).is_ok(),
        "independent root initialization is not implemented"
    );
}
