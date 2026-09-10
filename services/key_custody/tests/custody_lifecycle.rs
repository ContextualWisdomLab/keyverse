//! Behavioral contracts use only generated test keys; no deployment credentials.
use keyverse_custody::{CustodyBarrier, CustodyError, RecordContext, RecoveryShare};

fn record_context() -> RecordContext {
    RecordContext::new([
        "tenant_alpha", "production", "provider_credentials",
        "gateway_api_key", "version_1", "provider_request",
    ]).unwrap()
}

fn opened_barrier() -> (CustodyBarrier, Vec<RecoveryShare>) {
    let (mut custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    custody.unseal_custody(&shares[..2]).unwrap();
    (custody, shares)
}

#[test]
fn initializes_without_external_secret_authority() {
    let (custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    assert!(custody.is_sealed());
    assert_eq!(shares.len(), 3);
    assert_eq!(custody.export_sealed_record().len(), 94);
}

#[test]
fn rejects_invalid_quorum_before_initializing() {
    for (threshold, count) in [(0, 3), (1, 3), (3, 2), (2, 0), (2, 17)] {
        assert!(matches!(CustodyBarrier::initialize_custody(threshold, count), Err(CustodyError::InvalidInput)));
    }
}

#[test]
fn all_two_of_three_quorums_recover_the_same_instance() {
    let (custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    let snapshot = custody.export_sealed_record();
    for indices in [[0, 1], [0, 2], [1, 2]] {
        let selected: Vec<_> = indices.into_iter().map(|index| {
            RecoveryShare::from_custodian_bytes(shares[index].export_for_custodian().expose_secret()).unwrap()
        }).collect();
        let mut restored = CustodyBarrier::from_sealed_record(&snapshot).unwrap();
        restored.unseal_custody(&selected).unwrap();
        assert!(!restored.is_sealed());
    }
}

#[test]
fn insufficient_or_duplicate_shares_do_not_change_sealed_state() {
    let (mut custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    assert!(custody.unseal_custody(&shares[..1]).is_err());
    let duplicated = [
        RecoveryShare::from_custodian_bytes(shares[0].export_for_custodian().expose_secret()).unwrap(),
        RecoveryShare::from_custodian_bytes(shares[0].export_for_custodian().expose_secret()).unwrap(),
    ];
    assert!(custody.unseal_custody(&duplicated).is_err());
    assert!(custody.is_sealed());
    custody.unseal_custody(&shares[..2]).unwrap();
}

#[test]
fn foreign_shares_and_damaged_shares_never_unlock() {
    let (mut custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    let (_, foreign) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    assert!(custody.unseal_custody(&foreign[..2]).is_err());
    let mut changed = shares[0].export_for_custodian().expose_secret().to_vec();
    changed[54] ^= 1;
    let bad = RecoveryShare::from_custodian_bytes(&changed).unwrap();
    let good = RecoveryShare::from_custodian_bytes(shares[1].export_for_custodian().expose_secret()).unwrap();
    assert!(custody.unseal_custody(&[bad, good]).is_err());
    assert!(custody.is_sealed());
}

#[test]
fn tampered_root_record_never_installs_key_material() {
    let (custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    let original = custody.export_sealed_record();
    for offset in 0..original.len() {
        let mut damaged = original.clone();
        damaged[offset] ^= 1;
        if let Ok(mut restored) = CustodyBarrier::from_sealed_record(&damaged) {
            assert!(restored.unseal_custody(&shares[..2]).is_err(), "accepted mutation at {offset}");
            assert!(restored.is_sealed());
        }
    }
}

#[test]
fn malformed_root_records_and_shares_are_rejected() {
    for length in [0, 1, 54, 56, 93, 95, 4096] {
        assert!(CustodyBarrier::from_sealed_record(&vec![0; length]).is_err());
        assert!(RecoveryShare::from_custodian_bytes(&vec![0; length]).is_err());
    }
    let (_, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
    for index in [0, 4] {
        let mut malformed = shares[0].export_for_custodian().expose_secret().to_vec();
        malformed[22] = index;
        assert!(RecoveryShare::from_custodian_bytes(&malformed).is_err());
    }
}

#[test]
fn sealed_operations_fail_and_reseal_retains_recovery() {
    let (mut custody, shares) = opened_barrier();
    let context = record_context();
    let protected = custody.protect_record(&context, b"test-only provider credential").unwrap();
    custody.seal_custody();
    custody.seal_custody();
    assert!(matches!(custody.protect_record(&context, b"x"), Err(CustodyError::BarrierSealed)));
    assert!(matches!(custody.open_record(&context, &protected), Err(CustodyError::BarrierSealed)));
    custody.unseal_custody(&shares[..2]).unwrap();
    assert_eq!(custody.open_record(&context, &protected).unwrap().expose_secret(), b"test-only provider credential");
    assert!(matches!(custody.unseal_custody(&shares[..2]), Err(CustodyError::AlreadyUnsealed)));
}

#[test]
fn instance_and_every_context_dimension_are_authenticated() {
    let (custody, _) = opened_barrier();
    let (foreign, _) = opened_barrier();
    let context = record_context();
    let protected = custody.protect_record(&context, b"test-only credential").unwrap();
    assert!(foreign.open_record(&context, &protected).is_err());
    let original = ["tenant_alpha", "production", "provider_credentials", "gateway_api_key", "version_1", "provider_request"];
    for field_index in 0..6 {
        let mut fields = original;
        fields[field_index] = "wrong_context";
        assert!(custody.open_record(&RecordContext::new(fields).unwrap(), &protected).is_err());
    }
}

#[test]
fn context_encoding_has_no_concatenation_ambiguity() {
    let (custody, _) = opened_barrier();
    let first = RecordContext::new(["ab", "c", "namespace", "key_name", "version", "purpose"]).unwrap();
    let second = RecordContext::new(["a", "bc", "namespace", "key_name", "version", "purpose"]).unwrap();
    let protected = custody.protect_record(&first, b"value").unwrap();
    assert!(custody.open_record(&second, &protected).is_err());
}

#[test]
fn record_mutation_and_truncation_are_rejected() {
    let (custody, _) = opened_barrier();
    let context = record_context();
    let original = custody.protect_record(&context, b"non-production credential").unwrap();
    for offset in 0..original.len() {
        let mut damaged = original.clone();
        damaged[offset] ^= 1;
        assert!(custody.open_record(&context, &damaged).is_err());
    }
    for end in 0..original.len() {
        assert!(custody.open_record(&context, &original[..end]).is_err());
    }
}

#[test]
fn same_plaintext_uses_distinct_nonces_and_encrypted_records() {
    let (custody, _) = opened_barrier();
    let context = record_context();
    let first = custody.protect_record(&context, b"test value").unwrap();
    let second = custody.protect_record(&context, b"test value").unwrap();
    assert_ne!(&first[20..44], &second[20..44]);
    assert_ne!(first, second);
}

#[test]
fn reconstructed_barrier_starts_sealed_and_opens_existing_data() {
    let (custody, shares) = opened_barrier();
    let context = record_context();
    let value = custody.protect_record(&context, b"persisted test value").unwrap();
    let mut restored = CustodyBarrier::from_sealed_record(&custody.export_sealed_record()).unwrap();
    assert!(restored.is_sealed());
    restored.unseal_custody(&shares).unwrap();
    assert_eq!(restored.open_record(&context, &value).unwrap().expose_secret(), b"persisted test value");
}

#[test]
fn metadata_and_payload_limits_are_enforced() {
    for bad in ["", " ", "line\nbreak", "bad\0name"] {
        assert!(RecordContext::new([bad, "env", "ns", "key", "ver", "purpose"]).is_err());
    }
    let long = "a".repeat(129);
    assert!(RecordContext::new([&long, "env", "ns", "key", "ver", "purpose"]).is_err());
    let (custody, _) = opened_barrier();
    let context = record_context();
    let full = vec![0u8; 1_048_576];
    let encrypted = custody.protect_record(&context, &full).unwrap();
    assert_eq!(custody.open_record(&context, &encrypted).unwrap().expose_secret(), full);
    assert!(custody.protect_record(&context, &vec![0; 1_048_577]).is_err());
    assert!(custody.open_record(&context, &vec![0; 1_048_637]).is_err());
    let empty = custody.protect_record(&context, b"").unwrap();
    assert!(custody.open_record(&context, &empty).unwrap().expose_secret().is_empty());
}

#[test]
fn debug_output_never_displays_recovery_or_plaintext_material() {
    let (custody, shares) = opened_barrier();
    let context = record_context();
    let protected = custody.protect_record(&context, b"confidential-test-value").unwrap();
    let plaintext = custody.open_record(&context, &protected).unwrap();
    assert_eq!(format!("{plaintext:?}"), "SecretBytes([REDACTED])");
    assert_eq!(format!("{:?}", shares[0]), "RecoveryShare([REDACTED])");
    assert_eq!(format!("{context:?}"), "RecordContext([REDACTED])");
    assert!(!format!("{custody:?}").contains("confidential"));
}
