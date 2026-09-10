//! Internal Keyverse custody barrier; no network, credential file or remote KMS.
//!
//! This primitive requires a trusted in-process caller. Associated context is
//! cryptographic binding, not workload authentication or access authorization.
//! Durable audit, enrollment, persistence and rollback protection are separate
//! release gates. The wrapping root deliberately has no export API.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sharks::{Share, Sharks};
use zeroize::Zeroizing;

const ROOT_HEADER_BYTES: usize = 22;
const ROOT_RECORD_BYTES: usize = 94;
const SHARE_RECORD_BYTES: usize = 55;
const DATA_HEADER_BYTES: usize = 20;
const NONCE_BYTES: usize = 24;
const AUTH_TAG_BYTES: usize = 16;
const MAX_RECORD_BYTES: usize = 1_048_576;
const MAX_CONTEXT_BYTES: usize = 128;
const MAX_RECOVERY_SHARES: u8 = 16;

/// Value-free errors; none contains supplied material or an upstream diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyError {
    /// A bounded record, context or quorum is malformed.
    InvalidInput,
    /// Operating-system entropy was unavailable; there is no substitute source.
    EntropyUnavailable,
    /// The wrapping root is not present in memory.
    BarrierSealed,
    /// Unseal cannot replace an already-open root.
    AlreadyUnsealed,
    /// Shares, context or ciphertext did not authenticate.
    AuthenticationFailed,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, format_buffer: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_message = match self {
            Self::InvalidInput => "invalid custody input",
            Self::EntropyUnavailable => "custody entropy unavailable",
            Self::BarrierSealed => "custody is sealed",
            Self::AlreadyUnsealed => "custody is already unsealed",
            Self::AuthenticationFailed => "custody authentication failed",
        };
        format_buffer.write_str(error_message)
    }
}

impl std::error::Error for CustodyError {}

/// Zeroizing plaintext with deliberate exposure and a nonreflective Debug form.
///
/// This wrapper does not guarantee erasure of registers, swap, caller copies,
/// crash dumps or third-party implementation temporaries.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Borrow plaintext only at its explicitly authorized consumption boundary.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, format_buffer: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_buffer.write_str("SecretBytes([REDACTED])")
    }
}

/// One custodian's recovery material, never automatically logged or serialized.
pub struct RecoveryShare(SecretBytes);

impl RecoveryShare {
    /// Validate a bounded custodian envelope without asserting its authenticity.
    pub fn from_custodian_bytes(encoded_share: &[u8]) -> Result<Self, CustodyError> {
        if encoded_share.len() != SHARE_RECORD_BYTES || &encoded_share[..4] != b"KVS1" {
            return Err(CustodyError::InvalidInput);
        }
        validate_quorum(encoded_share[4], encoded_share[5])?;
        if encoded_share[22] == 0 || encoded_share[22] > encoded_share[5] {
            return Err(CustodyError::InvalidInput);
        }
        Ok(Self(SecretBytes(Zeroizing::new(encoded_share.to_vec()))))
    }

    /// Explicitly copy this one share for a protected custodian delivery channel.
    ///
    /// Never store all returned shares with the root record. Authenticated
    /// custodian enrollment and transport must be implemented by the service.
    pub fn export_for_custodian(&self) -> SecretBytes {
        SecretBytes(Zeroizing::new(self.0.expose_secret().to_vec()))
    }
}

impl fmt::Debug for RecoveryShare {
    fn fmt(&self, format_buffer: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_buffer.write_str("RecoveryShare([REDACTED])")
    }
}

/// Exact tenant/environment/namespace/key/version/purpose binding for one record.
///
/// Constructing a context is not authorization. A remote adapter must verify
/// its caller and policy independently before invoking the internal barrier.
pub struct RecordContext {
    encoded_fields: Vec<u8>,
}

impl RecordContext {
    /// Validate and length-frame six identifiers without normalizing their bytes.
    pub fn new(context_fields: [&str; 6]) -> Result<Self, CustodyError> {
        let mut encoded_fields = Vec::new();
        for context_field in context_fields {
            if context_field.is_empty()
                || context_field.len() > MAX_CONTEXT_BYTES
                || context_field.chars().any(|input_char| input_char.is_control() || input_char.is_whitespace())
            {
                return Err(CustodyError::InvalidInput);
            }
            encoded_fields.extend_from_slice(&(context_field.len() as u16).to_be_bytes());
            encoded_fields.extend_from_slice(context_field.as_bytes());
        }
        Ok(Self { encoded_fields })
    }

    fn associated_data(&self, record_header: &[u8]) -> Vec<u8> {
        let mut associated_data = b"keyverse_custody_record_v1".to_vec();
        associated_data.extend_from_slice(record_header);
        associated_data.extend_from_slice(&self.encoded_fields);
        associated_data
    }
}

impl fmt::Debug for RecordContext {
    fn fmt(&self, format_buffer: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_buffer.write_str("RecordContext([REDACTED])")
    }
}

/// Independently recoverable, sealed-by-default wrapping-root custody.
///
/// The encrypted record is exportable; the unsealed root is not. This is an
/// internal library, not a complete KMS service or a persistence transaction.
pub struct CustodyBarrier {
    sealed_record: [u8; ROOT_RECORD_BYTES],
    root_key: Option<SecretBytes>,
}

impl CustodyBarrier {
    /// Generate an independent root and separate quorum shares, returning sealed.
    pub fn initialize_custody(
        required_shares: u8,
        total_shares: u8,
    ) -> Result<(Self, Vec<RecoveryShare>), CustodyError> {
        Self::initialize_with_entropy(required_shares, total_shares, &SystemEntropy)
    }

    fn initialize_with_entropy(
        required_shares: u8,
        total_shares: u8,
        entropy_source: &impl EntropySource,
    ) -> Result<(Self, Vec<RecoveryShare>), CustodyError> {
        validate_quorum(required_shares, total_shares)?;
        let mut root_key = Zeroizing::new(vec![0u8; 32]);
        let mut recovery_key = Zeroizing::new(vec![0u8; 32]);
        let mut dealer_seed = Zeroizing::new([0u8; 32]);
        entropy_source.fill_bytes(&mut root_key)?;
        entropy_source.fill_bytes(&mut recovery_key)?;
        entropy_source.fill_bytes(&mut dealer_seed[..])?;
        let mut sealed_record = [0u8; ROOT_RECORD_BYTES];
        sealed_record[..4].copy_from_slice(b"KVC1");
        sealed_record[4] = required_shares;
        sealed_record[5] = total_shares;
        entropy_source.fill_bytes(&mut sealed_record[6..ROOT_HEADER_BYTES])?;
        let mut root_nonce = [0u8; NONCE_BYTES];
        entropy_source.fill_bytes(&mut root_nonce)?;
        let wrapped_root = encrypt_payload(
            &recovery_key, &root_nonce, &sealed_record[..ROOT_HEADER_BYTES], &root_key,
        )?;
        sealed_record[ROOT_HEADER_BYTES..ROOT_HEADER_BYTES + NONCE_BYTES]
            .copy_from_slice(&root_nonce);
        sealed_record[ROOT_HEADER_BYTES + NONCE_BYTES..].copy_from_slice(&wrapped_root);
        // sharks uses the rand-0.8 trait family. This independently OS-seeded
        // ChaCha20 generator supplies that compatibility boundary only.
        let mut dealer_random = ChaCha20Rng::from_seed(*dealer_seed);
        let share_dealer = Sharks(required_shares);
        let mut custodian_shares = Vec::with_capacity(usize::from(total_shares));
        for raw_share in share_dealer.dealer_rng(&recovery_key, &mut dealer_random)
            .take(usize::from(total_shares))
        {
            let encoded_share = Zeroizing::new(Vec::from(&raw_share));
            let mut custodian_record = Zeroizing::new(Vec::with_capacity(SHARE_RECORD_BYTES));
            custodian_record.extend_from_slice(b"KVS1");
            custodian_record.extend_from_slice(&sealed_record[4..ROOT_HEADER_BYTES]);
            custodian_record.extend_from_slice(&encoded_share);
            custodian_shares.push(RecoveryShare(SecretBytes(custodian_record)));
        }
        Ok((Self { sealed_record, root_key: None }, custodian_shares))
    }

    /// Parse only the bounded public envelope; authentication occurs on unseal.
    pub fn from_sealed_record(encoded_record: &[u8]) -> Result<Self, CustodyError> {
        if encoded_record.len() != ROOT_RECORD_BYTES || &encoded_record[..4] != b"KVC1" {
            return Err(CustodyError::InvalidInput);
        }
        validate_quorum(encoded_record[4], encoded_record[5])?;
        let mut sealed_record = [0u8; ROOT_RECORD_BYTES];
        sealed_record.copy_from_slice(encoded_record);
        Ok(Self { sealed_record, root_key: None })
    }

    /// Export encrypted root state, never recovery shares or plaintext root bytes.
    pub fn export_sealed_record(&self) -> Vec<u8> {
        self.sealed_record.to_vec()
    }

    /// Report local root availability, not remote authorization or readiness.
    pub fn is_sealed(&self) -> bool {
        self.root_key.is_none()
    }

    /// Authenticate a complete, distinct quorum before installing any root state.
    pub fn unseal_custody(&mut self, recovery_shares: &[RecoveryShare]) -> Result<(), CustodyError> {
        if self.root_key.is_some() {
            return Err(CustodyError::AlreadyUnsealed);
        }
        let required_shares = self.sealed_record[4];
        let total_shares = self.sealed_record[5];
        if recovery_shares.len() < usize::from(required_shares)
            || recovery_shares.len() > usize::from(total_shares)
        {
            return Err(CustodyError::AuthenticationFailed);
        }
        let mut seen_indices = [false; 256];
        let mut parsed_shares = Vec::with_capacity(recovery_shares.len());
        for recovery_share in recovery_shares {
            let encoded_share = recovery_share.0.expose_secret();
            let share_index = usize::from(encoded_share[22]);
            if encoded_share[4..ROOT_HEADER_BYTES] != self.sealed_record[4..ROOT_HEADER_BYTES]
                || seen_indices[share_index]
            {
                return Err(CustodyError::AuthenticationFailed);
            }
            seen_indices[share_index] = true;
            parsed_shares.push(Share::try_from(&encoded_share[ROOT_HEADER_BYTES..])
                .map_err(|_| CustodyError::AuthenticationFailed)?);
        }
        let recovery_key = Zeroizing::new(Sharks(required_shares).recover(&parsed_shares)
            .map_err(|_| CustodyError::AuthenticationFailed)?);
        let mut root_nonce = [0u8; NONCE_BYTES];
        root_nonce.copy_from_slice(&self.sealed_record[ROOT_HEADER_BYTES..ROOT_HEADER_BYTES + NONCE_BYTES]);
        let recovered_root = decrypt_payload(
            &recovery_key, &root_nonce, &self.sealed_record[..ROOT_HEADER_BYTES],
            &self.sealed_record[ROOT_HEADER_BYTES + NONCE_BYTES..],
        )?;
        self.root_key = Some(recovered_root);
        Ok(())
    }

    /// Idempotently drop the locally held root; recovery still requires a quorum.
    pub fn seal_custody(&mut self) {
        self.root_key = None;
    }

    /// Protect one bounded internal record with its exact associated context.
    pub fn protect_record(
        &self, record_context: &RecordContext, plain_bytes: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        self.protect_with_entropy(record_context, plain_bytes, &SystemEntropy)
    }

    fn protect_with_entropy(
        &self, record_context: &RecordContext, plain_bytes: &[u8], entropy_source: &impl EntropySource,
    ) -> Result<Vec<u8>, CustodyError> {
        let root_key = self.root_key.as_ref().ok_or(CustodyError::BarrierSealed)?;
        if plain_bytes.len() > MAX_RECORD_BYTES {
            return Err(CustodyError::InvalidInput);
        }
        let mut record_header = b"KVD1".to_vec();
        record_header.extend_from_slice(&self.sealed_record[6..ROOT_HEADER_BYTES]);
        let mut record_nonce = [0u8; NONCE_BYTES];
        entropy_source.fill_bytes(&mut record_nonce)?;
        let protected_body = encrypt_payload(
            root_key.expose_secret(), &record_nonce,
            &record_context.associated_data(&record_header), plain_bytes,
        )?;
        record_header.extend_from_slice(&record_nonce);
        record_header.extend_from_slice(&protected_body);
        Ok(record_header)
    }

    /// Authenticate context, instance and ciphertext before exposing plaintext.
    pub fn open_record(
        &self, record_context: &RecordContext, protected_record: &[u8],
    ) -> Result<SecretBytes, CustodyError> {
        let root_key = self.root_key.as_ref().ok_or(CustodyError::BarrierSealed)?;
        let minimum_size = DATA_HEADER_BYTES + NONCE_BYTES + AUTH_TAG_BYTES;
        if !(minimum_size..=minimum_size + MAX_RECORD_BYTES).contains(&protected_record.len())
            || &protected_record[..4] != b"KVD1"
            || protected_record[4..DATA_HEADER_BYTES] != self.sealed_record[6..ROOT_HEADER_BYTES]
        {
            return Err(CustodyError::AuthenticationFailed);
        }
        let mut record_nonce = [0u8; NONCE_BYTES];
        record_nonce.copy_from_slice(&protected_record[DATA_HEADER_BYTES..DATA_HEADER_BYTES + NONCE_BYTES]);
        decrypt_payload(
            root_key.expose_secret(), &record_nonce,
            &record_context.associated_data(&protected_record[..DATA_HEADER_BYTES]),
            &protected_record[DATA_HEADER_BYTES + NONCE_BYTES..],
        )
    }
}

impl fmt::Debug for CustodyBarrier {
    fn fmt(&self, format_buffer: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_buffer.debug_struct("CustodyBarrier")
            .field("sealed", &self.is_sealed()).finish_non_exhaustive()
    }
}

fn validate_quorum(required_shares: u8, total_shares: u8) -> Result<(), CustodyError> {
    if required_shares < 2 || required_shares > total_shares || total_shares > MAX_RECOVERY_SHARES {
        return Err(CustodyError::InvalidInput);
    }
    Ok(())
}

trait EntropySource {
    fn fill_bytes(&self, output_bytes: &mut [u8]) -> Result<(), CustodyError>;
}

struct SystemEntropy;

impl EntropySource for SystemEntropy {
    fn fill_bytes(&self, output_bytes: &mut [u8]) -> Result<(), CustodyError> {
        getrandom::fill(output_bytes).map_err(|_| CustodyError::EntropyUnavailable)
    }
}

fn encrypt_payload(
    secret_key: &[u8], nonce_bytes: &[u8; NONCE_BYTES], associated_data: &[u8], plain_bytes: &[u8],
) -> Result<Vec<u8>, CustodyError> {
    let record_cipher = XChaCha20Poly1305::new_from_slice(secret_key)
        .map_err(|_| CustodyError::AuthenticationFailed)?;
    let mut protected_buffer = Zeroizing::new(Vec::with_capacity(plain_bytes.len() + AUTH_TAG_BYTES));
    protected_buffer.extend_from_slice(plain_bytes);
    record_cipher.encrypt_in_place(&XNonce::from(*nonce_bytes), associated_data, &mut *protected_buffer)
        .map_err(|_| CustodyError::AuthenticationFailed)?;
    Ok(protected_buffer.to_vec())
}

fn decrypt_payload(
    secret_key: &[u8], nonce_bytes: &[u8; NONCE_BYTES], associated_data: &[u8], cipher_bytes: &[u8],
) -> Result<SecretBytes, CustodyError> {
    let record_cipher = XChaCha20Poly1305::new_from_slice(secret_key)
        .map_err(|_| CustodyError::AuthenticationFailed)?;
    let mut protected_buffer = Zeroizing::new(cipher_bytes.to_vec());
    // Even an authentication failure drops a zeroizing buffer, not an ordinary
    // Vec that might contain partially transformed sensitive data.
    record_cipher.decrypt_in_place(&XNonce::from(*nonce_bytes), associated_data, &mut *protected_buffer)
        .map_err(|_| CustodyError::AuthenticationFailed)?;
    Ok(SecretBytes(protected_buffer))
}

#[cfg(test)]
mod failure_contracts {
    use super::*;

    struct FailedEntropy;

    impl EntropySource for FailedEntropy {
        fn fill_bytes(&self, _: &mut [u8]) -> Result<(), CustodyError> {
            Err(CustodyError::EntropyUnavailable)
        }
    }

    #[test]
    fn failed_entropy_never_creates_fallback_keys_or_nonces() {
        assert!(matches!(CustodyBarrier::initialize_with_entropy(2, 3, &FailedEntropy), Err(CustodyError::EntropyUnavailable)));
        let (mut custody, shares) = CustodyBarrier::initialize_custody(2, 3).unwrap();
        custody.unseal_custody(&shares[..2]).unwrap();
        let context = RecordContext::new(["tenant", "env", "namespace", "key", "version", "purpose"]).unwrap();
        assert!(matches!(custody.protect_with_entropy(&context, b"test", &FailedEntropy), Err(CustodyError::EntropyUnavailable)));
    }

    #[test]
    fn errors_are_nonreflective_and_invalid_key_lengths_fail() {
        for (error, text) in [
            (CustodyError::InvalidInput, "invalid custody input"),
            (CustodyError::EntropyUnavailable, "custody entropy unavailable"),
            (CustodyError::BarrierSealed, "custody is sealed"),
            (CustodyError::AlreadyUnsealed, "custody is already unsealed"),
            (CustodyError::AuthenticationFailed, "custody authentication failed"),
        ] {
            assert_eq!(error.to_string(), text);
        }
        assert!(encrypt_payload(b"bad", &[0; 24], b"", b"").is_err());
        assert!(decrypt_payload(b"bad", &[0; 24], b"", b"").is_err());
    }
}
