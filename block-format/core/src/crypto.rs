//! The two cryptographic primitives the read path needs: SHA-256 digests and
//! Ed25519 signature verification. Signing lives in the `authoring` crate.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Verify an Ed25519 signature, returning `true` only on a strictly-valid
/// signature from a well-formed public key.
///
/// Uses `verify_strict` to reject the malleable / small-order edge cases that
/// plain `verify` accepts — important for a system where signature identity
/// gates trust.
pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}
