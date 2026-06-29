//! # bb-block-core
//!
//! `no_std`, allocation-free **read + verification** core for the Bruce's Bunker
//! block format (see `block-format/SPEC.md`). This is the security-critical code
//! shared verbatim between the ESP32 firmware and the orchestrator/server, so the
//! verification logic exists in exactly one place.
//!
//! Authoring (building, signing, writing volumes and key-sets) lives in the
//! `bb-block` (`authoring`) crate, which depends on this one.
//!
//! ## Read path at a glance
//! ```ignore
//! let (sb, manifest) = verify_volume(image, &trusted_content_keys)?;
//! if let Some(rec) = manifest.lookup(item_id)? {
//!     let bytes = verify_item(image, &rec)?; // serve this over HTTP Range
//! }
//! ```
#![cfg_attr(not(any(feature = "std", test)), no_std)]

pub mod bundle;
pub mod crypto;
pub mod error;
pub mod format;
pub mod keyset;
pub mod manifest;
pub mod superblock;
pub mod verify;

pub use bundle::{verify_bundle, TrustConfig, VerifiedBundle};
pub use error::{Error, Result};
pub use format::{CAP_CONTENT, CAP_MANAGEMENT};
pub use keyset::{key_id, verify_keyset, KeyEntry, KeySet};
pub use manifest::{ExtentRecord, Manifest};
pub use superblock::Superblock;
pub use verify::{verify_item, verify_manifest_signature, verify_volume};

#[cfg(test)]
mod tests {
    use super::format::crc32;

    #[test]
    fn crc32_known_vector() {
        // CRC-32/ISO-HDLC of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc32_empty() {
        assert_eq!(crc32(b""), 0x0000_0000);
    }
}
