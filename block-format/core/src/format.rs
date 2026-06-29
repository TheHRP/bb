//! On-storage constants and little-endian byte readers shared across the format.
//!
//! See `block-format/SPEC.md` for the authoritative field tables.

use crate::error::{Error, Result};

// ---- Region magics -------------------------------------------------------

pub const SUPERBLOCK_MAGIC: [u8; 4] = *b"BBLK";
pub const EXTENT_TABLE_MAGIC: [u8; 4] = *b"BMFT";
pub const SIGNATURE_MAGIC: [u8; 4] = *b"BSIG";
pub const KEYSET_MAGIC: [u8; 4] = *b"BKEY";

// ---- Versions / algorithms ----------------------------------------------

pub const FORMAT_VERSION: u16 = 1;
pub const KEYSET_FORMAT: u16 = 1;
pub const DIGEST_SHA256: u8 = 1;
pub const SIG_ED25519: u8 = 1;

// ---- Sizes ---------------------------------------------------------------

pub const SUPERBLOCK_LEN: usize = 128;
pub const SUPERBLOCK_CRC_RANGE: usize = 124;
pub const EXTENT_HEADER_LEN: usize = 32;
pub const EXTENT_RECORD_LEN: usize = 52;
pub const SIG_HEADER_LEN: usize = 8;
pub const SIG_RECORD_LEN: usize = 96; // 32-byte pubkey + 64-byte signature
pub const KEYSET_HEADER_LEN: usize = 12;
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

// ---- Signing-input domain separators ------------------------------------

pub const MANIFEST_SIG_PREFIX: &[u8] = b"BBLKSIGv1";
pub const KEYSET_SIG_PREFIX: &[u8] = b"BBKEYSv1";
pub const BUNDLE_SIG_PREFIX: &[u8] = b"BBLKUPDv1";

// ---- Capability flags ----------------------------------------------------

/// Permission to sign content / firmware update bundles.
pub const CAP_CONTENT: u32 = 1 << 0;
/// Permission to obtain management / shell access.
pub const CAP_MANAGEMENT: u32 = 1 << 1;

// ---- Little-endian slice readers (bounds-checked) ------------------------

#[inline]
pub fn take(buf: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    buf.get(off..off + len).ok_or(Error::Truncated)
}

#[inline]
pub fn u16le(buf: &[u8], off: usize) -> Result<u16> {
    let b = take(buf, off, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
pub fn u32le(buf: &[u8], off: usize) -> Result<u32> {
    let b = take(buf, off, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
pub fn u64le(buf: &[u8], off: usize) -> Result<u64> {
    let b = take(buf, off, 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_le_bytes(a))
}

#[inline]
pub fn array32(buf: &[u8], off: usize) -> Result<[u8; 32]> {
    let b = take(buf, off, 32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    Ok(a)
}

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), table-less.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// `true` if `value` is a multiple of `block` (block must be a power of two
/// is not required, only non-zero).
#[inline]
pub fn is_aligned(value: u64, block: u32) -> bool {
    block != 0 && value.is_multiple_of(block as u64)
}
