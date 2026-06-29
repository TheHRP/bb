//! Region 0 — the superblock. Fixed 128-byte header at offset 0 (SPEC §4).

use crate::error::{Error, Result};
use crate::format::*;

/// Parsed, validated superblock. All offsets/lengths are absolute byte values
/// into the volume image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    pub format_version: u16,
    pub flags: u16,
    pub volume_uuid: [u8; 16],
    pub created_unix: u64,
    pub block_size: u32,
    pub digest_algo: u8,
    pub sig_algo: u8,
    pub sig_offset: u64,
    pub sig_length: u64,
    pub manifest_offset: u64,
    pub manifest_length: u64,
    pub data_offset: u64,
    pub replica_offset: u64,
    pub item_count: u32,
    pub manifest_sha256: [u8; 32],
}

pub const FLAG_REPLICA_PRESENT: u16 = 1 << 0;

impl Superblock {
    /// Parse and self-validate the superblock from the start of a volume image.
    ///
    /// Validates magic, format version, supported algorithms, and the header
    /// CRC-32. Does **not** verify signatures — see [`crate::verify`].
    pub fn parse(image: &[u8]) -> Result<Superblock> {
        let hdr = take(image, 0, SUPERBLOCK_LEN)?;

        if hdr[0..4] != SUPERBLOCK_MAGIC {
            return Err(Error::BadMagic);
        }
        let stored_crc = u32le(hdr, SUPERBLOCK_CRC_RANGE)?;
        if crc32(&hdr[..SUPERBLOCK_CRC_RANGE]) != stored_crc {
            return Err(Error::BadCrc);
        }

        let format_version = u16le(hdr, 4)?;
        if format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }

        let digest_algo = hdr[36];
        let sig_algo = hdr[37];
        if digest_algo != DIGEST_SHA256 || sig_algo != SIG_ED25519 {
            return Err(Error::UnsupportedAlgo);
        }

        let mut volume_uuid = [0u8; 16];
        volume_uuid.copy_from_slice(&hdr[8..24]);

        Ok(Superblock {
            format_version,
            flags: u16le(hdr, 6)?,
            volume_uuid,
            created_unix: u64le(hdr, 24)?,
            block_size: u32le(hdr, 32)?,
            digest_algo,
            sig_algo,
            sig_offset: u64le(hdr, 40)?,
            sig_length: u64le(hdr, 48)?,
            manifest_offset: u64le(hdr, 56)?,
            manifest_length: u64le(hdr, 64)?,
            data_offset: u64le(hdr, 72)?,
            replica_offset: u64le(hdr, 80)?,
            item_count: u32le(hdr, 88)?,
            manifest_sha256: array32(hdr, 92)?,
        })
    }

    /// Borrow the manifest payload (`manifest_length` bytes at `manifest_offset`).
    pub fn manifest<'a>(&self, image: &'a [u8]) -> Result<&'a [u8]> {
        slice_u64(image, self.manifest_offset, self.manifest_length)
    }

    /// Borrow the signature block payload (`sig_length` bytes at `sig_offset`).
    pub fn signature_block<'a>(&self, image: &'a [u8]) -> Result<&'a [u8]> {
        slice_u64(image, self.sig_offset, self.sig_length)
    }
}

/// Bounds-checked slice using `u64` offset/length, guarding against overflow on
/// 32-bit targets (the ESP32 is 32-bit).
pub fn slice_u64(buf: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
    let off: usize = offset.try_into().map_err(|_| Error::Truncated)?;
    let len: usize = length.try_into().map_err(|_| Error::Truncated)?;
    take(buf, off, len)
}
