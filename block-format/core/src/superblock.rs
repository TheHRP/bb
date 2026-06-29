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
    /// Total allocatable bytes; the upper bound for in-place update allocation.
    pub volume_capacity: u64,
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
            volume_capacity: u64le(hdr, 124)?,
        })
    }

    /// Serialize this superblock to its fixed 128/160-byte header, computing the
    /// CRC. Shared by the authoring builder and the in-place update path so the
    /// node, not the bundle author, always controls the committed superblock.
    pub fn encode(&self) -> [u8; SUPERBLOCK_LEN] {
        let mut sb = [0u8; SUPERBLOCK_LEN];
        sb[0..4].copy_from_slice(&SUPERBLOCK_MAGIC);
        sb[4..6].copy_from_slice(&self.format_version.to_le_bytes());
        sb[6..8].copy_from_slice(&self.flags.to_le_bytes());
        sb[8..24].copy_from_slice(&self.volume_uuid);
        sb[24..32].copy_from_slice(&self.created_unix.to_le_bytes());
        sb[32..36].copy_from_slice(&self.block_size.to_le_bytes());
        sb[36] = self.digest_algo;
        sb[37] = self.sig_algo;
        sb[40..48].copy_from_slice(&self.sig_offset.to_le_bytes());
        sb[48..56].copy_from_slice(&self.sig_length.to_le_bytes());
        sb[56..64].copy_from_slice(&self.manifest_offset.to_le_bytes());
        sb[64..72].copy_from_slice(&self.manifest_length.to_le_bytes());
        sb[72..80].copy_from_slice(&self.data_offset.to_le_bytes());
        sb[80..88].copy_from_slice(&self.replica_offset.to_le_bytes());
        sb[88..92].copy_from_slice(&self.item_count.to_le_bytes());
        sb[92..124].copy_from_slice(&self.manifest_sha256);
        sb[124..132].copy_from_slice(&self.volume_capacity.to_le_bytes());
        let crc = crc32(&sb[..SUPERBLOCK_CRC_RANGE]);
        sb[132..136].copy_from_slice(&crc.to_le_bytes());
        sb
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
