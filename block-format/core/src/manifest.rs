//! Region 2 — the manifest. The firmware fast path reads only the binary
//! extent table (SPEC §5.1); the CBOR metadata document (§5.2) is left to the
//! orchestrator and is exposed here only as a borrowed slice.

use crate::error::{Error, Result};
use crate::format::*;

/// One content item's location and digest. Single contiguous extent in v0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentRecord {
    pub item_id: u32,
    pub data_offset: u64,
    pub data_length: u64,
    pub content_sha256: [u8; 32],
}

/// Zero-copy view over the manifest's extent table and metadata region.
#[derive(Debug, Clone, Copy)]
pub struct Manifest<'a> {
    records: &'a [u8],
    entry_count: u32,
    meta: &'a [u8],
}

impl<'a> Manifest<'a> {
    /// Parse the extent-table header and locate the records + metadata regions
    /// within the manifest payload.
    pub fn parse(manifest: &'a [u8]) -> Result<Manifest<'a>> {
        let hdr = take(manifest, 0, EXTENT_HEADER_LEN)?;
        if hdr[0..4] != EXTENT_TABLE_MAGIC {
            return Err(Error::BadMagic);
        }
        let entry_count = u32le(hdr, 4)?;
        let entry_size = u32le(hdr, 8)? as usize;
        if entry_size != EXTENT_RECORD_LEN {
            return Err(Error::UnsupportedVersion);
        }
        let records_len = (entry_count as usize)
            .checked_mul(EXTENT_RECORD_LEN)
            .ok_or(Error::Malformed)?;
        let records = take(manifest, EXTENT_HEADER_LEN, records_len)?;

        let meta_offset = u64le(hdr, 12)? as usize;
        let meta_length = u64le(hdr, 20)? as usize;
        // A zero-length metadata region is valid (firmware-only volumes).
        let meta = if meta_length == 0 {
            &manifest[0..0]
        } else {
            take(manifest, meta_offset, meta_length)?
        };

        Ok(Manifest {
            records,
            entry_count,
            meta,
        })
    }

    pub fn len(&self) -> u32 {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// The raw CBOR metadata document (empty if absent). Not parsed here.
    pub fn metadata(&self) -> &'a [u8] {
        self.meta
    }

    /// Decode the extent record at `index` (0-based).
    pub fn get(&self, index: u32) -> Result<ExtentRecord> {
        if index >= self.entry_count {
            return Err(Error::Truncated);
        }
        let off = index as usize * EXTENT_RECORD_LEN;
        let r = take(self.records, off, EXTENT_RECORD_LEN)?;
        Ok(ExtentRecord {
            item_id: u32le(r, 0)?,
            data_offset: u64le(r, 4)?,
            data_length: u64le(r, 12)?,
            content_sha256: array32(r, 20)?,
        })
    }

    /// Binary-search for an item by id. Records are sorted ascending by
    /// `item_id` (SPEC §5.1), giving O(log n) lookup with no allocation.
    pub fn lookup(&self, item_id: u32) -> Result<Option<ExtentRecord>> {
        let mut lo = 0u32;
        let mut hi = self.entry_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let rec = self.get(mid)?;
            if rec.item_id == item_id {
                return Ok(Some(rec));
            } else if rec.item_id < item_id {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(None)
    }

    /// Iterate every extent record in order.
    pub fn iter(&self) -> ExtentIter<'_, 'a> {
        ExtentIter {
            manifest: self,
            index: 0,
        }
    }
}

pub struct ExtentIter<'m, 'a> {
    manifest: &'m Manifest<'a>,
    index: u32,
}

impl<'m, 'a> Iterator for ExtentIter<'m, 'a> {
    type Item = Result<ExtentRecord>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.manifest.entry_count {
            return None;
        }
        let r = self.manifest.get(self.index);
        self.index += 1;
        Some(r)
    }
}
