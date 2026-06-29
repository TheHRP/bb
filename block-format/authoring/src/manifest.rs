//! Manifest construction (extent table + CBOR metadata) and metadata decoding,
//! shared by `VolumeBuilder` and `BundleBuilder`.

use bb_block_core::error::{Error, Result};
use bb_block_core::format::*;
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;

/// One item's full record: extent (offset/len/digest) plus descriptive metadata.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub item_id: u32,
    pub data_offset: u64,
    pub data_length: u64,
    pub sha256: [u8; 32],
    pub path: String,
    pub title: String,
    pub mime: String,
    pub collection: String,
    pub language: String,
    pub added_unix: u64,
}

/// Descriptive metadata for one item (no extent info).
#[derive(Debug, Clone, Default)]
pub struct ItemMeta {
    pub path: String,
    pub title: String,
    pub mime: String,
    pub collection: String,
    pub language: String,
    pub added_unix: u64,
}

/// Encode the CBOR metadata document (SPEC §5.2). Independent of data offsets.
pub fn encode_metadata(entries: &[ManifestEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    e.map(entries.len() as u64).unwrap();
    for it in entries {
        e.u64(it.item_id as u64).unwrap();
        e.map(8).unwrap();
        e.str("path").unwrap().str(&it.path).unwrap();
        e.str("title").unwrap().str(&it.title).unwrap();
        e.str("mime").unwrap().str(&it.mime).unwrap();
        e.str("collection").unwrap().str(&it.collection).unwrap();
        e.str("language").unwrap().str(&it.language).unwrap();
        e.str("size").unwrap().u64(it.data_length).unwrap();
        e.str("sha256").unwrap().bytes(&it.sha256).unwrap();
        e.str("added_unix").unwrap().u64(it.added_unix).unwrap();
    }
    buf
}

/// The metadata region's offset within a manifest of `n` items (records are
/// fixed-size, so this is purely a function of count).
pub fn meta_offset(n: usize) -> u64 {
    (EXTENT_HEADER_LEN + n * EXTENT_RECORD_LEN) as u64
}

/// Encode a full manifest payload from entries that already carry final offsets.
/// Entries must be sorted ascending by `item_id`.
pub fn encode_manifest(entries: &[ManifestEntry]) -> Vec<u8> {
    let n = entries.len();
    let metadata = encode_metadata(entries);
    let mo = meta_offset(n);

    let mut m = Vec::with_capacity(mo as usize + metadata.len());
    m.extend_from_slice(&EXTENT_TABLE_MAGIC);
    m.extend_from_slice(&(n as u32).to_le_bytes());
    m.extend_from_slice(&(EXTENT_RECORD_LEN as u32).to_le_bytes());
    m.extend_from_slice(&mo.to_le_bytes());
    m.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for it in entries {
        m.extend_from_slice(&it.item_id.to_le_bytes());
        m.extend_from_slice(&it.data_offset.to_le_bytes());
        m.extend_from_slice(&it.data_length.to_le_bytes());
        m.extend_from_slice(&it.sha256);
    }
    m.extend_from_slice(&metadata);
    m
}

/// Decode the metadata document into a map keyed by `item_id`. Used by the
/// bundle builder to carry forward descriptive metadata for unchanged items.
pub fn decode_metadata(meta: &[u8]) -> Result<BTreeMap<u32, ItemMeta>> {
    let mut out = BTreeMap::new();
    if meta.is_empty() {
        return Ok(out);
    }
    let mut d = Decoder::new(meta);
    let n = d.map().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
    for _ in 0..n {
        let id = d.u64().map_err(|_| Error::Cbor)? as u32;
        let mut im = ItemMeta::default();
        let fields = d.map().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
        for _ in 0..fields {
            let f = d.str().map_err(|_| Error::Cbor)?;
            match f {
                "path" => im.path = d.str().map_err(|_| Error::Cbor)?.to_string(),
                "title" => im.title = d.str().map_err(|_| Error::Cbor)?.to_string(),
                "mime" => im.mime = d.str().map_err(|_| Error::Cbor)?.to_string(),
                "collection" => im.collection = d.str().map_err(|_| Error::Cbor)?.to_string(),
                "language" => im.language = d.str().map_err(|_| Error::Cbor)?.to_string(),
                "added_unix" => im.added_unix = d.u64().map_err(|_| Error::Cbor)?,
                _ => d.skip().map_err(|_| Error::Cbor)?,
            }
        }
        out.insert(id, im);
    }
    Ok(out)
}
