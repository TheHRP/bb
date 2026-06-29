//! Author copy-on-write update bundles (SPEC §9).
//!
//! The builder models the volume's free space from its manifest, allocates new
//! data / manifest / signature regions out of that free space, signs the new
//! manifest, and emits a bundle the node can validate and apply.

use crate::builder::sign_manifest;
use crate::keys::Keypair;
use crate::manifest::{encode_manifest, encode_metadata, meta_offset, ItemMeta, ManifestEntry};
use bb_block_core::crypto::sha256;
use bb_block_core::error::{Error, Result};
use bb_block_core::format::*;
use bb_block_core::{Manifest, Superblock};
use std::collections::BTreeMap;

#[inline]
fn align_up(v: u64, block: u64) -> u64 {
    v.div_ceil(block) * block
}

/// First-fit allocator over the volume's free intervals.
struct Allocator {
    block: u64,
    free: Vec<(u64, u64)>, // (start, len), sorted by start, block-aligned
}

impl Allocator {
    /// Build from the occupied (start, len) ranges within `[block, capacity)`.
    fn new(block: u64, capacity: u64, occupied: &[(u64, u64)]) -> Allocator {
        // Normalize occupied ranges to block boundaries and sort.
        let mut occ: Vec<(u64, u64)> = occupied
            .iter()
            .map(|&(s, l)| {
                let start = (s / block) * block;
                let end = align_up(s + l, block);
                (start, end)
            })
            .collect();
        occ.sort_by_key(|r| r.0);

        // Complement within [block, capacity).
        let mut free = Vec::new();
        let mut cursor = block; // never allocate block 0 (superblock)
        for (start, end) in occ {
            if start > cursor {
                free.push((cursor, start - cursor));
            }
            cursor = cursor.max(end);
        }
        if capacity > cursor {
            free.push((cursor, capacity - cursor));
        }
        Allocator { block, free }
    }

    /// Allocate `size` bytes (rounded up to a block), returning the offset.
    fn alloc(&mut self, size: u64) -> Result<u64> {
        let need = align_up(size, self.block);
        for slot in self.free.iter_mut() {
            if slot.1 >= need {
                let off = slot.0;
                slot.0 += need;
                slot.1 -= need;
                return Ok(off);
            }
        }
        Err(Error::CapacityExceeded)
    }
}

enum Work {
    Kept(ManifestEntry),
    Set { meta: ItemMeta, data: Vec<u8> },
}

/// Builds an update bundle against a current volume image.
pub struct BundleBuilder {
    block_size: u32,
    capacity: u64,
    volume_uuid: [u8; 16],
    base_manifest_sha: [u8; 32],
    occupied: Vec<(u64, u64)>,
    working: BTreeMap<u32, Work>,
    next_id: u32,
    keyset: Option<Vec<u8>>,
}

impl BundleBuilder {
    /// Load the current volume state from its image (parsed, not re-verified —
    /// the authoring host is the source of truth for its own volumes).
    pub fn from_volume(image: &[u8]) -> Result<BundleBuilder> {
        let sb = Superblock::parse(image)?;
        let manifest = Manifest::parse(sb.manifest(image)?)?;
        let metas = crate::manifest::decode_metadata(manifest.metadata())?;

        let mut working = BTreeMap::new();
        let mut occupied = Vec::new();
        let mut next_id = 1u32;
        for r in manifest.iter() {
            let rec = r?;
            let m = metas.get(&rec.item_id).cloned().unwrap_or_default();
            working.insert(
                rec.item_id,
                Work::Kept(ManifestEntry {
                    item_id: rec.item_id,
                    data_offset: rec.data_offset,
                    data_length: rec.data_length,
                    sha256: rec.content_sha256,
                    path: m.path,
                    title: m.title,
                    mime: m.mime,
                    collection: m.collection,
                    language: m.language,
                    added_unix: m.added_unix,
                }),
            );
            occupied.push((rec.data_offset, rec.data_length));
            next_id = next_id.max(rec.item_id + 1);
        }
        // The current manifest and signature regions must survive until commit.
        occupied.push((sb.manifest_offset, sb.manifest_length));
        occupied.push((sb.sig_offset, sb.sig_length));

        Ok(BundleBuilder {
            block_size: sb.block_size,
            capacity: sb.volume_capacity,
            volume_uuid: sb.volume_uuid,
            base_manifest_sha: sb.manifest_sha256,
            occupied,
            working,
            next_id,
            keyset: None,
        })
    }

    /// Replace an existing item's bytes (optionally updating its metadata).
    pub fn replace(&mut self, item_id: u32, data: Vec<u8>, meta: Option<ItemMeta>) -> Result<()> {
        let existing = self.working.get(&item_id).ok_or(Error::Malformed)?;
        let meta = meta.unwrap_or_else(|| match existing {
            Work::Kept(e) => ItemMeta {
                path: e.path.clone(),
                title: e.title.clone(),
                mime: e.mime.clone(),
                collection: e.collection.clone(),
                language: e.language.clone(),
                added_unix: e.added_unix,
            },
            Work::Set { meta, .. } => meta.clone(),
        });
        self.working.insert(item_id, Work::Set { meta, data });
        Ok(())
    }

    /// Add a new item; returns its assigned `item_id`.
    pub fn add(&mut self, meta: ItemMeta, data: Vec<u8>) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.working.insert(id, Work::Set { meta, data });
        id
    }

    /// Delete an item.
    pub fn delete(&mut self, item_id: u32) {
        self.working.remove(&item_id);
    }

    /// Embed a key-set (already a signed `BKEY` envelope) so revocations travel
    /// with the bundle (SPEC §9.2).
    pub fn with_keyset(&mut self, envelope: Vec<u8>) -> &mut Self {
        self.keyset = Some(envelope);
        self
    }

    /// Build and sign the bundle.
    pub fn seal(&self, signers: &[Keypair]) -> Result<Vec<u8>> {
        let block = self.block_size as u64;
        let n = self.working.len();

        // Provisional entries (offset 0) to size the new manifest.
        let mut entries: Vec<ManifestEntry> = Vec::with_capacity(n);
        // Track which ids are segments (changed/new) and their payloads.
        let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
        for (&id, w) in &self.working {
            match w {
                Work::Kept(e) => entries.push(e.clone()),
                Work::Set { meta, data } => {
                    entries.push(ManifestEntry {
                        item_id: id,
                        data_offset: 0,
                        data_length: data.len() as u64,
                        sha256: sha256(data),
                        path: meta.path.clone(),
                        title: meta.title.clone(),
                        mime: meta.mime.clone(),
                        collection: meta.collection.clone(),
                        language: meta.language.clone(),
                        added_unix: meta.added_unix,
                    });
                    segments.push((id, data.clone()));
                }
            }
        }
        entries.sort_by_key(|e| e.item_id);

        let manifest_len = meta_offset(n) + encode_metadata(&entries).len() as u64;
        let sigblock_len = (SIG_HEADER_LEN + signers.len() * SIG_RECORD_LEN) as u64;

        // Allocate new data segments, then manifest, then signature block.
        let mut alloc = Allocator::new(block, self.capacity, &self.occupied);
        for (id, data) in &segments {
            let off = alloc.alloc(data.len() as u64)?;
            // Patch the matching entry's offset.
            let e = entries.iter_mut().find(|e| e.item_id == *id).unwrap();
            e.data_offset = off;
        }
        let manifest_target = alloc.alloc(manifest_len)?;
        let sig_target = alloc.alloc(sigblock_len)?;

        // Finalize manifest + signature.
        let manifest = encode_manifest(&entries);
        debug_assert_eq!(manifest.len() as u64, manifest_len);
        let manifest_sha = sha256(&manifest);
        let sigblock = sign_manifest(&self.volume_uuid, &manifest_sha, signers);

        // Assemble the bundle.
        let keyset = self.keyset.as_deref().unwrap_or(&[]);
        let mut b = Vec::new();
        b.extend_from_slice(&BUNDLE_MAGIC);
        b.extend_from_slice(&BUNDLE_FORMAT.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // flags
        b.extend_from_slice(&self.volume_uuid);
        b.extend_from_slice(&self.base_manifest_sha);
        b.extend_from_slice(&manifest_target.to_le_bytes());
        b.extend_from_slice(&sig_target.to_le_bytes());
        b.extend_from_slice(&(keyset.len() as u32).to_le_bytes());
        b.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        b.extend_from_slice(&(sigblock.len() as u32).to_le_bytes());
        b.extend_from_slice(&(segments.len() as u32).to_le_bytes());
        debug_assert_eq!(b.len(), BUNDLE_HEADER_LEN);

        b.extend_from_slice(keyset);
        b.extend_from_slice(&manifest);
        b.extend_from_slice(&sigblock);
        // Segment table (item_id, payload_len), then concatenated payloads.
        for (id, data) in &segments {
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&(data.len() as u64).to_le_bytes());
        }
        for (_id, data) in &segments {
            b.extend_from_slice(data);
        }
        Ok(b)
    }
}
