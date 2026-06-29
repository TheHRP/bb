//! Build and sign a complete block-format volume image (SPEC §3–§7).

use crate::keys::Keypair;
use crate::manifest::{encode_manifest, encode_metadata, meta_offset, ManifestEntry};
use bb_block_core::crypto::sha256;
use bb_block_core::format::*;
use bb_block_core::Superblock;

/// A single content item to place in the volume.
pub struct Item {
    pub item_id: u32,
    pub path: String,
    pub title: String,
    pub mime: String,
    pub collection: String,
    pub language: String,
    pub data: Vec<u8>,
}

/// Accumulates items, then lays out, hashes, signs, and emits a volume image.
pub struct VolumeBuilder {
    block_size: u32,
    volume_uuid: [u8; 16],
    created_unix: u64,
    items: Vec<Item>,
    next_id: u32,
    capacity: u64,
}

#[inline]
fn align_up(v: u64, block: u64) -> u64 {
    v.div_ceil(block) * block
}

impl VolumeBuilder {
    pub fn new(volume_uuid: [u8; 16], created_unix: u64) -> VolumeBuilder {
        VolumeBuilder {
            block_size: DEFAULT_BLOCK_SIZE,
            volume_uuid,
            created_unix,
            items: Vec::new(),
            next_id: 1,
            capacity: 0,
        }
    }

    pub fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = block_size;
        self
    }

    /// Set the volume's total allocatable capacity (the medium size). Free space
    /// beyond the laid-out image is available to in-place update bundles (§9).
    /// Defaults to a tight fit (image length) when unset, leaving no slack.
    pub fn with_capacity(mut self, capacity: u64) -> Self {
        self.capacity = capacity;
        self
    }

    /// Add an item; returns its assigned `item_id`. Ids increase monotonically
    /// so the resulting extent table is sorted by construction.
    pub fn add_item(
        &mut self,
        path: &str,
        title: &str,
        mime: &str,
        collection: &str,
        language: &str,
        data: Vec<u8>,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.items.push(Item {
            item_id: id,
            path: path.to_string(),
            title: title.to_string(),
            mime: mime.to_string(),
            collection: collection.to_string(),
            language: language.to_string(),
            data,
        });
        id
    }

    /// Lay out, hash, sign with every provided key, and return the full image.
    pub fn seal(&self, signers: &[Keypair]) -> Vec<u8> {
        let block = self.block_size as u64;

        let n = self.items.len();

        // 1. Manifest entries (offsets assigned below).
        let mut entries: Vec<ManifestEntry> = self
            .items
            .iter()
            .map(|it| ManifestEntry {
                item_id: it.item_id,
                data_offset: 0,
                data_length: it.data.len() as u64,
                sha256: sha256(&it.data),
                path: it.path.clone(),
                title: it.title.clone(),
                mime: it.mime.clone(),
                collection: it.collection.clone(),
                language: it.language.clone(),
                added_unix: self.created_unix,
            })
            .collect();

        // 2. Metadata length is offset-independent, so region layout is known.
        let manifest_len = meta_offset(n) + encode_metadata(&entries).len() as u64;

        let sig_count = signers.len();
        let region1_start = block; // superblock occupies block 0
        let region1_len = (SIG_HEADER_LEN + sig_count * SIG_RECORD_LEN) as u64;
        let region2_start = align_up(region1_start + region1_len, block);
        let region3_start = align_up(region2_start + manifest_len, block);

        // 3. Assign block-aligned data offsets within region 3.
        let mut cursor = region3_start;
        for (it, entry) in self.items.iter().zip(entries.iter_mut()) {
            entry.data_offset = cursor;
            cursor = align_up(cursor + it.data.len() as u64, block);
        }
        let image_len = cursor.max(region3_start);
        let capacity = align_up(self.capacity.max(image_len), block);

        // 4. Manifest bytes + digest.
        let manifest = encode_manifest(&entries);
        debug_assert_eq!(manifest.len() as u64, manifest_len);
        let manifest_sha = sha256(&manifest);

        // 5. Superblock (encoded via core so the format lives in one place).
        let superblock = Superblock {
            format_version: FORMAT_VERSION,
            flags: 0,
            volume_uuid: self.volume_uuid,
            created_unix: self.created_unix,
            block_size: self.block_size,
            digest_algo: DIGEST_SHA256,
            sig_algo: SIG_ED25519,
            sig_offset: region1_start,
            sig_length: region1_len,
            manifest_offset: region2_start,
            manifest_length: manifest_len,
            data_offset: region3_start,
            replica_offset: 0,
            item_count: n as u32,
            manifest_sha256: manifest_sha,
            volume_capacity: capacity,
        }
        .encode();

        // 6. Signatures over the manifest signing input (SPEC §7.3).
        let sig_block = sign_manifest(&self.volume_uuid, &manifest_sha, signers);

        // 7. Assemble the image, sized to capacity so the free tail is real,
        //    writable space for later in-place update bundles.
        let mut image = vec![0u8; capacity as usize];
        image[0..superblock.len()].copy_from_slice(&superblock);
        let r1 = region1_start as usize;
        image[r1..r1 + sig_block.len()].copy_from_slice(&sig_block);
        let r2 = region2_start as usize;
        image[r2..r2 + manifest.len()].copy_from_slice(&manifest);
        for (it, entry) in self.items.iter().zip(&entries) {
            let o = entry.data_offset as usize;
            image[o..o + it.data.len()].copy_from_slice(&it.data);
        }
        image
    }
}

/// Build the `BSIG` signature block for a manifest digest.
pub fn sign_manifest(
    volume_uuid: &[u8; 16],
    manifest_sha: &[u8; 32],
    signers: &[Keypair],
) -> Vec<u8> {
    // Signing input (SPEC §7.3).
    let mut msg = Vec::with_capacity(9 + 16 + 2 + 32);
    msg.extend_from_slice(MANIFEST_SIG_PREFIX);
    msg.extend_from_slice(volume_uuid);
    msg.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    msg.extend_from_slice(manifest_sha);

    let mut block = Vec::new();
    block.extend_from_slice(&SIGNATURE_MAGIC);
    block.extend_from_slice(&(signers.len() as u16).to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes()); // reserved
    for k in signers {
        block.extend_from_slice(&k.public());
        block.extend_from_slice(&k.sign(&msg));
    }
    block
}
