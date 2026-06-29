//! Build and sign a complete block-format volume image (SPEC §3–§7).

use crate::keys::Keypair;
use bb_block_core::crypto::sha256;
use bb_block_core::format::*;
use minicbor::Encoder;

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
        }
    }

    pub fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = block_size;
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

        // 1. Per-item digests (needed by both the extent table and metadata).
        let digests: Vec<[u8; 32]> = self.items.iter().map(|i| sha256(&i.data)).collect();

        // 2. Metadata document (CBOR). Its length is independent of data offsets.
        let metadata = self.encode_metadata(&digests);

        // 3. Manifest length is fixed by counts, so region offsets are known
        //    before data offsets are assigned.
        let n = self.items.len();
        let meta_offset = (EXTENT_HEADER_LEN + n * EXTENT_RECORD_LEN) as u64;
        let manifest_len = meta_offset + metadata.len() as u64;

        let sig_count = signers.len();
        let region1_start = block; // superblock occupies block 0
        let region1_len = (SIG_HEADER_LEN + sig_count * SIG_RECORD_LEN) as u64;
        let region2_start = align_up(region1_start + region1_len, block);
        let region3_start = align_up(region2_start + manifest_len, block);

        // 4. Assign block-aligned data offsets within region 3.
        let mut data_offsets = Vec::with_capacity(n);
        let mut cursor = region3_start;
        for item in &self.items {
            data_offsets.push(cursor);
            cursor = align_up(cursor + item.data.len() as u64, block);
        }
        let image_len = cursor.max(region3_start) as usize;

        // 5. Manifest bytes (extent table header + records + metadata).
        let manifest = self.encode_manifest(&digests, &data_offsets, meta_offset, &metadata);
        debug_assert_eq!(manifest.len() as u64, manifest_len);
        let manifest_sha = sha256(&manifest);

        // 6. Superblock.
        let superblock = self.encode_superblock(
            region1_start,
            region1_len,
            region2_start,
            manifest_len,
            region3_start,
            &manifest_sha,
        );

        // 7. Signatures over the manifest signing input (SPEC §7.3).
        let sig_block = sign_manifest(&self.volume_uuid, &manifest_sha, signers);

        // 8. Assemble the zero-filled image.
        let mut image = vec![0u8; image_len];
        image[0..superblock.len()].copy_from_slice(&superblock);
        let r1 = region1_start as usize;
        image[r1..r1 + sig_block.len()].copy_from_slice(&sig_block);
        let r2 = region2_start as usize;
        image[r2..r2 + manifest.len()].copy_from_slice(&manifest);
        for (item, &off) in self.items.iter().zip(&data_offsets) {
            let o = off as usize;
            image[o..o + item.data.len()].copy_from_slice(&item.data);
        }
        image
    }

    fn encode_metadata(&self, digests: &[[u8; 32]]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.map(self.items.len() as u64).unwrap();
        for (item, digest) in self.items.iter().zip(digests) {
            e.u64(item.item_id as u64).unwrap();
            e.map(8).unwrap();
            e.str("path").unwrap().str(&item.path).unwrap();
            e.str("title").unwrap().str(&item.title).unwrap();
            e.str("mime").unwrap().str(&item.mime).unwrap();
            e.str("collection").unwrap().str(&item.collection).unwrap();
            e.str("language").unwrap().str(&item.language).unwrap();
            e.str("size").unwrap().u64(item.data.len() as u64).unwrap();
            e.str("sha256").unwrap().bytes(digest).unwrap();
            e.str("added_unix").unwrap().u64(self.created_unix).unwrap();
        }
        buf
    }

    fn encode_manifest(
        &self,
        digests: &[[u8; 32]],
        data_offsets: &[u64],
        meta_offset: u64,
        metadata: &[u8],
    ) -> Vec<u8> {
        let n = self.items.len();
        let mut m = Vec::with_capacity(meta_offset as usize + metadata.len());
        // Extent table header (SPEC §5.1).
        m.extend_from_slice(&EXTENT_TABLE_MAGIC);
        m.extend_from_slice(&(n as u32).to_le_bytes());
        m.extend_from_slice(&(EXTENT_RECORD_LEN as u32).to_le_bytes());
        m.extend_from_slice(&meta_offset.to_le_bytes());
        m.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
        m.extend_from_slice(&0u32.to_le_bytes()); // reserved
                                                  // Records.
        for ((item, &off), digest) in self.items.iter().zip(data_offsets).zip(digests) {
            m.extend_from_slice(&item.item_id.to_le_bytes());
            m.extend_from_slice(&off.to_le_bytes());
            m.extend_from_slice(&(item.data.len() as u64).to_le_bytes());
            m.extend_from_slice(digest);
        }
        // Metadata document.
        m.extend_from_slice(metadata);
        m
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_superblock(
        &self,
        sig_offset: u64,
        sig_length: u64,
        manifest_offset: u64,
        manifest_length: u64,
        data_offset: u64,
        manifest_sha: &[u8; 32],
    ) -> Vec<u8> {
        let mut sb = vec![0u8; SUPERBLOCK_LEN];
        sb[0..4].copy_from_slice(&SUPERBLOCK_MAGIC);
        sb[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        sb[6..8].copy_from_slice(&0u16.to_le_bytes()); // flags
        sb[8..24].copy_from_slice(&self.volume_uuid);
        sb[24..32].copy_from_slice(&self.created_unix.to_le_bytes());
        sb[32..36].copy_from_slice(&self.block_size.to_le_bytes());
        sb[36] = DIGEST_SHA256;
        sb[37] = SIG_ED25519;
        // 38..40 reserved
        sb[40..48].copy_from_slice(&sig_offset.to_le_bytes());
        sb[48..56].copy_from_slice(&sig_length.to_le_bytes());
        sb[56..64].copy_from_slice(&manifest_offset.to_le_bytes());
        sb[64..72].copy_from_slice(&manifest_length.to_le_bytes());
        sb[72..80].copy_from_slice(&data_offset.to_le_bytes());
        sb[80..88].copy_from_slice(&0u64.to_le_bytes()); // replica_offset
        sb[88..92].copy_from_slice(&(self.items.len() as u32).to_le_bytes());
        sb[92..124].copy_from_slice(manifest_sha);
        let crc = crc32(&sb[..SUPERBLOCK_CRC_RANGE]);
        sb[124..128].copy_from_slice(&crc.to_le_bytes());
        sb
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
