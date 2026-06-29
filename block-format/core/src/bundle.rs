//! Update-bundle parse, verify, and in-place apply (SPEC §9).
//!
//! The bundle author (server) computes the copy-on-write layout; the node only
//! **validates** it (in-bounds, aligned, non-overlapping, capacity-respecting)
//! and executes the writes, with the superblock swap as the atomic commit. This
//! keeps the constrained-node apply path simple and allocation-free.

use crate::crypto::sha256;
use crate::error::{Error, Result};
use crate::format::*;
use crate::keyset::{verify_keyset, KeySet};
use crate::manifest::Manifest;
use crate::superblock::Superblock;
use crate::verify::{manifest_signing_input, verify_signature_block};

/// Trust inputs a node supplies when applying a bundle.
pub struct TrustConfig<'a> {
    /// Embedded root keys (firmware-fixed); used only to verify an embedded key-set.
    pub root_keys: &'a [[u8; 32]],
    /// Root-signature quorum required for a key-set.
    pub quorum: usize,
    /// Key-set version the node currently holds (rollback guard).
    pub current_keyset_version: u64,
    /// The node's currently-active project key-set (if any).
    pub current_keyset: Option<&'a KeySet>,
    /// Owner keys trusted on this node.
    pub owner_keys: &'a [[u8; 32]],
    /// Unix seconds, or `0` if the node has no trustworthy clock.
    pub now: u64,
}

/// A bundle that has passed every check and is ready to execute.
pub struct VerifiedBundle<'a> {
    /// New superblock bytes, computed by the node (commit point — written last).
    pub new_superblock: [u8; SUPERBLOCK_LEN],
    /// An embedded key-set to persist, if the bundle carried a newer one.
    pub new_keyset: Option<&'a [u8]>,
    /// The version of `new_keyset`, if present.
    pub new_keyset_version: Option<u64>,
    manifest: &'a [u8],
    sigblock: &'a [u8],
    manifest_target: u64,
    sig_target: u64,
    seg_table: &'a [u8],
    seg_data: &'a [u8],
    seg_count: usize,
}

struct Raw<'a> {
    target_uuid: [u8; 16],
    base_sha: [u8; 32],
    manifest_target: u64,
    sig_target: u64,
    keyset: Option<&'a [u8]>,
    manifest: &'a [u8],
    sigblock: &'a [u8],
    seg_table: &'a [u8],
    seg_data: &'a [u8],
    seg_count: usize,
}

fn parse(bundle: &[u8]) -> Result<Raw<'_>> {
    let hdr = take(bundle, 0, BUNDLE_HEADER_LEN)?;
    if hdr[0..4] != BUNDLE_MAGIC {
        return Err(Error::BadMagic);
    }
    if u16le(hdr, 4)? != BUNDLE_FORMAT {
        return Err(Error::UnsupportedVersion);
    }
    let mut target_uuid = [0u8; 16];
    target_uuid.copy_from_slice(&hdr[8..24]);
    let mut base_sha = [0u8; 32];
    base_sha.copy_from_slice(&hdr[24..56]);
    let manifest_target = u64le(hdr, 56)?;
    let sig_target = u64le(hdr, 64)?;
    let keyset_len = u32le(hdr, 72)? as usize;
    let manifest_len = u32le(hdr, 76)? as usize;
    let sigblock_len = u32le(hdr, 80)? as usize;
    let seg_count = u32le(hdr, 84)? as usize;
    if seg_count > MAX_BUNDLE_SEGMENTS {
        return Err(Error::CapacityExceeded);
    }

    let mut cur = BUNDLE_HEADER_LEN;
    let keyset = if keyset_len == 0 {
        None
    } else {
        let k = take(bundle, cur, keyset_len)?;
        cur += keyset_len;
        Some(k)
    };
    let manifest = take(bundle, cur, manifest_len)?;
    cur += manifest_len;
    let sigblock = take(bundle, cur, sigblock_len)?;
    cur += sigblock_len;
    let seg_table = take(bundle, cur, seg_count * BUNDLE_SEGMENT_REC_LEN)?;
    cur += seg_count * BUNDLE_SEGMENT_REC_LEN;

    // Segment payloads are concatenated; total length is the sum of the table.
    let mut payload_total = 0usize;
    for i in 0..seg_count {
        payload_total += u64le(seg_table, i * BUNDLE_SEGMENT_REC_LEN + 4)? as usize;
    }
    let seg_data = take(bundle, cur, payload_total)?;

    Ok(Raw {
        target_uuid,
        base_sha,
        manifest_target,
        sig_target,
        keyset,
        manifest,
        sigblock,
        seg_table,
        seg_data,
        seg_count,
    })
}

/// One segment's `(item_id, payload_len, payload_offset_within_seg_data)`.
fn seg_entry(raw: &Raw, i: usize) -> Result<(u32, u64, usize)> {
    let off = i * BUNDLE_SEGMENT_REC_LEN;
    let item_id = u32le(raw.seg_table, off)?;
    let len = u64le(raw.seg_table, off + 4)?;
    // Payload offset = sum of preceding payload lengths.
    let mut start = 0usize;
    for j in 0..i {
        start += u64le(raw.seg_table, j * BUNDLE_SEGMENT_REC_LEN + 4)? as usize;
    }
    Ok((item_id, len, start))
}

fn is_segment(raw: &Raw, item_id: u32) -> Result<bool> {
    for i in 0..raw.seg_count {
        if u32le(raw.seg_table, i * BUNDLE_SEGMENT_REC_LEN)? == item_id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `true` if `[a, a+alen)` and `[b, b+blen)` overlap.
fn overlaps(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    a < b + blen && b < a + alen
}

/// Verify a bundle against the current volume image and trust config (SPEC §9.3
/// steps 0–4), returning a [`VerifiedBundle`] ready to [`execute`](VerifiedBundle::execute).
pub fn verify_bundle<'a>(
    image: &[u8],
    bundle: &'a [u8],
    trust: &TrustConfig,
) -> Result<VerifiedBundle<'a>> {
    let raw = parse(bundle)?;
    let cur_sb = Superblock::parse(image)?;
    let cur_manifest = Manifest::parse(cur_sb.manifest(image)?)?;

    // Step 2a: target + base.
    if raw.target_uuid != cur_sb.volume_uuid {
        return Err(Error::Malformed);
    }
    if raw.base_sha != [0u8; 32] && raw.base_sha != cur_sb.manifest_sha256 {
        return Err(Error::BaseMismatch);
    }

    // Step 0: process an embedded key-set first, so trust is fresh.
    let mut embedded: Option<KeySet> = None;
    let (new_keyset, new_keyset_version) = if let Some(ks_bytes) = raw.keyset {
        let ks = verify_keyset(
            ks_bytes,
            trust.root_keys,
            trust.quorum,
            trust.current_keyset_version,
        )?;
        let v = ks.version;
        embedded = Some(ks);
        (Some(ks_bytes), Some(v))
    } else {
        (None, None)
    };
    let active_keyset = embedded.as_ref().or(trust.current_keyset);

    // Step 1: authorize the new manifest's signature (content capability).
    let new_manifest_sha = sha256(raw.manifest);
    let msg = manifest_signing_input(
        &cur_sb.volume_uuid,
        cur_sb.format_version,
        &new_manifest_sha,
    );
    let now = trust.now;
    verify_signature_block(&msg, raw.sigblock, |pk| {
        trust.owner_keys.iter().any(|k| k == pk)
            || active_keyset
                .map(|ks| ks.authorizes(pk, CAP_CONTENT, now))
                .unwrap_or(false)
    })?;

    // Parse the (now trusted) new manifest.
    let new_manifest = Manifest::parse(raw.manifest)?;

    // Step 3 + kept-item validity: every new record is either supplied as a
    // segment whose bytes hash correctly, or a kept item identical to the
    // current volume (so its existing bytes survive untouched).
    for r in new_manifest.iter() {
        let rec = r?;
        if is_segment(&raw, rec.item_id)? {
            // Find the matching segment and verify its payload.
            let mut matched = false;
            for i in 0..raw.seg_count {
                let (id, len, start) = seg_entry(&raw, i)?;
                if id == rec.item_id {
                    if len != rec.data_length {
                        return Err(Error::Malformed);
                    }
                    let bytes = take(raw.seg_data, start, len as usize)?;
                    if sha256(bytes) != rec.content_sha256 {
                        return Err(Error::ContentHashMismatch);
                    }
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(Error::Malformed);
            }
        } else {
            // Kept item: must equal the current manifest's record exactly.
            match cur_manifest.lookup(rec.item_id)? {
                Some(cur) if cur == rec => {}
                _ => return Err(Error::Malformed),
            }
        }
    }

    // Step 4: safety of every write region (segments + new manifest + new sig).
    let block = cur_sb.block_size;
    let cap = cur_sb.volume_capacity;
    let mut writes: [(u64, u64); MAX_BUNDLE_SEGMENTS + 2] = [(0, 0); MAX_BUNDLE_SEGMENTS + 2];
    let mut wn = 0usize;

    // Collect segment write regions (offset from the *new* manifest record).
    for i in 0..raw.seg_count {
        let (id, _len, _start) = seg_entry(&raw, i)?;
        let rec = new_manifest.lookup(id)?.ok_or(Error::Malformed)?;
        writes[wn] = (rec.data_offset, rec.data_length);
        wn += 1;
    }
    writes[wn] = (raw.manifest_target, raw.manifest.len() as u64);
    wn += 1;
    writes[wn] = (raw.sig_target, raw.sigblock.len() as u64);
    wn += 1;

    let arena_lo = block as u64;
    for &(off, len) in &writes[..wn] {
        // In-bounds, block-aligned start, within capacity.
        if off < arena_lo || !is_aligned(off, block) {
            return Err(Error::Malformed);
        }
        if off.checked_add(len).ok_or(Error::Malformed)? > cap {
            return Err(Error::Malformed);
        }
    }
    // Mutually non-overlapping write regions.
    for i in 0..wn {
        for j in (i + 1)..wn {
            if overlaps(writes[i].0, writes[i].1, writes[j].0, writes[j].1) {
                return Err(Error::Malformed);
            }
        }
    }
    // No write region may clobber currently-referenced bytes (kept data, the
    // current manifest, or the current sig block) before the commit.
    let protected = |off: u64, len: u64| -> Result<bool> {
        if overlaps(off, len, cur_sb.manifest_offset, cur_sb.manifest_length)
            || overlaps(off, len, cur_sb.sig_offset, cur_sb.sig_length)
        {
            return Ok(true);
        }
        for r in cur_manifest.iter() {
            let rec = r?;
            // Only kept items are protected; data we are replacing is fair game.
            if !is_segment(&raw, rec.item_id)?
                && overlaps(off, len, rec.data_offset, rec.data_length)
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    for &(off, len) in &writes[..wn] {
        if protected(off, len)? {
            return Err(Error::Malformed);
        }
    }

    // Step 6 (compute): build the new superblock; the node controls it.
    let mut new_sb = cur_sb;
    new_sb.manifest_offset = raw.manifest_target;
    new_sb.manifest_length = raw.manifest.len() as u64;
    new_sb.manifest_sha256 = new_manifest_sha;
    new_sb.sig_offset = raw.sig_target;
    new_sb.sig_length = raw.sigblock.len() as u64;
    new_sb.item_count = new_manifest.len();

    Ok(VerifiedBundle {
        new_superblock: new_sb.encode(),
        new_keyset,
        new_keyset_version,
        manifest: raw.manifest,
        sigblock: raw.sigblock,
        manifest_target: raw.manifest_target,
        sig_target: raw.sig_target,
        seg_table: raw.seg_table,
        seg_data: raw.seg_data,
        seg_count: raw.seg_count,
    })
}

impl<'a> VerifiedBundle<'a> {
    /// Apply the bundle to an in-memory image (the medium, sized to
    /// `volume_capacity`). Writes data + manifest + sig into free space, then the
    /// superblock last — the commit point (SPEC §9.3 steps 5–6).
    ///
    /// A device-backed node performs the same writes against storage, ordering
    /// the superblock (and replica) per §9.3 for crash-safety.
    pub fn execute(&self, image: &mut [u8]) -> Result<()> {
        let new_manifest = Manifest::parse(self.manifest)?;

        // Segments → their new-manifest offsets.
        for i in 0..self.seg_count {
            let off = i * BUNDLE_SEGMENT_REC_LEN;
            let id = u32le(self.seg_table, off)?;
            let len = u64le(self.seg_table, off + 4)? as usize;
            let mut start = 0usize;
            for j in 0..i {
                start += u64le(self.seg_table, j * BUNDLE_SEGMENT_REC_LEN + 4)? as usize;
            }
            let bytes = take(self.seg_data, start, len)?;
            let rec = new_manifest.lookup(id)?.ok_or(Error::Malformed)?;
            write_at(image, rec.data_offset, bytes)?;
        }

        write_at(image, self.manifest_target, self.manifest)?;
        write_at(image, self.sig_target, self.sigblock)?;
        // Commit.
        write_at(image, 0, &self.new_superblock)?;
        Ok(())
    }
}

fn write_at(image: &mut [u8], offset: u64, bytes: &[u8]) -> Result<()> {
    let off: usize = offset.try_into().map_err(|_| Error::Truncated)?;
    let end = off.checked_add(bytes.len()).ok_or(Error::Truncated)?;
    image
        .get_mut(off..end)
        .ok_or(Error::Truncated)?
        .copy_from_slice(bytes);
    Ok(())
}
