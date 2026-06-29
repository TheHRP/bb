//! The boot/mount verification procedure (SPEC §7.5) and per-item content
//! verification.

use crate::crypto::{ed25519_verify, sha256};
use crate::error::{Error, Result};
use crate::format::*;
use crate::manifest::{ExtentRecord, Manifest};
use crate::superblock::{slice_u64, Superblock};

/// Iterate the `(pubkey, signature)` records of a `BSIG` signature block.
struct SignatureBlock<'a> {
    count: u16,
    body: &'a [u8],
}

impl<'a> SignatureBlock<'a> {
    fn parse(buf: &'a [u8]) -> Result<SignatureBlock<'a>> {
        let hdr = take(buf, 0, SIG_HEADER_LEN)?;
        if hdr[0..4] != SIGNATURE_MAGIC {
            return Err(Error::BadMagic);
        }
        let count = u16le(hdr, 4)?;
        let body = take(buf, SIG_HEADER_LEN, count as usize * SIG_RECORD_LEN)?;
        Ok(SignatureBlock { count, body })
    }

    fn record(&self, i: usize) -> Result<([u8; 32], [u8; 64])> {
        let r = take(self.body, i * SIG_RECORD_LEN, SIG_RECORD_LEN)?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&r[0..32]);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&r[32..96]);
        Ok((pk, sig))
    }
}

/// Build the manifest signing input (SPEC §7.3):
/// `"BBLKSIGv1" || volume_uuid || format_version(LE) || manifest_sha256`.
fn manifest_signing_input(sb: &Superblock) -> [u8; 9 + 16 + 2 + 32] {
    let mut msg = [0u8; 9 + 16 + 2 + 32];
    msg[0..9].copy_from_slice(MANIFEST_SIG_PREFIX);
    msg[9..25].copy_from_slice(&sb.volume_uuid);
    msg[25..27].copy_from_slice(&sb.format_version.to_le_bytes());
    msg[27..59].copy_from_slice(&sb.manifest_sha256);
    msg
}

/// Verify the manifest signature against a set of trusted public keys.
///
/// Returns the index (within `trusted`) of the first key that produced a valid
/// signature. Distinguishes a genuine-but-untrusted signer
/// ([`Error::UntrustedSigner`]) from a forged/corrupt signature
/// ([`Error::SignatureInvalid`]).
pub fn verify_manifest_signature(
    sb: &Superblock,
    sig_block: &[u8],
    trusted: &[[u8; 32]],
) -> Result<usize> {
    let block = SignatureBlock::parse(sig_block)?;
    let msg = manifest_signing_input(sb);

    let mut saw_untrusted = false;
    for i in 0..block.count as usize {
        let (pubkey, sig) = block.record(i)?;
        if ed25519_verify(&pubkey, &msg, &sig) {
            if let Some(idx) = trusted.iter().position(|k| k == &pubkey) {
                return Ok(idx);
            }
            saw_untrusted = true;
        }
    }
    Err(if saw_untrusted {
        Error::UntrustedSigner
    } else {
        Error::SignatureInvalid
    })
}

/// Full volume verification (SPEC §7.5 steps 1–4).
///
/// On success the returned [`Manifest`] borrows `image` and may be served. This
/// does *not* hash every item up front; call [`verify_item`] before serving (or
/// lazily) to detect bit-rot.
pub fn verify_volume<'a>(
    image: &'a [u8],
    trusted: &[[u8; 32]],
) -> Result<(Superblock, Manifest<'a>)> {
    let sb = Superblock::parse(image)?;

    let manifest_bytes = sb.manifest(image)?;
    if sha256(manifest_bytes) != sb.manifest_sha256 {
        return Err(Error::ManifestHashMismatch);
    }

    let sig_block = sb.signature_block(image)?;
    verify_manifest_signature(&sb, sig_block, trusted)?;

    let manifest = Manifest::parse(manifest_bytes)?;
    Ok((sb, manifest))
}

/// Verify and borrow a single item's bytes against its recorded digest.
///
/// Use the slice directly to satisfy HTTP Range reads (SPEC §8).
pub fn verify_item<'a>(image: &'a [u8], rec: &ExtentRecord) -> Result<&'a [u8]> {
    let data = slice_u64(image, rec.data_offset, rec.data_length)?;
    if sha256(data) != rec.content_sha256 {
        return Err(Error::ContentHashMismatch);
    }
    Ok(data)
}
