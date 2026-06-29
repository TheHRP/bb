//! The signed, monotonically-versioned key-set (SPEC §7.6).
//!
//! Project keys are *not* hardcoded; they arrive in this root-signed document.
//! Parsing is fixed-capacity and allocation-free so it runs on the ESP32.

use crate::crypto::{ed25519_verify, sha256};
use crate::error::{Error, Result};
use crate::format::*;
use minicbor::Decoder;

/// Max project keys a single build will hold. Tune per target; ample for the
/// project + courier roster.
pub const MAX_KEYS: usize = 32;
/// Max explicit revocations carried in one key-set.
pub const MAX_REVOKED: usize = 64;
/// Max root keys (bounded so the quorum dedup bitmask fits in a `u32`).
pub const MAX_ROOT_KEYS: usize = 32;

/// One project key and its delegated capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEntry {
    /// First 8 bytes of `SHA-256(pubkey)`; referenced by the revocation list.
    pub id: [u8; 8],
    pub pubkey: [u8; 32],
    /// Bitmask of `CAP_*` flags.
    pub caps: u32,
    /// Unix seconds; `0` means no lower bound.
    pub not_before: u64,
    /// Unix seconds; `0` means no expiry.
    pub not_after: u64,
}

const EMPTY_KEY: KeyEntry = KeyEntry {
    id: [0u8; 8],
    pubkey: [0u8; 32],
    caps: 0,
    not_before: 0,
    not_after: 0,
};

/// A parsed, capability-bearing set of project keys.
#[derive(Debug, Clone)]
pub struct KeySet {
    pub version: u64,
    pub created_unix: u64,
    keys: [KeyEntry; MAX_KEYS],
    key_len: usize,
    revoked: [[u8; 8]; MAX_REVOKED],
    rev_len: usize,
}

/// Derive a key id from its public key.
pub fn key_id(pubkey: &[u8; 32]) -> [u8; 8] {
    let h = sha256(pubkey);
    let mut id = [0u8; 8];
    id.copy_from_slice(&h[..8]);
    id
}

/// Split a `BKEY` envelope into its signature records and signed body.
pub struct Envelope<'a> {
    pub sig_count: u16,
    pub sigs: &'a [u8],
    pub body: &'a [u8],
}

impl<'a> Envelope<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Envelope<'a>> {
        let hdr = take(buf, 0, KEYSET_HEADER_LEN)?;
        if hdr[0..4] != KEYSET_MAGIC {
            return Err(Error::BadMagic);
        }
        if u16le(hdr, 4)? != KEYSET_FORMAT {
            return Err(Error::UnsupportedVersion);
        }
        let sig_count = u16le(hdr, 6)?;
        let body_len = u32le(hdr, 8)? as usize;
        let sigs_len = (sig_count as usize)
            .checked_mul(SIG_RECORD_LEN)
            .ok_or(Error::Malformed)?;
        let sigs = take(buf, KEYSET_HEADER_LEN, sigs_len)?;
        let body = take(buf, KEYSET_HEADER_LEN + sigs_len, body_len)?;
        Ok(Envelope {
            sig_count,
            sigs,
            body,
        })
    }

    fn sig(&self, i: usize) -> Result<(&'a [u8], &'a [u8])> {
        let rec = take(self.sigs, i * SIG_RECORD_LEN, SIG_RECORD_LEN)?;
        Ok((&rec[0..32], &rec[32..96]))
    }
}

/// Verify a candidate key-set envelope and, on success, return the parsed set.
///
/// Enforces (SPEC §7.6.3):
/// 1. at least `quorum` signatures from **distinct** root keys verify, and
/// 2. `version` is strictly greater than `current_version` (rollback guard).
pub fn verify_keyset(
    envelope: &[u8],
    root_keys: &[[u8; 32]],
    quorum: usize,
    current_version: u64,
) -> Result<KeySet> {
    if root_keys.len() > MAX_ROOT_KEYS {
        return Err(Error::CapacityExceeded);
    }
    let env = Envelope::parse(envelope)?;
    let set = KeySet::parse_body(env.body)?;

    if set.version <= current_version {
        return Err(Error::KeysetRollback);
    }

    // Signing input: prefix || version (LE) || sha256(body)  (SPEC §7.6.2)
    let body_hash = sha256(env.body);
    let mut msg = [0u8; 8 + 8 + 32];
    msg[..8].copy_from_slice(KEYSET_SIG_PREFIX);
    msg[8..16].copy_from_slice(&set.version.to_le_bytes());
    msg[16..].copy_from_slice(&body_hash);

    let mut used: u32 = 0;
    let mut valid = 0usize;
    for i in 0..env.sig_count as usize {
        let (pubkey, sig) = env.sig(i)?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(pubkey);
        let mut s = [0u8; 64];
        s.copy_from_slice(sig);
        if let Some(idx) = root_keys.iter().position(|r| r == &pk) {
            let bit = 1u32 << idx;
            if used & bit == 0 && ed25519_verify(&pk, &msg, &s) {
                used |= bit;
                valid += 1;
            }
        }
    }
    if valid < quorum {
        return Err(Error::QuorumNotMet);
    }
    Ok(set)
}

impl KeySet {
    /// Decode the CBOR body (SPEC §7.6.1). Does **not** check signatures — use
    /// [`verify_keyset`] for the trusted path.
    pub fn parse_body(body: &[u8]) -> Result<KeySet> {
        let mut d = Decoder::new(body);
        let mut set = KeySet {
            version: 0,
            created_unix: 0,
            keys: [EMPTY_KEY; MAX_KEYS],
            key_len: 0,
            revoked: [[0u8; 8]; MAX_REVOKED],
            rev_len: 0,
        };

        let n = d.map().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
        for _ in 0..n {
            let field = d.str().map_err(|_| Error::Cbor)?;
            match field {
                "v" => {
                    if d.u64().map_err(|_| Error::Cbor)? != KEYSET_FORMAT as u64 {
                        return Err(Error::UnsupportedVersion);
                    }
                }
                "version" => set.version = d.u64().map_err(|_| Error::Cbor)?,
                "created_unix" => set.created_unix = d.u64().map_err(|_| Error::Cbor)?,
                "keys" => set.parse_keys(&mut d)?,
                "revoked" => set.parse_revoked(&mut d)?,
                _ => d.skip().map_err(|_| Error::Cbor)?,
            }
        }
        Ok(set)
    }

    fn parse_keys(&mut self, d: &mut Decoder) -> Result<()> {
        let kn = d.array().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
        for _ in 0..kn {
            if self.key_len >= MAX_KEYS {
                return Err(Error::CapacityExceeded);
            }
            let mut entry = EMPTY_KEY;
            let fields = d.map().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
            for _ in 0..fields {
                let f = d.str().map_err(|_| Error::Cbor)?;
                match f {
                    "pubkey" => {
                        let b = d.bytes().map_err(|_| Error::Cbor)?;
                        if b.len() != 32 {
                            return Err(Error::Malformed);
                        }
                        entry.pubkey.copy_from_slice(b);
                    }
                    "caps" => entry.caps = parse_caps(d)?,
                    "not_before" => entry.not_before = d.u64().map_err(|_| Error::Cbor)?,
                    "not_after" => entry.not_after = d.u64().map_err(|_| Error::Cbor)?,
                    _ => d.skip().map_err(|_| Error::Cbor)?,
                }
            }
            entry.id = key_id(&entry.pubkey);
            self.keys[self.key_len] = entry;
            self.key_len += 1;
        }
        Ok(())
    }

    fn parse_revoked(&mut self, d: &mut Decoder) -> Result<()> {
        let rn = d.array().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
        for _ in 0..rn {
            if self.rev_len >= MAX_REVOKED {
                return Err(Error::CapacityExceeded);
            }
            let b = d.bytes().map_err(|_| Error::Cbor)?;
            if b.len() != 8 {
                return Err(Error::Malformed);
            }
            self.revoked[self.rev_len].copy_from_slice(b);
            self.rev_len += 1;
        }
        Ok(())
    }

    /// All project keys in the set.
    pub fn keys(&self) -> &[KeyEntry] {
        &self.keys[..self.key_len]
    }

    pub fn is_revoked(&self, id: &[u8; 8]) -> bool {
        self.revoked[..self.rev_len].iter().any(|r| r == id)
    }

    pub fn find_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<&KeyEntry> {
        self.keys().iter().find(|k| &k.pubkey == pubkey)
    }

    /// Whether `pubkey` is currently authorized for `cap`.
    ///
    /// `now` is unix seconds; pass `0` when the node has no trustworthy clock,
    /// which skips the validity-window check (SPEC §7.7).
    pub fn authorizes(&self, pubkey: &[u8; 32], cap: u32, now: u64) -> bool {
        match self.find_by_pubkey(pubkey) {
            Some(k) => {
                if self.is_revoked(&k.id) {
                    return false;
                }
                if k.caps & cap == 0 {
                    return false;
                }
                if now != 0 {
                    if k.not_before != 0 && now < k.not_before {
                        return false;
                    }
                    if k.not_after != 0 && now > k.not_after {
                        return false;
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Collect the public keys currently authorized for `cap` into `out`,
    /// returning how many were written. Allocation-free; truncates at
    /// `out.len()`.
    pub fn collect_keys(&self, cap: u32, now: u64, out: &mut [[u8; 32]]) -> usize {
        let mut n = 0;
        for k in self.keys() {
            if n >= out.len() {
                break;
            }
            if self.authorizes(&k.pubkey, cap, now) {
                out[n] = k.pubkey;
                n += 1;
            }
        }
        n
    }
}

fn parse_caps(d: &mut Decoder) -> Result<u32> {
    let mut caps = 0u32;
    let n = d.array().map_err(|_| Error::Cbor)?.ok_or(Error::Cbor)?;
    for _ in 0..n {
        match d.str().map_err(|_| Error::Cbor)? {
            "content" => caps |= CAP_CONTENT,
            "management" => caps |= CAP_MANAGEMENT,
            _ => {}
        }
    }
    Ok(caps)
}
