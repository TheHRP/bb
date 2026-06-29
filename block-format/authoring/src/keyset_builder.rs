//! Build and root-sign a key-set envelope (SPEC §7.6).

use crate::keys::Keypair;
use bb_block_core::crypto::sha256;
use bb_block_core::format::*;
use bb_block_core::keyset::key_id;
use minicbor::Encoder;

struct KeyDef {
    pubkey: [u8; 32],
    caps: u32,
    not_before: u64,
    not_after: u64,
    label: String,
}

/// Accumulates project keys and revocations, then emits a root-signed `BKEY`
/// envelope.
pub struct KeySetBuilder {
    version: u64,
    created_unix: u64,
    keys: Vec<KeyDef>,
    revoked: Vec<[u8; 8]>,
}

impl KeySetBuilder {
    pub fn new(version: u64, created_unix: u64) -> KeySetBuilder {
        KeySetBuilder {
            version,
            created_unix,
            keys: Vec::new(),
            revoked: Vec::new(),
        }
    }

    /// Add a project key with the given capability bitmask. `not_before` /
    /// `not_after` of `0` mean "unbounded".
    pub fn add_key(
        &mut self,
        pubkey: [u8; 32],
        caps: u32,
        not_before: u64,
        not_after: u64,
        label: &str,
    ) -> &mut Self {
        self.keys.push(KeyDef {
            pubkey,
            caps,
            not_before,
            not_after,
            label: label.to_string(),
        });
        self
    }

    /// Explicitly revoke a key by its public key.
    pub fn revoke(&mut self, pubkey: &[u8; 32]) -> &mut Self {
        self.revoked.push(key_id(pubkey));
        self
    }

    /// Encode the canonical CBOR body that gets signed.
    pub fn encode_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        // Fixed field order for deterministic, reproducible bytes.
        e.map(5).unwrap();
        e.str("v").unwrap().u64(KEYSET_FORMAT as u64).unwrap();
        e.str("version").unwrap().u64(self.version).unwrap();
        e.str("created_unix")
            .unwrap()
            .u64(self.created_unix)
            .unwrap();

        e.str("keys").unwrap();
        e.array(self.keys.len() as u64).unwrap();
        for k in &self.keys {
            let mut fields = 2; // pubkey + caps
            if k.not_before != 0 {
                fields += 1;
            }
            if k.not_after != 0 {
                fields += 1;
            }
            if !k.label.is_empty() {
                fields += 1;
            }
            e.map(fields).unwrap();
            e.str("pubkey").unwrap().bytes(&k.pubkey).unwrap();
            e.str("caps").unwrap();
            let cap_strs = caps_to_strs(k.caps);
            e.array(cap_strs.len() as u64).unwrap();
            for s in &cap_strs {
                e.str(s).unwrap();
            }
            if k.not_before != 0 {
                e.str("not_before").unwrap().u64(k.not_before).unwrap();
            }
            if k.not_after != 0 {
                e.str("not_after").unwrap().u64(k.not_after).unwrap();
            }
            if !k.label.is_empty() {
                e.str("label").unwrap().str(&k.label).unwrap();
            }
        }

        e.str("revoked").unwrap();
        e.array(self.revoked.len() as u64).unwrap();
        for id in &self.revoked {
            e.bytes(id).unwrap();
        }
        buf
    }

    /// Build the full `BKEY` envelope, root-signed by `roots` (each must be a
    /// configured root key for nodes to accept it).
    pub fn seal(&self, roots: &[Keypair]) -> Vec<u8> {
        let body = self.encode_body();
        let body_hash = sha256(&body);

        // Signing input (SPEC §7.6.2): prefix || version (LE) || sha256(body).
        let mut msg = Vec::with_capacity(8 + 8 + 32);
        msg.extend_from_slice(KEYSET_SIG_PREFIX);
        msg.extend_from_slice(&self.version.to_le_bytes());
        msg.extend_from_slice(&body_hash);

        let mut env = Vec::new();
        env.extend_from_slice(&KEYSET_MAGIC);
        env.extend_from_slice(&KEYSET_FORMAT.to_le_bytes());
        env.extend_from_slice(&(roots.len() as u16).to_le_bytes());
        env.extend_from_slice(&(body.len() as u32).to_le_bytes());
        for r in roots {
            env.extend_from_slice(&r.public());
            env.extend_from_slice(&r.sign(&msg));
        }
        env.extend_from_slice(&body);
        env
    }
}

fn caps_to_strs(caps: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if caps & CAP_CONTENT != 0 {
        v.push("content");
    }
    if caps & CAP_MANAGEMENT != 0 {
        v.push("management");
    }
    v
}
