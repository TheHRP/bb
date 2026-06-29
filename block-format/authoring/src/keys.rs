//! Thin wrapper over Ed25519 signing keys for authoring tools and tests.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// An Ed25519 keypair used to sign manifests, bundles, or key-sets.
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Construct from a 32-byte seed. Deterministic — ideal for reproducible
    /// builds and test vectors. Production key generation should use a CSPRNG
    /// seed.
    pub fn from_seed(seed: &[u8; 32]) -> Keypair {
        Keypair {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte public key.
    pub fn public(&self) -> [u8; 32] {
        VerifyingKey::from(&self.signing).to_bytes()
    }

    /// Sign `msg`, returning the 64-byte detached signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}
