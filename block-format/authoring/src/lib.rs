//! # bb-block
//!
//! Authoring side of the Bruce's Bunker block format: build content volumes,
//! sign manifests, and produce root-signed key-sets. Runs on a real computer
//! (the `writer` / `indexer` / key-management tooling), not the ESP32.
//!
//! Verification of everything produced here lives in the shared `bb-block-core`
//! crate, so a round-trip test exercises both sides of the contract.

mod builder;
mod bundle;
mod keys;
mod keyset_builder;
mod manifest;

pub use builder::{sign_manifest, Item, VolumeBuilder};
pub use bundle::BundleBuilder;
pub use keys::Keypair;
pub use keyset_builder::KeySetBuilder;
pub use manifest::{ItemMeta, ManifestEntry};

// Re-export the capability flags so authoring callers don't need both crates.
pub use bb_block_core::{CAP_CONTENT, CAP_MANAGEMENT};
