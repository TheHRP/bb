//! End-to-end tests: author with `bb-block`, verify with `bb-block-core`.
//! These double as the seed of the cross-implementation conformance suite.

use bb_block::{KeySetBuilder, Keypair, VolumeBuilder, CAP_CONTENT, CAP_MANAGEMENT};
use bb_block_core::{verify_item, verify_keyset, verify_volume, Error};

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn sample_volume(signer: &Keypair) -> Vec<u8> {
    let mut b = VolumeBuilder::new([7u8; 16], 1_719_600_000);
    b.add_item(
        "gutenberg/frankenstein.txt",
        "Frankenstein",
        "text/plain",
        "gutenberg",
        "en",
        b"You will rejoice to hear that no disaster has accompanied...".to_vec(),
    );
    b.add_item(
        "wikipedia/en/Bunker.html",
        "Bunker",
        "text/html",
        "wikimedia-en",
        "en",
        b"<html><body>A bunker is a defensive military fortification.</body></html>".to_vec(),
    );
    b.seal(std::slice::from_ref(signer))
}

#[test]
fn happy_path_verify_and_fetch() {
    let project = Keypair::from_seed(&seed(1));
    let image = sample_volume(&project);

    let trusted = [project.public()];
    let (sb, manifest) = verify_volume(&image, &trusted).expect("volume verifies");
    assert_eq!(sb.item_count, 2);
    assert_eq!(manifest.len(), 2);

    // Lookup + content verification (the HTTP Range read path).
    let rec = manifest.lookup(2).unwrap().expect("item 2 present");
    let bytes = verify_item(&image, &rec).expect("content matches digest");
    assert!(bytes.starts_with(b"<html>"));

    // Missing ids return None, not an error.
    assert!(manifest.lookup(999).unwrap().is_none());
}

#[test]
fn untrusted_signer_is_rejected() {
    let project = Keypair::from_seed(&seed(1));
    let stranger = Keypair::from_seed(&seed(42));
    let image = sample_volume(&project);

    // Trust store does not include the actual signer.
    let err = verify_volume(&image, &[stranger.public()]).unwrap_err();
    assert_eq!(err, Error::UntrustedSigner);
}

#[test]
fn tampered_content_is_detected() {
    let project = Keypair::from_seed(&seed(1));
    let mut image = sample_volume(&project);
    let trusted = [project.public()];

    // Volume-level verification still passes (manifest untouched)...
    let (_, manifest) = verify_volume(&image, &trusted).unwrap();
    let rec = manifest.lookup(1).unwrap().unwrap();

    // ...but flipping a content byte fails the per-item digest.
    let off = rec.data_offset as usize;
    image[off] ^= 0xFF;
    let (_, manifest) = verify_volume(&image, &trusted).unwrap();
    let rec = manifest.lookup(1).unwrap().unwrap();
    assert_eq!(
        verify_item(&image, &rec).unwrap_err(),
        Error::ContentHashMismatch
    );
}

#[test]
fn tampered_manifest_is_detected() {
    let project = Keypair::from_seed(&seed(1));
    let mut image = sample_volume(&project);
    let trusted = [project.public()];

    let sb = bb_block_core::Superblock::parse(&image).unwrap();
    // Flip a byte inside the manifest region.
    image[sb.manifest_offset as usize + 4] ^= 0x01;
    assert_eq!(
        verify_volume(&image, &trusted).unwrap_err(),
        Error::ManifestHashMismatch
    );
}

#[test]
fn multi_signer_owner_and_project() {
    let owner = Keypair::from_seed(&seed(10));
    let project = Keypair::from_seed(&seed(11));
    let mut b = VolumeBuilder::new([9u8; 16], 1);
    b.add_item("a.txt", "A", "text/plain", "misc", "en", b"hello".to_vec());
    let image = b.seal(&[owner.clone(), project.clone()]);

    // A node trusting only the project key still verifies (co-signed).
    verify_volume(&image, &[project.public()]).expect("project co-sign accepted");
    // A node trusting only the owner key also verifies.
    verify_volume(&image, &[owner.public()]).expect("owner co-sign accepted");
}

// ---- Key-set tests -------------------------------------------------------

fn five_roots() -> Vec<Keypair> {
    (0..5).map(|i| Keypair::from_seed(&seed(100 + i))).collect()
}

#[test]
fn keyset_quorum_and_capabilities() {
    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();

    let courier = Keypair::from_seed(&seed(1));
    let admin = Keypair::from_seed(&seed(2));

    let mut ksb = KeySetBuilder::new(5, 1_719_600_000);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "courier-eu-1");
    ksb.add_key(
        admin.public(),
        CAP_CONTENT | CAP_MANAGEMENT,
        0,
        0,
        "admin-1",
    );

    // Sign with 3 of the 5 roots.
    let envelope = ksb.seal(&roots[0..3]);

    // Quorum of 3 satisfied; current_version 4 < 5 so it is accepted.
    let ks = verify_keyset(&envelope, &root_pubs, 3, 4).expect("quorum met");
    assert_eq!(ks.version, 5);

    // Capability checks (now = 0 => skip time window).
    assert!(ks.authorizes(&courier.public(), CAP_CONTENT, 0));
    assert!(!ks.authorizes(&courier.public(), CAP_MANAGEMENT, 0));
    assert!(ks.authorizes(&admin.public(), CAP_MANAGEMENT, 0));

    // collect_keys yields exactly the content-capable keys.
    let mut buf = [[0u8; 32]; 8];
    let n = ks.collect_keys(CAP_CONTENT, 0, &mut buf);
    assert_eq!(n, 2);
}

#[test]
fn keyset_quorum_not_met() {
    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let courier = Keypair::from_seed(&seed(1));

    let mut ksb = KeySetBuilder::new(2, 1);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "c");
    let envelope = ksb.seal(&roots[0..2]); // only 2 signatures

    assert_eq!(
        verify_keyset(&envelope, &root_pubs, 3, 0).unwrap_err(),
        Error::QuorumNotMet
    );
}

#[test]
fn keyset_rollback_is_rejected() {
    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let courier = Keypair::from_seed(&seed(1));

    let mut ksb = KeySetBuilder::new(5, 1);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "c");
    let envelope = ksb.seal(&roots[0..3]);

    // Node already at version 5 must refuse a candidate of version 5.
    assert_eq!(
        verify_keyset(&envelope, &root_pubs, 3, 5).unwrap_err(),
        Error::KeysetRollback
    );
}

#[test]
fn keyset_revocation_denies_authorization() {
    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let courier = Keypair::from_seed(&seed(1));

    let mut ksb = KeySetBuilder::new(6, 1);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "c");
    ksb.revoke(&courier.public());
    let envelope = ksb.seal(&roots[0..3]);

    let ks = verify_keyset(&envelope, &root_pubs, 3, 0).unwrap();
    assert!(!ks.authorizes(&courier.public(), CAP_CONTENT, 0));
}

#[test]
fn keyset_validity_window_enforced() {
    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let courier = Keypair::from_seed(&seed(1));

    let mut ksb = KeySetBuilder::new(7, 1);
    // Valid only within [1000, 2000].
    ksb.add_key(courier.public(), CAP_CONTENT, 1000, 2000, "c");
    let envelope = ksb.seal(&roots[0..3]);
    let ks = verify_keyset(&envelope, &root_pubs, 3, 0).unwrap();

    assert!(!ks.authorizes(&courier.public(), CAP_CONTENT, 500)); // before
    assert!(ks.authorizes(&courier.public(), CAP_CONTENT, 1500)); // within
    assert!(!ks.authorizes(&courier.public(), CAP_CONTENT, 2500)); // after
    assert!(ks.authorizes(&courier.public(), CAP_CONTENT, 0)); // clockless => skip
}

#[test]
fn end_to_end_keyset_drives_volume_trust() {
    // The realistic flow: roots issue a key-set; a node derives its content
    // trust from that key-set; a volume signed by a listed courier verifies.
    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let courier = Keypair::from_seed(&seed(1));

    let mut ksb = KeySetBuilder::new(1, 1);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "courier");
    let envelope = ksb.seal(&roots[0..3]);
    let ks = verify_keyset(&envelope, &root_pubs, 3, 0).unwrap();

    let mut trust = [[0u8; 32]; 8];
    let n = ks.collect_keys(CAP_CONTENT, 0, &mut trust);

    let image = sample_volume(&courier);
    verify_volume(&image, &trust[..n]).expect("courier-signed volume trusted via key-set");
}
