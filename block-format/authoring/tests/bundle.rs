//! Update-bundle apply tests: author a bundle with `bb-block`, validate + apply
//! with `bb-block-core`, and confirm the resulting volume verifies.

use bb_block::{
    BundleBuilder, ItemMeta, KeySetBuilder, Keypair, VolumeBuilder, CAP_CONTENT, CAP_MANAGEMENT,
};
use bb_block_core::{verify_bundle, verify_item, verify_keyset, verify_volume, Error, TrustConfig};

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A base volume with generous free capacity for in-place updates.
fn base_volume(signer: &Keypair) -> Vec<u8> {
    let mut b = VolumeBuilder::new([7u8; 16], 1_000).with_capacity(256 * 1024);
    b.add_item("a.txt", "A", "text/plain", "c", "en", b"alpha".to_vec());
    b.add_item("b.txt", "B", "text/plain", "c", "en", b"bravo".to_vec());
    b.seal(std::slice::from_ref(signer))
}

fn meta(path: &str) -> ItemMeta {
    ItemMeta {
        path: path.into(),
        title: path.into(),
        mime: "text/plain".into(),
        collection: "c".into(),
        language: "en".into(),
        added_unix: 2_000,
    }
}

/// Trust config naming `owner` as the sole content key, no key-set.
fn owner_trust(owner: &[[u8; 32]]) -> TrustConfig<'_> {
    TrustConfig {
        root_keys: &[],
        quorum: 0,
        current_keyset_version: 0,
        current_keyset: None,
        owner_keys: owner,
        now: 0,
    }
}

/// Read an item's verified bytes by id.
fn read(image: &[u8], trusted: &[[u8; 32]], id: u32) -> Vec<u8> {
    let (_, manifest) = verify_volume(image, trusted).unwrap();
    let rec = manifest.lookup(id).unwrap().unwrap();
    verify_item(image, &rec).unwrap().to_vec()
}

#[test]
fn replace_item_roundtrip() {
    let owner = Keypair::from_seed(&seed(1));
    let mut image = base_volume(&owner);
    let trusted = [owner.public()];

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.replace(1, b"ALPHA-v2-longer".to_vec(), None).unwrap();
    let bundle = bb.seal(std::slice::from_ref(&owner)).unwrap();

    let verified = verify_bundle(&image, &bundle, &owner_trust(&trusted)).unwrap();
    verified.execute(&mut image).unwrap();

    // Whole volume still verifies; item 1 changed, item 2 untouched.
    verify_volume(&image, &trusted).expect("updated volume verifies");
    assert_eq!(read(&image, &trusted, 1), b"ALPHA-v2-longer");
    assert_eq!(read(&image, &trusted, 2), b"bravo");
}

#[test]
fn add_and_delete_items() {
    let owner = Keypair::from_seed(&seed(1));
    let mut image = base_volume(&owner);
    let trusted = [owner.public()];

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.delete(2);
    let new_id = bb.add(meta("c.txt"), b"charlie-content".to_vec());
    let bundle = bb.seal(std::slice::from_ref(&owner)).unwrap();

    let verified = verify_bundle(&image, &bundle, &owner_trust(&trusted)).unwrap();
    verified.execute(&mut image).unwrap();

    let (sb, manifest) = verify_volume(&image, &trusted).unwrap();
    assert_eq!(sb.item_count, 2); // a.txt + c.txt
    assert!(manifest.lookup(2).unwrap().is_none()); // b deleted
    assert_eq!(read(&image, &trusted, 1), b"alpha");
    assert_eq!(read(&image, &trusted, new_id), b"charlie-content");
}

#[test]
fn deleted_space_is_reclaimed() {
    // Tight-ish capacity: a delete must free room for a same-size add.
    let owner = Keypair::from_seed(&seed(1));
    let mut b = VolumeBuilder::new([7u8; 16], 1).with_capacity(64 * 1024);
    let big = vec![0xABu8; 20 * 1024];
    b.add_item(
        "big.bin",
        "big",
        "application/octet-stream",
        "c",
        "en",
        big.clone(),
    );
    let mut image = b.seal(std::slice::from_ref(&owner));
    let trusted = [owner.public()];

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.delete(1);
    let id = bb.add(meta("big2.bin"), vec![0xCDu8; 20 * 1024]);
    // Succeeds only because deleting item 1 frees its 20 KiB.
    let bundle = bb.seal(std::slice::from_ref(&owner)).unwrap();
    let verified = verify_bundle(&image, &bundle, &owner_trust(&trusted)).unwrap();
    verified.execute(&mut image).unwrap();

    assert_eq!(read(&image, &trusted, id), vec![0xCDu8; 20 * 1024]);
}

#[test]
fn out_of_capacity_is_rejected() {
    // No slack beyond the laid-out image: a larger replacement cannot fit.
    let owner = Keypair::from_seed(&seed(1));
    let image = base_volume(&owner); // default tight capacity? base has 256K slack
                                     // Rebuild with no slack.
    let mut b = VolumeBuilder::new([7u8; 16], 1); // capacity defaults to image length
    b.add_item("a.txt", "A", "text/plain", "c", "en", b"alpha".to_vec());
    let tight = b.seal(std::slice::from_ref(&owner));
    let _ = image;

    let mut bb = BundleBuilder::from_volume(&tight).unwrap();
    bb.replace(1, vec![0u8; 100 * 1024], None).unwrap();
    assert_eq!(
        bb.seal(std::slice::from_ref(&owner)).err().unwrap(),
        Error::CapacityExceeded
    );
}

#[test]
fn untrusted_bundle_signer_is_rejected() {
    let owner = Keypair::from_seed(&seed(1));
    let stranger = Keypair::from_seed(&seed(99));
    let image = base_volume(&owner);

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.replace(1, b"x".to_vec(), None).unwrap();
    // Bundle's new manifest is signed by a stranger.
    let bundle = bb.seal(std::slice::from_ref(&stranger)).unwrap();

    let owner_pub = [owner.public()];
    let trust = owner_trust(&owner_pub);
    assert_eq!(
        verify_bundle(&image, &bundle, &trust).err().unwrap(),
        Error::UntrustedSigner
    );
}

#[test]
fn base_mismatch_after_first_apply() {
    let owner = Keypair::from_seed(&seed(1));
    let mut image = base_volume(&owner);
    let trusted = [owner.public()];

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.replace(1, b"once".to_vec(), None).unwrap();
    let bundle = bb.seal(std::slice::from_ref(&owner)).unwrap();

    // First apply succeeds.
    verify_bundle(&image, &bundle, &owner_trust(&trusted))
        .unwrap()
        .execute(&mut image)
        .unwrap();

    // Re-applying the same bundle now fails the base-manifest check.
    assert_eq!(
        verify_bundle(&image, &bundle, &owner_trust(&trusted))
            .err()
            .unwrap(),
        Error::BaseMismatch
    );
}

// ---- Key-set-driven authorization ---------------------------------------

fn five_roots() -> Vec<Keypair> {
    (0..5).map(|i| Keypair::from_seed(&seed(100 + i))).collect()
}

#[test]
fn courier_authorized_via_keyset() {
    let owner = Keypair::from_seed(&seed(1));
    let courier = Keypair::from_seed(&seed(2));
    let mut image = base_volume(&owner);

    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let mut ksb = KeySetBuilder::new(1, 1);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "courier");
    let envelope = ksb.seal(&roots[0..3]);
    let ks = verify_keyset(&envelope, &root_pubs, 3, 0).unwrap();

    // Courier signs the update; trust comes from the key-set, not owner keys.
    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.replace(2, b"bravo-by-courier".to_vec(), None).unwrap();
    let bundle = bb.seal(std::slice::from_ref(&courier)).unwrap();

    let trust = TrustConfig {
        root_keys: &root_pubs,
        quorum: 3,
        current_keyset_version: 0,
        current_keyset: Some(&ks),
        owner_keys: &[],
        now: 0,
    };
    verify_bundle(&image, &bundle, &trust)
        .unwrap()
        .execute(&mut image)
        .unwrap();
    assert_eq!(read(&image, &[courier.public()], 2), b"bravo-by-courier");
}

#[test]
fn management_only_key_cannot_sign_content() {
    let owner = Keypair::from_seed(&seed(1));
    let admin = Keypair::from_seed(&seed(2));
    let image = base_volume(&owner);

    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let mut ksb = KeySetBuilder::new(1, 1);
    ksb.add_key(admin.public(), CAP_MANAGEMENT, 0, 0, "admin");
    let envelope = ksb.seal(&roots[0..3]);
    let ks = verify_keyset(&envelope, &root_pubs, 3, 0).unwrap();

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.replace(1, b"nope".to_vec(), None).unwrap();
    let bundle = bb.seal(std::slice::from_ref(&admin)).unwrap();

    let trust = TrustConfig {
        root_keys: &root_pubs,
        quorum: 3,
        current_keyset_version: 0,
        current_keyset: Some(&ks),
        owner_keys: &[],
        now: 0,
    };
    assert_eq!(
        verify_bundle(&image, &bundle, &trust).err().unwrap(),
        Error::UntrustedSigner
    );
}

#[test]
fn embedded_keyset_propagates_then_authorizes() {
    // A bundle carries a *newer* key-set that first introduces the courier; the
    // node processes it, then authorizes the bundle's signer against it.
    let owner = Keypair::from_seed(&seed(1));
    let courier = Keypair::from_seed(&seed(2));
    let mut image = base_volume(&owner);

    let roots = five_roots();
    let root_pubs: Vec<[u8; 32]> = roots.iter().map(|r| r.public()).collect();
    let mut ksb = KeySetBuilder::new(7, 1);
    ksb.add_key(courier.public(), CAP_CONTENT, 0, 0, "courier");
    let envelope = ksb.seal(&roots[0..3]);

    let mut bb = BundleBuilder::from_volume(&image).unwrap();
    bb.replace(1, b"alpha-v2".to_vec(), None).unwrap();
    bb.with_keyset(envelope);
    let bundle = bb.seal(std::slice::from_ref(&courier)).unwrap();

    // Node currently has no key-set (version 0) and does not know the courier.
    let trust = TrustConfig {
        root_keys: &root_pubs,
        quorum: 3,
        current_keyset_version: 0,
        current_keyset: None,
        owner_keys: &[],
        now: 0,
    };
    let verified = verify_bundle(&image, &bundle, &trust).unwrap();
    assert_eq!(verified.new_keyset_version, Some(7));
    verified.execute(&mut image).unwrap();
    assert_eq!(read(&image, &[courier.public()], 1), b"alpha-v2");
}
