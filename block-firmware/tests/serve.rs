//! Host tests: author a volume with `bb-block`, mount it from `SliceStorage`,
//! and exercise the SPEC §8 read API end to end.

use bb_block::{Keypair, VolumeBuilder};
use bb_node::http::{Body, Method, RangeReq, Request, Response};
use bb_node::{Node, SliceStorage, Storage};

/// Build a 2-item volume; return (image, signer pubkey).
fn volume() -> (Vec<u8>, [u8; 32]) {
    let k = Keypair::from_seed(&[1u8; 32]);
    let mut b = VolumeBuilder::new([5u8; 16], 100).with_capacity(64 * 1024);
    b.add_item(
        "a.txt",
        "A",
        "text/plain",
        "c",
        "en",
        b"hello world".to_vec(),
    );
    b.add_item(
        "b.bin",
        "B",
        "application/octet-stream",
        "c",
        "en",
        (0..50u8).collect(),
    );
    (b.seal(std::slice::from_ref(&k)), k.public())
}

fn get(path: &str, range: Option<RangeReq>) -> Request {
    Request {
        method: Method::Get,
        path: path.to_string(),
        range,
    }
}

/// Read a storage-descriptor body into bytes.
fn body_bytes(storage: &impl Storage, resp: &Response) -> Vec<u8> {
    match &resp.body {
        Body::Storage { offset, len } => {
            let mut buf = vec![0u8; *len as usize];
            storage.read(*offset, &mut buf).unwrap();
            buf
        }
        Body::Bytes(b) => b.clone(),
        Body::Empty => Vec::new(),
    }
}

#[test]
fn mount_and_health() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).expect("mounts");
    assert_eq!(node.superblock().item_count, 2);

    let resp = node.handle(&get("/v1/health", None));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, "application/json");
    let json = String::from_utf8(body_bytes(&storage, &resp)).unwrap();
    assert!(json.contains("\"item_count\":2"));
    assert!(json.contains("\"format_version\":1"));
}

#[test]
fn mount_rejects_untrusted() {
    let (mut image, _pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let stranger = Keypair::from_seed(&[9u8; 32]).public();
    assert!(Node::mount(&storage, &[stranger]).is_err());
}

#[test]
fn get_full_item() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();

    let resp = node.handle(&get("/v1/item/1", None));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_length, 11);
    assert!(resp.accept_ranges);
    assert!(resp.etag.is_some());
    assert_eq!(body_bytes(&storage, &resp), b"hello world");
}

#[test]
fn get_range() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();

    // bytes=0-4 of "hello world" => "hello"
    let resp = node.handle(&get(
        "/v1/item/1",
        Some(RangeReq {
            start: 0,
            end: Some(4),
        }),
    ));
    assert_eq!(resp.status, 206);
    assert_eq!(resp.content_length, 5);
    assert_eq!(resp.content_range, Some((0, 4, 11)));
    assert_eq!(body_bytes(&storage, &resp), b"hello");

    // bytes=6- (to end) => "world"
    let resp = node.handle(&get(
        "/v1/item/1",
        Some(RangeReq {
            start: 6,
            end: None,
        }),
    ));
    assert_eq!(resp.status, 206);
    assert_eq!(body_bytes(&storage, &resp), b"world");
}

#[test]
fn range_past_end_is_416() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();

    let resp = node.handle(&get(
        "/v1/item/1",
        Some(RangeReq {
            start: 100,
            end: None,
        }),
    ));
    assert_eq!(resp.status, 416);
}

#[test]
fn head_has_no_body() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();

    let req = Request {
        method: Method::Head,
        path: "/v1/item/2".to_string(),
        range: None,
    };
    let resp = node.handle(&req);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_length, 50);
    assert!(matches!(resp.body, Body::Empty));
}

#[test]
fn unknown_item_and_path() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();

    assert_eq!(node.handle(&get("/v1/item/999", None)).status, 404);
    assert_eq!(node.handle(&get("/nope", None)).status, 404);
    assert_eq!(node.handle(&get("/v1/item/abc", None)).status, 400);
}

#[test]
fn manifest_endpoint_returns_metadata() {
    let (mut image, pk) = volume();
    let storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();

    let resp = node.handle(&get("/v1/manifest", None));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, "application/cbor");
    assert_eq!(body_bytes(&storage, &resp), node.metadata());
}

#[test]
fn integrity_scan_detects_bitrot() {
    let (mut image, pk) = volume();
    let mut storage = SliceStorage::new(&mut image);
    let node = Node::mount(&storage, &[pk]).unwrap();
    let mut scratch = [0u8; 8];

    assert!(node.verify_item(&storage, 1, &mut scratch).unwrap());

    // Corrupt one byte of item 1's data and rescan.
    let rec = node.item(1).unwrap();
    storage.write(rec.data_offset, &[0x00]).unwrap();
    assert!(!node.verify_item(&storage, 1, &mut scratch).unwrap());
}

#[test]
fn request_parsing() {
    let raw = b"GET /v1/item/2 HTTP/1.1\r\nHost: bruce\r\nRange: bytes=2-4\r\n\r\n";
    let req = Request::parse(raw).unwrap();
    assert_eq!(req.method, Method::Get);
    assert_eq!(req.path, "/v1/item/2");
    assert_eq!(
        req.range,
        Some(RangeReq {
            start: 2,
            end: Some(4)
        })
    );
}

#[test]
fn response_head_rendering() {
    let resp = Response {
        status: 206,
        content_type: "application/octet-stream",
        content_length: 5,
        etag: Some([0xab; 32]),
        accept_ranges: true,
        content_range: Some((0, 4, 11)),
        body: Body::Empty,
    };
    let head = resp.write_head();
    assert!(head.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(head.contains("Content-Length: 5\r\n"));
    assert!(head.contains("Accept-Ranges: bytes\r\n"));
    assert!(head.contains("Content-Range: bytes 0-4/11\r\n"));
    assert!(head.contains("ETag: \""));
    assert!(head.ends_with("\r\n\r\n"));
}
