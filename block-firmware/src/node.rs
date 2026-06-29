//! The node: mount a volume from [`Storage`], verify it, and answer the SPEC §8
//! read API. Item bodies are returned as storage descriptors so the platform
//! streams them without this crate touching the network.

use crate::http::{hex_uuid, json_object, Body, JsonValue, Method, Request, Response};
use crate::storage::{Storage, StorageError};
use alloc::vec;
use alloc::vec::Vec;
use bb_block_core::crypto::sha256;
use bb_block_core::format::SUPERBLOCK_LEN;
use bb_block_core::{
    verify_manifest_signature, Error as FmtError, ExtentRecord, Manifest, Superblock,
};
use sha2::{Digest, Sha256};

/// Failure mounting or serving a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeError {
    Storage(StorageError),
    Format(FmtError),
}

impl From<StorageError> for NodeError {
    fn from(e: StorageError) -> Self {
        NodeError::Storage(e)
    }
}
impl From<FmtError> for NodeError {
    fn from(e: FmtError) -> Self {
        NodeError::Format(e)
    }
}

/// A mounted, verified volume ready to serve.
pub struct Node {
    sb: Superblock,
    /// The verified manifest payload, held in RAM (PSRAM on device).
    manifest_buf: Vec<u8>,
}

impl Node {
    /// Read the superblock, manifest, and signature block from `storage`, verify
    /// the manifest hash and a trusted signature (SPEC §7.5), and retain the
    /// manifest for serving. `trusted` is the effective content-trust set
    /// (owner keys ∪ key-set content keys).
    pub fn mount<S: Storage>(storage: &S, trusted: &[[u8; 32]]) -> Result<Node, NodeError> {
        let mut sb_buf = [0u8; SUPERBLOCK_LEN];
        storage.read(0, &mut sb_buf)?;
        let sb = Superblock::parse(&sb_buf)?;

        let manifest_buf = read_region(storage, sb.manifest_offset, sb.manifest_length)?;
        if sha256(&manifest_buf) != sb.manifest_sha256 {
            return Err(NodeError::Format(FmtError::ManifestHashMismatch));
        }

        let sig_buf = read_region(storage, sb.sig_offset, sb.sig_length)?;
        verify_manifest_signature(&sb, &sig_buf, trusted)?;

        // Confirm the retained manifest parses.
        Manifest::parse(&manifest_buf)?;
        Ok(Node { sb, manifest_buf })
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    fn manifest(&self) -> Manifest<'_> {
        // Safe: validated at mount.
        Manifest::parse(&self.manifest_buf).expect("manifest validated at mount")
    }

    /// The CBOR metadata document (SPEC §5.2), for the UI/portal.
    pub fn metadata(&self) -> &[u8] {
        self.manifest().metadata()
    }

    /// Look up an item's extent record.
    pub fn item(&self, item_id: u32) -> Option<ExtentRecord> {
        self.manifest().lookup(item_id).ok().flatten()
    }

    /// Route a parsed request to a response (SPEC §8). Item bodies are storage
    /// descriptors; `/v1/health` and `/v1/manifest` carry in-RAM bytes.
    pub fn handle(&self, req: &Request) -> Response {
        match req.method {
            Method::Get | Method::Head => {}
            Method::Other => return simple(405),
        }

        if req.path == "/v1/health" {
            return self.health();
        }
        if req.path == "/v1/manifest" {
            return Response {
                status: 200,
                content_type: "application/cbor",
                content_length: self.metadata().len() as u64,
                etag: None,
                accept_ranges: false,
                content_range: None,
                body: if req.method == Method::Head {
                    Body::Empty
                } else {
                    Body::Bytes(self.metadata().to_vec())
                },
            };
        }
        if let Some(rest) = req.path.strip_prefix("/v1/item/") {
            return match rest.parse::<u32>() {
                Ok(id) => self.serve_item(req, id),
                Err(_) => simple(400),
            };
        }
        simple(404)
    }

    fn serve_item(&self, req: &Request, id: u32) -> Response {
        let rec = match self.item(id) {
            Some(r) => r,
            None => return simple(404),
        };
        let total = rec.data_length;

        // Resolve the byte range to serve.
        let (status, offset, len, content_range) = match req.range {
            None => (200u16, rec.data_offset, total, None),
            Some(r) => {
                if r.start >= total {
                    return Response {
                        status: 416,
                        content_type: "application/octet-stream",
                        content_length: 0,
                        etag: Some(rec.content_sha256),
                        accept_ranges: true,
                        content_range: Some((0, 0, total)),
                        body: Body::Empty,
                    };
                }
                let end = r.end.unwrap_or(total - 1).min(total - 1);
                let len = end - r.start + 1;
                (
                    206,
                    rec.data_offset + r.start,
                    len,
                    Some((r.start, end, total)),
                )
            }
        };

        Response {
            status,
            // Items are served opaque; clients learn MIME from /v1/manifest.
            content_type: "application/octet-stream",
            content_length: len,
            etag: Some(rec.content_sha256),
            accept_ranges: true,
            content_range,
            body: if req.method == Method::Head {
                Body::Empty
            } else {
                Body::Storage { offset, len }
            },
        }
    }

    fn health(&self) -> Response {
        let body = json_object(&[
            (
                "volume_uuid",
                JsonValue::Str(hex_uuid(&self.sb.volume_uuid)),
            ),
            (
                "format_version",
                JsonValue::Num(self.sb.format_version as u64),
            ),
            ("item_count", JsonValue::Num(self.sb.item_count as u64)),
            ("capacity", JsonValue::Num(self.sb.volume_capacity)),
        ]);
        Response {
            status: 200,
            content_type: "application/json",
            content_length: body.len() as u64,
            etag: None,
            accept_ranges: false,
            content_range: None,
            body: Body::Bytes(body),
        }
    }

    /// Stream an item from storage, hashing it, and confirm it matches the
    /// signed digest (SPEC §8 — bit-rot detection / integrity scans). `scratch`
    /// is a reusable read buffer (e.g. one block).
    pub fn verify_item<S: Storage>(
        &self,
        storage: &S,
        item_id: u32,
        scratch: &mut [u8],
    ) -> Result<bool, NodeError> {
        let rec = self
            .item(item_id)
            .ok_or(NodeError::Format(FmtError::Truncated))?;
        let mut hasher = Sha256::new();
        let mut pos = 0u64;
        let chunk = scratch.len().max(1);
        while pos < rec.data_length {
            let n = ((rec.data_length - pos) as usize).min(chunk);
            let buf = &mut scratch[..n];
            storage.read(rec.data_offset + pos, buf)?;
            hasher.update(&buf[..n]);
            pos += n as u64;
        }
        let mut got = [0u8; 32];
        got.copy_from_slice(&hasher.finalize());
        Ok(got == rec.content_sha256)
    }
}

fn read_region<S: Storage>(storage: &S, offset: u64, length: u64) -> Result<Vec<u8>, NodeError> {
    let len: usize = length.try_into().map_err(|_| StorageError::OutOfBounds)?;
    let mut buf = vec![0u8; len];
    storage.read(offset, &mut buf)?;
    Ok(buf)
}

fn simple(status: u16) -> Response {
    Response {
        status,
        content_type: "text/plain",
        content_length: 0,
        etag: None,
        accept_ranges: false,
        content_range: None,
        body: Body::Empty,
    }
}
