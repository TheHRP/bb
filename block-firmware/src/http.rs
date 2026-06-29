//! Minimal HTTP request/response model for the node's read API (SPEC §8).
//!
//! This is pure logic: it parses a request and produces a [`Response`] whose
//! body is either in-RAM bytes or a *descriptor* of a storage byte-range. The
//! platform's TCP layer streams the body — keeping this crate transport-free.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Other,
}

/// A parsed `Range: bytes=START-[END]` (single range only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeReq {
    pub start: u64,
    pub end: Option<u64>, // inclusive; None = to end of item
}

/// A parsed request: just the fields the node routes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub range: Option<RangeReq>,
}

impl Request {
    /// Parse the head of an HTTP/1.x request. Returns `None` on a malformed
    /// request line.
    pub fn parse(raw: &[u8]) -> Option<Request> {
        let text = core::str::from_utf8(raw).ok()?;
        let mut lines = text.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.split(' ');
        let method = match parts.next()? {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            _ => Method::Other,
        };
        let path = parts.next()?.to_string();

        let mut range = None;
        for line in lines {
            if line.is_empty() {
                break; // end of headers
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("range") {
                    range = parse_range(value.trim());
                }
            }
        }
        Some(Request {
            method,
            path,
            range,
        })
    }
}

fn parse_range(value: &str) -> Option<RangeReq> {
    let spec = value.strip_prefix("bytes=")?;
    // Single range only; ignore anything after a comma.
    let spec = spec.split(',').next()?.trim();
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = match end.trim() {
        "" => None,
        e => Some(e.parse().ok()?),
    };
    Some(RangeReq { start, end })
}

/// Where a response body comes from.
pub enum Body {
    Empty,
    /// In-RAM bytes (health, manifest).
    Bytes(Vec<u8>),
    /// A byte range on the storage medium to be streamed by the platform.
    Storage {
        offset: u64,
        len: u64,
    },
}

/// A fully-routed response. The platform writes the head, then the body.
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub content_length: u64,
    pub etag: Option<[u8; 32]>,
    pub accept_ranges: bool,
    /// `(start, end_inclusive, total)` for a 206 partial response.
    pub content_range: Option<(u64, u64, u64)>,
    pub body: Body,
}

impl Response {
    pub fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            206 => "Partial Content",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            416 => "Range Not Satisfiable",
            _ => "Unknown",
        }
    }

    /// Render the status line + headers (terminated by the blank line) into a
    /// string. The platform writes this, then streams the body.
    pub fn write_head(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "HTTP/1.1 {} {}\r\n",
            self.status,
            Self::status_text(self.status)
        );
        let _ = write!(s, "Content-Type: {}\r\n", self.content_type);
        let _ = write!(s, "Content-Length: {}\r\n", self.content_length);
        if self.accept_ranges {
            let _ = write!(s, "Accept-Ranges: bytes\r\n");
        }
        if let Some((start, end, total)) = self.content_range {
            let _ = write!(s, "Content-Range: bytes {start}-{end}/{total}\r\n");
        }
        if let Some(etag) = self.etag {
            let _ = write!(s, "ETag: \"{}\"\r\n", hex32(&etag));
        }
        s.push_str("\r\n");
        s
    }
}

/// Lowercase hex of a 32-byte digest.
pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Lowercase hex of a 16-byte volume UUID.
pub fn hex_uuid(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Build a small JSON object body (avoids a serde dependency on the node).
pub fn json_object(pairs: &[(&str, JsonValue)]) -> Vec<u8> {
    let mut s = String::from("{");
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"{k}\":");
        match v {
            JsonValue::Str(x) => {
                let _ = write!(s, "\"{x}\"");
            }
            JsonValue::Num(x) => {
                let _ = write!(s, "{x}");
            }
        }
    }
    s.push('}');
    s.into_bytes()
}

pub enum JsonValue {
    Str(String),
    Num(u64),
}
