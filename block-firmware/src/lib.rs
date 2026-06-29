//! # bb-node
//!
//! Portable node firmware logic for Bruce's Bunker. It mounts a block-format
//! volume from a [`Storage`] backend, verifies it with `bb-block-core`, and
//! answers the SPEC §8 read API — returning item bodies as storage descriptors
//! so the platform streams them. All hardware (SD, WiFi, TCP) lives behind the
//! [`Storage`] trait and the platform's transport loop, so this crate is
//! `no_std`, target-agnostic, and fully testable on a host.
//!
//! ```ignore
//! let node = Node::mount(&storage, &trusted_keys)?;
//! let req = Request::parse(raw_http)?;
//! let resp = node.handle(&req);
//! // platform writes resp.write_head(), then streams resp.body from storage
//! ```
//!
//! The ESP32-S3 firmware binary (SD driver + esp-wifi + an HTTP server wired to
//! this logic) lives outside this crate; see `block-firmware/README.md`.
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

pub mod http;
pub mod node;
pub mod storage;

pub use http::{Body, Method, RangeReq, Request, Response};
pub use node::{Node, NodeError};
pub use storage::{SliceStorage, Storage, StorageError};
