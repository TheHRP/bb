# Bruce's Bunker — Block Format Specification

**Status:** Draft · **Version:** 0.1 · **Last updated:** 2026-06-29

This document defines the on-storage layout, manifest format, checksum scheme, and
signing/update model used by every Bruce's Bunker (BB) node. It is the **shared
contract** between the firmware (`block-firmware`), the preparation tools
(`writer`, `indexer`), the coordinator (`node`/synth), and the update/signing
library (`update`). Changing this format is expensive; changing anything else is
not. Treat this spec as the source of truth.

---

## 1. Goals & non-goals

### Goals
- Serve arbitrary byte ranges of stored content **without a filesystem on the read
  path**, so a tiny MCU (ESP32-S3) can act as a "wireless disk."
- Make all integrity metadata (offsets, sizes, checksums) **precomputed at
  preparation time**, so the node only verifies, never indexes.
- Make content and firmware **updates cryptographically signed**, so no party can
  silently poison the archive—even with full network/management access.
- Be **append/replace-friendly** for field updates, and **hardware-agnostic** (the
  same volume works whether served by an ESP32 or a Pi-class board).

### Non-goals (v0.1)
- General-purpose read/write filesystem semantics.
- Per-user access control or encryption-at-rest (content is public knowledge; the
  threat model is *integrity*, not confidentiality).
- Deduplication on-volume (the `indexer` dedupes upstream; the volume stores the
  resulting items).

---

## 2. Conventions

- All multi-byte integers are **little-endian, unsigned** unless stated otherwise.
- All offsets and lengths are in **bytes**, absolute from the start of the volume,
  unless stated otherwise.
- Hashes are **SHA-256** (32 bytes). Rationale: the ESP32-S3 has a hardware SHA
  accelerator, making verification cheap on the constrained node. BLAKE3 MAY be
  offered as an alternate digest in a future version via the `digest_algo` field.
- Signatures are **Ed25519** (64-byte signature, 32-byte public key). Rationale:
  small, fast to verify on an MCU, widely available libraries.
- `BLOCK_SIZE` is fixed per volume (default **4096 bytes**) and recorded in the
  superblock. All regions are block-aligned.
- Reserved fields MUST be written as zero and ignored on read.

---

## 3. Volume layout

A volume (one microSD card or one USB device) is laid out as four contiguous,
block-aligned regions:

```
 offset 0
 ┌───────────────────────────────────────────────┐
 │ Region 0: Superblock            (1 block)       │  fixed location, offset 0
 ├───────────────────────────────────────────────┤
 │ Region 1: Signature block       (1+ blocks)     │  signs Region 2
 ├───────────────────────────────────────────────┤
 │ Region 2: Manifest              (N blocks)       │  index + metadata (signed)
 ├───────────────────────────────────────────────┤
 │ Region 3: Content data          (rest of device) │  concatenated items
 └───────────────────────────────────────────────┘
```

A second copy of the Superblock + Signature + Manifest (Regions 0–2) MAY be written
at the **end** of the device as a recovery replica; the superblock records its
offset (`replica_offset`, 0 if absent).

---

## 4. Region 0 — Superblock (offset 0, 1 block)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 4 | `magic` | ASCII `"BBLK"` (0x42 0x42 0x4C 0x4B) |
| 4 | 2 | `format_version` | `0x0001` for this spec |
| 6 | 2 | `flags` | bit0 = replica present; others reserved |
| 8 | 16 | `volume_uuid` | RFC 4122 UUID, identifies this volume |
| 24 | 8 | `created_unix` | volume creation time, seconds |
| 32 | 4 | `block_size` | bytes; default 4096 |
| 36 | 1 | `digest_algo` | `1` = SHA-256 (only value in v0.1) |
| 37 | 1 | `sig_algo` | `1` = Ed25519 (only value in v0.1) |
| 38 | 2 | reserved | zero |
| 40 | 8 | `sig_offset` | byte offset of Region 1 |
| 48 | 8 | `sig_length` | length of Region 1 payload |
| 56 | 8 | `manifest_offset` | byte offset of Region 2 |
| 64 | 8 | `manifest_length` | length of the manifest payload (bytes) |
| 72 | 8 | `data_offset` | byte offset of Region 3 |
| 80 | 8 | `replica_offset` | offset of replica superblock, or 0 |
| 88 | 4 | `item_count` | number of content items in the manifest |
| 92 | 32 | `manifest_sha256` | SHA-256 of the manifest payload bytes |
| 124 | 4 | `header_crc32` | CRC-32 of bytes [0,124) for quick sanity check |
| 128 | … | reserved | zero to end of block |

A reader validates `magic`, `format_version`, and `header_crc32`, then trusts
`manifest_sha256` only **after** the signature in Region 1 verifies (§7).

---

## 5. Region 2 — Manifest

The manifest has two parts so the constrained read path stays trivial while the UI
gets rich metadata:

### 5.1 Extent table (fast path — read by firmware)

A header followed by a packed array of fixed-size records, sorted ascending by
`item_id` to allow binary search.

**Extent table header (32 bytes):**

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 4 | `table_magic` | ASCII `"BMFT"` |
| 4 | 4 | `entry_count` | number of extent records |
| 8 | 4 | `entry_size` | bytes per record (52 in v0.1) |
| 12 | 8 | `meta_offset` | offset of the metadata document, relative to manifest start |
| 20 | 8 | `meta_length` | length of the metadata document |
| 28 | 4 | reserved | zero |

**Extent record (52 bytes):**

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 4 | `item_id` | stable per-volume id, unique, sorted |
| 4 | 8 | `data_offset` | absolute byte offset in Region 3 |
| 12 | 8 | `data_length` | item length in bytes |
| 20 | 32 | `content_sha256` | SHA-256 of the item's bytes |

> v0.1 stores each item as a **single contiguous extent**. A future version MAY
> introduce multi-extent items by adding an indirection record; readers detect this
> via `format_version`. Keeping v0.1 contiguous keeps the firmware lookup O(log n)
> with zero allocation.

### 5.2 Metadata document (rich path — read by node/UI)

Located at `meta_offset`/`meta_length` within the manifest. Encoded as **CBOR**
(deterministic, RFC 8949 §4.2 canonical ordering) so it is compact, streamable, and
reproducibly serialized for signing. It is a map from `item_id` to an item record:

```
{
  <item_id>: {
    "path":       "wikipedia/en/Article_Title.html",  // logical path
    "title":      "Article Title",
    "mime":       "text/html",
    "collection": "wikimedia-en",
    "language":   "en",                                // BCP-47, optional
    "size":       12345,                               // == data_length
    "sha256":     h'…32 bytes…',                       // == content_sha256
    "added_unix": 1719600000,
    "tags":       ["reference"]                        // optional
  },
  ...
}
```

The firmware never needs to parse this. The `node`/`portal` use it to build the
browse UI and search index.

---

## 6. Region 3 — Content data

A simple concatenation of item byte-blobs, each starting at its `data_offset`
(block-aligned) and running `data_length` bytes. There is no per-item header in the
data region; all framing lives in the (signed) manifest. Padding between items (to
the next block boundary) MUST be zero.

---

## 7. Signing & verification

### 7.1 What is signed

The manifest (Region 2, exactly `manifest_length` bytes starting at
`manifest_offset`) is the single signed object. Because every item's
`content_sha256` lives in the signed manifest, a valid manifest signature
transitively secures **all content** and the superblock's critical pointers (the
superblock stores `manifest_sha256`, which the signature commits to).

### 7.2 Signature block (Region 1)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 4 | `sig_magic` | ASCII `"BSIG"` |
| 4 | 2 | `sig_count` | number of signatures that follow (≥1) |
| 6 | 2 | reserved | zero |
| 8 | … | `signatures[]` | array of signature records |

**Signature record (96 bytes):**

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 32 | `signer_pubkey` | Ed25519 public key of the signer |
| 32 | 64 | `signature` | Ed25519 signature over the signing input (§7.3) |

Multiple signatures are allowed (e.g. owner + project co-sign). A node accepts the
volume if **at least one** signature verifies against a key in its trust store
(§7.4), unless a stricter policy is configured.

### 7.3 Signing input

The signed message is the byte string:

```
"BBLKSIGv1" || volume_uuid (16) || format_version (2, LE) || manifest_sha256 (32)
```

This binds the signature to the specific volume and manifest. Signers compute
`manifest_sha256` over the exact manifest payload bytes.

### 7.4 Trust store

Each node holds an Ed25519 trust store assembled from:

- **Project keys** — bundled into the firmware/build (the project / "inner cabal"
  content updaters). Trusted for content/firmware updates on any project node.
- **Owner key(s)** — added at provisioning. Trusted for updates on that node.

For *management/SSH* access the same keys are used, but the policy differs (see
README → Security & Trust): the owner key is always authorized; project keys gain
management access only when the owner **enrolls** the node.

### 7.5 Verification procedure (node boot / mount)

1. Read and validate the superblock (`magic`, `format_version`, `header_crc32`).
2. Read the manifest payload; compute its SHA-256; compare to
   `superblock.manifest_sha256`. Abort on mismatch.
3. Read Region 1; for each signature, verify it over the §7.3 signing input against
   the signer's public key, and confirm that key is in the trust store. Require ≥1
   valid trusted signature.
4. Only then expose content. The extent table is now trusted.
5. On each served range (or lazily/periodically), the node MAY re-verify the item's
   bytes against `content_sha256` to detect bit-rot; it MUST do so before applying
   or re-signing an update.

A volume failing steps 1–3 MUST NOT be served.

---

## 8. HTTP Range serving semantics

The firmware exposes content over HTTP. Item addressing and range mapping:

- `GET /v1/manifest` → returns the metadata document (CBOR) for the UI.
- `GET /v1/item/<item_id>` → returns the full item bytes; supports
  `Range: bytes=...` per RFC 7233. The server maps the requested item range to
  `data_offset + range_start` in Region 3 and streams raw blocks.
- `HEAD /v1/item/<item_id>` → returns `Content-Length` (= `data_length`),
  `ETag` (hex of `content_sha256`), `Accept-Ranges: bytes`.
- `GET /v1/health` → node id (volume_uuid), `item_count`, firmware version,
  verification status.

The server performs O(log n) binary search on the extent table for `item_id`, then
issues block-aligned reads. No filesystem, no allocation per request beyond a fixed
I/O buffer.

---

## 9. Update bundles

A field update is a signed, self-contained bundle applied by the `update` library.
v0.1 supports **full-manifest replacement** with incremental data append (the
simplest correct model); manifest *deltas* are a future optimization.

**Bundle contents:**
- `target_uuid` — volume the bundle applies to (or a wildcard for fleet content
  packs intended for any project node).
- `base_manifest_sha256` — the manifest the bundle expects to replace (optimistic
  concurrency; `0` = unconditional).
- `new_manifest` — the full replacement manifest (extent table + metadata).
- `data_segments[]` — new/changed item blobs with their target offsets.
- `signature` — Ed25519 over `"BBLKUPDv1" || target_uuid || new_manifest_sha256`,
  by a key in the node's trust store.

**Apply procedure (atomic-ish):**
1. Verify the bundle signature against the trust store. Reject if untrusted.
2. If `base_manifest_sha256 != 0`, confirm it matches the current manifest.
3. Verify each `data_segment` against its `content_sha256` in `new_manifest`.
4. Write new data segments to Region 3 (and replica, if present).
5. Write the new manifest, then the new signature block, then update the superblock
   (`manifest_offset/length`, `manifest_sha256`, `item_count`) **last** — the
   superblock swap is the commit point. A torn write leaves the old superblock
   valid (write the replica first, primary last).

---

## 10. Versioning & compatibility

- `format_version` gates all structural changes. Readers MUST refuse versions they
  do not understand rather than guess.
- New optional fields go into the CBOR metadata document (which is schema-flexible)
  before they go into the fixed binary structures.
- `digest_algo` / `sig_algo` allow future algorithm agility without a new
  `format_version`.

---

## 11. Open questions (to resolve before v1.0)

- **Multi-extent items** for large files and update-in-place without rewriting all
  of Region 3.
- **Manifest deltas** to avoid resending the full index on small updates.
- **Key revocation / rotation** mechanism for project keys (CRL-style list bundled
  in firmware updates? signed key-set with a monotonic version?).
- **Cross-node aggregation contract**: how the synth presents `item_id` namespaces
  from multiple volumes without collision (likely `volume_uuid` + `item_id`).
- Whether to offer **optional at-rest encryption** for sensitive regional content
  despite the public-content default.

---

*This spec is intentionally minimal for v0.1: enough to build the firmware, writer,
indexer, and update path against a stable contract, with explicit seams for the
features we know are coming.*
