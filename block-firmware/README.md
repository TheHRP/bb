# bb-node — node firmware logic

`bb-node` is the **portable** part of the Bruce's Bunker node firmware: it mounts a
block-format volume, verifies it with `bb-block-core`, and answers the SPEC §8 read
API. It is `no_std`, has **no transport or hardware dependencies**, and is fully
tested on a host — the same logic the ESP32 firmware binary links.

## Design: logic here, hardware in the binary

Everything that can be tested without a radio or an SD card lives here. Two seams
keep the hardware out:

- **`Storage` trait** — block read/write. The device implements it over SD
  (SDMMC/SPI); tests use `SliceStorage` (an in-RAM slice). The node never knows
  which.
- **Body-as-descriptor** — `handle()` returns a `Response` whose body is either
  in-RAM bytes (`/v1/health`, `/v1/manifest`) or a `Storage { offset, len }`
  *descriptor*. The platform's TCP loop streams that range from storage. The node
  never touches a socket, so there is no embedded HTTP stack to mock.

```text
        ┌── bb-node (this crate, no_std, host-tested) ──────────────┐
WiFi ─► │ Request::parse → Node::handle → Response (head + body)     │
 SD  ◄─►│ Node::mount / verify_item   ── via Storage trait ──────────│
        └────────────────────────────────────────────────────────────┘
   platform binary supplies: SD-backed Storage, WiFi, and the TCP write loop
```

## API (SPEC §8)

| Route | Result |
|-------|--------|
| `GET /v1/health` | JSON: `volume_uuid`, `format_version`, `item_count`, `capacity` |
| `GET /v1/manifest` | the CBOR metadata document (clients learn per-item MIME here) |
| `GET /v1/item/<id>` | item bytes; honors `Range: bytes=…` → `206` + `Content-Range` |
| `HEAD /v1/item/<id>` | headers only: `Content-Length`, `ETag` (hex of `content_sha256`), `Accept-Ranges` |

Unknown id → `404`; non-numeric id → `400`; range past end → `416`; non-GET/HEAD → `405`.

`Node::verify_item` streams an item from storage and checks it against the signed
digest — the bit-rot / integrity-scan path (run on a schedule), separate from the
hot serving path which trusts the signature-verified manifest.

## Memory model

`mount()` reads the superblock, manifest, and signature block into RAM and verifies
them (SPEC §7.5); the manifest is retained for lookups. On the ESP32-S3 the manifest
lives in PSRAM. **Item data is never fully buffered** — it streams from storage in
chunks, so a 1 TB card serves with a few KB of RAM.

## Build & test

```sh
cargo test                                  # 11 host tests over SliceStorage
cargo clippy --all-targets -- -D warnings
cargo build --target thumbv7em-none-eabihf  # proves no_std embeddability
```

## ESP32-S3 firmware binary (next, separate crate)

Not in this crate (it needs the Espressif toolchain and can't run in host CI). The
binary is thin glue around `bb-node`:

- **SD**: an `embedded-sdmmc`/SDMMC `Storage` impl (raw block reads; no filesystem on
  the read path, per the format).
- **WiFi + TCP**: `esp-hal` + `esp-wifi`; a small HTTP server (e.g. `picoserve` or
  `edge-http`) that calls `Request::parse` → `Node::handle`, writes
  `Response::write_head()`, then streams the body (in-RAM `Bytes`, or chunked reads
  for `Storage { offset, len }`).
- **Trust**: root keys compiled in; current key-set + owner key in NVS; assemble the
  effective content-trust set and pass it to `Node::mount`.
- **AP**: hosts the `bruce` management SSID and (optionally) the public content SSID.

## Deferred

- On-device (streaming) **bundle apply** — `bb-block-core`'s `verify_bundle`/`execute`
  operate on an addressable image (fine for a PSRAM-resident volume); applying to a
  1 TB card without buffering it needs a storage-streaming variant.
- Serving the correct per-item **MIME** directly (currently `application/octet-stream`;
  clients use `/v1/manifest`).
- The ESP32-S3 binary crate itself.
