# bb-block — block-format reference library

Reference implementation of the Bruce's Bunker on-storage block format. The
authoritative format definition is [`SPEC.md`](SPEC.md); this code is the
executable contract.

## One core, two runtimes

The read + verification path is identical on the ESP32 firmware and on the
orchestrator/server, so it lives in **one** crate and is shared verbatim:

| Crate | `std`? | Role | Used by |
|-------|--------|------|---------|
| [`core`](core) — `bb-block-core` | `no_std`, no alloc on the hot path | parse + verify volumes and key-sets | ESP32 firmware **and** server |
| [`authoring`](authoring) — `bb-block` | `std` | build, sign, and write volumes + key-sets | `writer`, `indexer`, key-management tooling |

There is no separate "embedded implementation": the firmware links `bb-block-core`
directly (it builds for bare-metal `no_std` targets — see below). Authoring is
server-only because nodes never create content, they only verify it.

## What's implemented (v0.1)

- **Superblock** parse + CRC + algorithm checks (SPEC §4).
- **Manifest**: binary extent table with O(log n) `lookup`, plus the borrowed CBOR
  metadata region (SPEC §5).
- **Verification** (SPEC §7.5): manifest-hash check, Ed25519 manifest-signature
  check against a trust store, per-item SHA-256 content check for HTTP Range reads.
- **Key-set** (SPEC §7.6): CBOR parse, root-quorum signature check, strict
  monotonic rollback protection, capability + validity enforcement, allocation-free
  key collection.
- **Update bundles** (SPEC §9): copy-on-write in-place updates. The node validates
  the author's layout (in-bounds, block-aligned, no overlap with kept items, within
  `volume_capacity`), verifies the new manifest's signature + every segment digest,
  processes an embedded key-set first, then executes with the superblock swap as the
  atomic commit. `replace` / `add` / `delete`, with deleted space auto-reclaimed.
- **Authoring**: `VolumeBuilder` (lay out → hash → sign → emit image),
  `KeySetBuilder` (build → root-sign envelope), and `BundleBuilder` (model free
  space → allocate → sign → emit bundle).

Not yet implemented (tracked in SPEC §9/§11): manifest deltas, multi-extent items,
replica handling, on-device (SD) bundle executor (the in-memory `execute` is the
reference; firmware writes the same plan to storage with crash-safe ordering).

## Build & test

```sh
cargo test          # round-trip + key-set tests (authoring ↔ core)
cargo clippy --all-targets -- -D warnings

# prove the shared core is embeddable (no std available):
rustup target add thumbv7em-none-eabihf
cargo build -p bb-block-core --target thumbv7em-none-eabihf
```

## Conformance vectors

The `authoring/tests` round-trips are the seed of a language-agnostic conformance
suite: any second implementation (e.g. a hand-written C firmware) must reproduce the
same accept/reject verdicts. A future `test-vectors/` directory will pin canonical
byte images so the vectors outlive this Rust implementation.
