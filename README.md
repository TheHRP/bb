# Bruce's Bunker: A Distributed Digital Preservation Network

## Executive Summary

Bruce's Bunker (BB) is designed as humanity's last-resort preservation system for digital knowledge. By distributing content across offline, independently-powered storage nodes worldwide, we ensure that human knowledge survives any catastrophe—technological, political, or natural.

BB ships in **two deployment modes** that share one content format and one toolchain:

- **Bunker Mode** — the full self-contained, solar-powered archive node: an ammo can holding a synthesizer (Android phone or OpenWRT router) and an array of wireless ESP32 "disk" nodes, each backing a 1TB microSD card. Designed for long-term, off-grid, 8–10TB cold archival.
- **Standalone Mode** — a single small OpenWRT device (e.g. GL.iNet AR300M, GL-SFT1200, Cudy TR1200) serving content directly from local USB storage. Low-cost, five-minute deployment, opportunistic networking. This is the on-ramp.

Both modes are immune to network-based censorship: a node requires no internet connection to store or serve content. Together they form a redundant, uncensorable archive of human knowledge.

---

## Mission Statement

> "When the lights go out, knowledge endures. When the networks fail, wisdom persists. When censorship rises, truth survives—in Bruce's Bunker."

Our mission is to create an immutable, unstoppable, uncensorable, and indestructible backup of humanity's digital heritage, distributed across every nation, stored by volunteers who believe that access to knowledge is a fundamental human right.

---

## Why Bruce's Bunker?

### The Threats We Face

1. **Digital Dark Ages**: Formats become obsolete, platforms disappear, links rot
2. **Censorship**: Increasing restrictions on digital content worldwide
3. **Infrastructure Failure**: Natural disasters, conflicts, or systemic collapse
4. **Corporate Control**: Paywalls, DRM, and artificial scarcity of knowledge
5. **Torrent Death**: Seeders disappear, trackers shut down, magnets become useless

### Our Solution

Bruce's Bunker creates a physical, distributed backup that:
- **Exists Offline**: No internet required for storage or access
- **Survives Locally**: Each node is self-sufficient
- **Resists Censorship**: No central point of control
- **Preserves Permanently**: Off-grid power for indefinite operation (Bunker Mode)
- **Scales Globally**: Designed for worldwide deployment, from $30 routers to solar archives

---

## Deployment Modes

### Mode A — Bunker Mode (Archival)

The original concept: a weatherproof, solar-powered node optimized for maximum capacity and indefinite off-grid life. A **synthesizer** (Android phone or OpenWRT router) aggregates an array of **wireless disk nodes** (ESP32-S3 + 1TB microSD) into a single browsable archive and hosts a local hotspot. Content and the on-card blocks can be rewritten in the field via signed updates.

**Best for**: permanent regional archives, off-grid sites, maximum capacity (8–10TB).

### Mode B — Standalone Mode (Opportunistic)

A single small OpenWRT device serves content directly from attached USB storage—no ESP32 array, no solar, no ammo can. It can run on battery or USB power and be deployed in minutes. Networking is flexible per site:

- **Management access** — a discovery SSID named **`bruce`** for local management and content updates. (See **Security & Trust** for why association alone is not authentication.)
- **Public content SSID** — optionally broadcast a public network that serves the content library but **no internet access**, or serves content *and* passes through upstream internet, depending on configuration and how friendly the piggybacked connection is.
- **Upstream siphon (optional)** — where an authorized upstream connection is available, the device can join it to gain internet, either to passthrough or solely for remote status/updates.
- **Remote presence** — when it has any upstream, the node joins the **Yggdrasil** network for remote access and status reporting (see **Networking**).

Standalone devices can be configured to **piggyback** an existing local WiFi network, or to operate as a **transparent bridge ("bump in the wire")** with its LAN/WAN ports bridged so it sits inline on an existing wired link.

**Best for**: low-cost rapid deployment, community spaces, mobile/temporary sites, seeding new operators.

> **Note on placement.** The transparent-bridge and upstream-siphon capabilities are powerful and must only be used on networks and premises you own or are authorized to use. See **Legal & Ethical Use**.

#### Reference hardware (Standalone Mode)

| Device | Notes |
|--------|-------|
| GL.iNet GL-AR300M | Tiny, cheap, OpenWRT-native, USB storage, low power |
| GL.iNet GL-SFT1200 (Opal) | Dual-band, more throughput, USB |
| Cudy TR1200 | Travel router, dual-band, USB, OpenWRT-supported |

---

## Technical Architecture

### The Bunker Unit (Mode A)

Each bunker consists of:

| Component | Specification | Purpose |
|-----------|--------------|---------|
| **Container** | Military surplus ammo can | Weatherproof, EMP-resistant, durable |
| **Compute** | Refurbished Android phone *or* OpenWRT router | Content synthesizer and network coordinator |
| **Storage** | 8-10× Seeed XIAO ESP32-S3 | Wireless disk nodes with minimal power draw |
| **Capacity** | 8-10× 1TB microSD cards | 8-10TB total storage per bunker |
| **Power** | 100W solar panel + battery | Indefinite off-grid operation |
| **Network** | Internal WiFi router | Local content distribution |
| **Cooling** | Passive ventilation | No moving parts, silent operation |

### How It Works (Mode A)

```
[Solar Panel]
     |
[Battery System]
     |
[Ammo Can] ─────────────────────┐
  ├─[Synthesizer]                │ External
  │   └─ Content Synthesizer     │ Antenna
  │       (Port 8080)            │    │
  │                              └────┘
  ├─[WiFi Router]
  │   ├─ Internal Network Only
  │   └─ Optional External Access
  │
  └─[Storage Array]
      ├─ XIAO-001: 1TB Content Pack A (raw blocks)
      ├─ XIAO-002: 1TB Content Pack B (raw blocks)
      ├─ XIAO-003: 1TB Content Pack C (raw blocks)
      └─ ... up to 10 nodes
```

### How It Works (Mode B)

```
[USB/Battery Power]
     |
[OpenWRT Device]
  ├─ SSID "bruce" (management + updates, authenticated)
  ├─ Public content SSID (content only, or content + internet)
  ├─ Upstream join (optional): piggyback WiFi or bridged WAN
  └─ Yggdrasil (when upstream present): remote status / management
     |
[USB Storage] ── content library (block format or filesystem)
```

### Storage Technology

- **Block format**: Content is laid out on storage in a pre-indexed raw block layout. A manifest maps logical content to byte offsets, so a node serves arbitrary ranges without a filesystem on the hot path.
- **No Filesystem (Mode A cards)**: Direct block storage eliminates overhead on the ESP32 disk nodes
- **Pre-indexed**: All metadata (offsets, checksums) computed during preparation
- **HTTP Range**: Standard protocol for partial content access
- **Read-Only**: No wear leveling needed, long lifespan
- **Distributed**: Content spread across multiple nodes for redundancy
- **Signed updates**: Blocks are rewritten in the field only via update bundles signed by a trusted key (see **Security & Trust**)

> **Performance note.** The XIAO ESP32-S3 reads its microSD over SPI and serves over 2.4GHz WiFi; sustained throughput is on the order of a few MB/s per node. Bunker Mode is optimized for *capacity and longevity as a cold archive*, not high-concurrency streaming. The block-server contract is hardware-agnostic, so faster compute (e.g. a Pi-class board) can back the same format where throughput matters.

---

## System Architecture & Repositories

BB is composed of several subsystems that share a single contract: the **on-storage block format**. While that format is still evolving, development lives in a **monorepo**; subsystems are split into their own repositories as their interfaces stabilize.

| Subsystem | Responsibility |
|-----------|----------------|
| **block-format** | The on-storage raw layout + manifest format. The shared contract every other subsystem depends on. Spec + reference library. |
| **block-firmware** (ESP32-S3) | "Wireless disk" firmware: serve raw block ranges over HTTP/WiFi; fetch and apply signed block updates. |
| **writer** | Block recorder/writer: lay prepared content onto cards/USB in block format and write raw images. |
| **indexer** | Content manager: ingest, deduplicate, checksum, build manifests, and track which content lives on which block / card / node. |
| **node** (synth) | Coordinator. Runs on Android or OpenWRT: aggregates disk nodes, hosts the hotspot, serves the API/UI. In Standalone Mode, serves content directly from USB. |
| **portal** (ui) | Content browse/read frontend and captive portal. |
| **openwrt** | UCI configuration + package feed for Standalone/router builds: SSIDs, firewall, captive portal, transparent-bridge mode, Yggdrasil integration. |
| **fleet** | Remote status/heartbeat/health reporting and update orchestration over Yggdrasil. |
| **update** (signing) | Signed content & firmware update bundles plus verification. Security-critical shared library. |
| **docs** | Build guides, BOMs, operator runbooks. |

---

## Networking (Standalone Mode)

### SSIDs

- **`bruce` (management)** — used to associate with a device for local management and content updates. Association is for *discovery convenience only*; management actions require separate authentication (see **Security & Trust**).
- **Public content SSID** — optional. Serves the content library. Configurable to provide:
  - content only (no internet), or
  - content + internet passthrough, where an upstream is available and authorized.

### Upstream / piggyback

A Standalone node can obtain internet by:
- **Piggybacking** an existing local WiFi network (as a client), or
- **Transparent bridge** ("bump in the wire") with ports bridged so it sits inline on a wired link.

Upstream may be used for passthrough to clients, or solely for remote status/updates—configurable per site.

### Yggdrasil (remote presence)

When a node has any upstream connection, it joins the [Yggdrasil](https://yggdrasil-network.github.io/) network. This gives each node a stable, cryptographically-derived IPv6 address and an end-to-end-encrypted path for remote status reporting and management, independent of the upstream's addressing or NAT.

**Opsec note**: Yggdrasil traffic is identifiable to deep-packet inspection and the node advertises its presence to peers. On opportunistic/borrowed uplinks, weigh this before enabling.

---

## Security & Trust

### Content & update integrity (most important)

The archive's value depends on operators being unable to silently poison it. Therefore:

- **All content and firmware updates are cryptographically signed.** A node applies an update only if it is signed by a trusted key—**regardless of who can reach the management interface.** This is the primary integrity control.
- **Local content is verified against per-block checksums** recorded in the manifest at preparation time.

### Management authentication

> ⚠️ **A single shared, well-known WiFi password is not authentication.** A common discovery SSID (`bruce`) makes devices easy to find, but anyone who knows the project knows the password. Network association MUST NOT, by itself, grant the ability to rewrite content.

Recommended model:
- The `bruce` SSID handles **discovery/association** only.
- **Management actions require a second factor**: an SSH key, or a per-device token derived as `HMAC(master_secret, device_id)` so credentials are not shared fleet-wide.
- Signed updates (above) mean that even a fully compromised management channel cannot alter the archive's contents undetected.

### Operational Security

1. **No Network Dependency**: Nodes work completely offline
2. **No Tracking**: No phone-home or telemetry beyond opt-in fleet status
3. **Plausible Deniability**: Bunker Mode looks like camping/emergency equipment

### Community Trust

- **Pseudonymous Participation**: No real names required
- **Distributed Git-Based Coordination**: No central member database
- **Local Chapters**: Regional coordination without central oversight
- **Trusted Preseeders**: Vetted by community participation

---

## Legal & Ethical Use

BB's networking capabilities—piggybacking an upstream WiFi, transparent-bridge ("bump in the wire") deployment, and upstream siphoning—must only be used on **networks and premises you own or are explicitly authorized to use.**

Plugging a device into a network you do not control, or using a connection without permission, may constitute unauthorized access, theft of service, or trespass depending on jurisdiction, and can expose operators to serious legal risk. BB is a **preservation** project; deploy in spaces that consent to host you—your own property, partner venues, community centers, libraries and mutual-aid sites that opt in. Get permission first.

---

## Bill of Materials (BOM)

### Mode A — Bunker (~$500-800)

| Item | Source | Approx Cost | Notes |
|------|--------|------------|-------|
| Ammo Can (50 cal) | Harbor Freight | $20 | Metal, weatherproof seal |
| Android Phone *or* OpenWRT router | Walmart/Used | $24.99-99.99 | Any Android 8+ device, or router below |
| XIAO ESP32-S3 Sense ×10 | Seeed Studio | $130 | $13 each |
| 1TB microSD ×10 | Amazon | $260 | Class 10 or better |
| 100W Solar Panel | Harbor Freight | $150 | Monocrystalline preferred |
| 12V 20Ah Battery | Grainger | $80 | Deep cycle AGM |
| Charge Controller | Amazon | $30 | MPPT preferred, can skip if integrated into panel |
| WiFi Router | Walmart | $30 | Any compact model, TPLink Archer C54 works well |
| Cables & Connectors | Various | $50 | Power, USB, network |
| Mounting Hardware | Harbor Freight | $20 | Pole mount kit |

### Mode B — Standalone (~$30-80)

| Item | Source | Approx Cost | Notes |
|------|--------|------------|-------|
| OpenWRT device | GL.iNet / Cudy | $30-70 | AR300M, GL-SFT1200, or Cudy TR1200 |
| USB storage | Amazon | $10-40 | USB stick or SSD, sized to content |
| Power | — | $0-15 | USB power; optional battery for portability |

### Optional Enhancements

- Larger battery for extended cloudy periods (Mode A)
- Temperature/humidity sensor for monitoring
- Larger solar panel for faster charging or client services
- N97/N100 Based Server for Enhanced Services

---

## Content Organization

### Storage Allocation

Each bunker stores a carefully curated 8-10TB subset (Mode A); Standalone nodes carry a smaller curated library sized to their USB storage:

1. **Core Collections** (2TB)
   - Wikimedia Foundation snapshots
   - Project Gutenberg
   - Internet Archive essentials
   - Kiwix ZIM files
   - Chunk of Scientific papers

2. **Regional Content** (2TB)
   - Local language materials
   - Regional history/culture
   - Government documents
   - Maps and geographic data

3. **Specialized Archives** (4-6TB)
   - Assigned by BB coordination team
   - Ensures global redundancy
   - No single point of failure

---

## Deployment Paths

### Path 1: Full DIY (Technical Users)

**Requirements**: Linux skills, fast internet (100Mbps+)

1. **Purchase BOM**: ~$500-800 depending on storage (Mode A) or ~$30-80 (Mode B)
2. **Coordinate Assignment**: Contact HRP/BB team for content allocation
3. **Download Content**: Retrieve assigned archives
4. **Prepare Storage**: Use our tools to write content to SD cards / USB
5. **Assemble**: Follow the build guide for your mode
6. **Deploy**: Install in an authorized location

### Path 2: Assisted Setup (Semi-Technical)

**Requirements**: Fast internet, basic computer skills

1. **Purchase BOM**: Same as Path 1
2. **Run Preseed VM**: Download our preconfigured Linux VM, run in VirtualBox
3. **USB Passthrough**: Connect SD cards / USB storage one at a time to VM
4. **Remote Assistance**: BB team remotely fills storage
5. **Local Assembly**: You build and deploy the node

### Path 3: Preseeded Storage (Non-Technical)

**Requirements**: Trusted community member status

1. **Purchase BOM**: Minus storage
2. **Contact Local Chapter**: Find nearest preseed volunteer
3. **Acquire Storage**: Purchase preloaded content packs on 1TB SD cards / USB
4. **Simple Assembly**: Just insert storage and deploy
5. **Maintenance**: Periodic power-on for integrity checks

---

## Deployment Guidelines

### Site Selection (Mode A)

**Ideal Locations**:
- Roof access for solar panel
- Weatherproof mounting point
- Minimal interference risk
- Community accessible (optional)

**Avoid**:
- Flood zones
- Extreme temperature areas
- High-crime locations
- Government facilities

### Installation (Mode A)

1. **Mount Solar Panel**: South-facing (Northern hemisphere)
2. **Secure Ammo Can**: Weatherproof location, accessible
3. **Connect Power**: Solar → Controller → Battery → Systems
4. **Initial Test**: Verify all nodes responding
5. **Weatherproof**: Seal all external connections
6. **Document**: Record GPS coordinates (optional)

### Installation (Mode B)

1. **Flash & configure**: Install the BB OpenWRT build; set SSIDs and management auth
2. **Load content**: Attach prepared USB storage
3. **Choose networking**: Standalone, piggyback, or transparent bridge—*on an authorized network only*
4. **Verify**: Confirm content serves and (if enabled) Yggdrasil status is reporting
5. **Place discreetly and consensually**: With the host site's permission

### Maintenance

- **Monthly**: Visual inspection
- **Quarterly**: Power-on test, verify node count / content integrity
- **Annually**: Clean solar panel, check battery (Mode A)
- **As Needed**: Content updates (signed; coordinated with BB team)

---

## Community Structure

### Global Coordination

```
Bruce's Bunker Core Team
         |
    Local Chapters
         |
    Individual Node Operators
```

### Roles

**Node Operator**: Maintains one or more nodes (bunker or standalone)
**Preseeder**: Helps prepare SD cards / USB storage for others
**Chapter Lead**: Coordinates local operators
**Regional Coordinator**: Manages multiple chapters
**Core Team**: Technical development and strategy

---

## Future Roadmap

### Phase 1: Foundation (Current)
- Finalize block format and technical architecture
- Build initial Bunker and Standalone prototypes
- Establish core team
- Create preparation tools (writer, indexer, signing)

### Phase 2: Early Deployment
- Deploy pilot nodes in both modes
- Establish regional chapters
- Refine content packs
- Build preseeder network

### Phase 3: Global Scale
- 1,000+ nodes worldwide
- Automated content distribution
- Fleet management over Yggdrasil
- Community governance model

### Phase 4: Full Resilience
- 10,000+ nodes
- Complete content redundancy
- Self-sustaining network
- Cultural institution status

---

## Join the Resistance

Bruce's Bunker is more than a technical project—it's a movement to ensure that human knowledge remains free and accessible to all, forever. Whether you're technical or not, whether you have fast internet or live off-grid, there's a role for you in preserving humanity's digital heritage.

### Get Started

1. **Review the BOM**: Pick a mode and ensure you can source components
2. **Choose Your Path**: DIY, Assisted, or Preseeded
3. **Contact BB Team**: Via secure channels
4. **Build Your Node**: Join the preservation network
5. **Spread the Word**: Help others join the effort

### Remember

*"Every node is a library. Every operator is a librarian. Every SD card is a seed of knowledge, waiting to grow when the world needs it most."*

Together, we ensure that no fire can burn all the books, no flood can wash away all wisdom, and no tyrant can silence all truth.

**Knowledge is power. Preservation is resistance. Bruce's Bunker is forever.**

---

*For operational security, specific contact methods and coordination details are shared only through trusted channels. If you're ready to join, you know where to find us.*
