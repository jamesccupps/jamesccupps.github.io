# APOGEE P2 Protocol — Technical Reference

Siemens APOGEE P2 is the building-automation protocol used by Siemens PXC controllers when they talk to supervisory software (Insight, Desigo CC) and to each other. No public specification exists. This document describes the protocol based on:

- Wireshark captures of live supervisor ↔ PXC traffic across multiple firmware revisions
- Empirical probing against PXC controllers under controlled conditions
- Cross-referencing observed wire behavior against the vendor's point-definition metadata
- Packet captures from a multi-panel reference site running a mixed PME1252 / PME1300 firmware mix, totalling several MB of traffic and thousands of messages:
  - **5033-side baseline** (~1.6 MB, ~7900 messages, 188 TCP flows) — all 5033-side traffic; the baseline for polling behavior.
  - **Server-side full capture** (~4.6 MB) covering TCP 5033, TCP 5034, and BACnet — exposes the PXC→supervisor push channel.
  - **PPCL-enumeration capture** — supervisor-side capture of a scanner probing one panel. Contains ~100 consecutive `0x0985` calls — the reference for decoding the PPCL enumerate protocol.
  - **PPCL-refresh capture** — small capture of a "Clear Tracebits / Refresh" operation on a PPCL program. Exposes opcode `0x4106`.
  - **Scanner-side capture** of a full `--walk-points` and `--dump-programs` run against a single panel. Validates the enumerate opcodes against live firmware.
  - **Alarm-acknowledgement capture** (~5 MB, 24 minutes, 35k packets, 10 panels) — server-side capture of a Desigo CC supervisor session that includes an operator acknowledging two alarms. First wire-level evidence of the alarm-handling opcodes (`0x0508` / `0x0509`) and refines the role of `0x0273`.
  - **Property-write workflow capture** (~1.3 MB) — server-side capture of an operator changing a numeric setpoint from 50 back to 40 via Desigo CC. Surfaces the `0x0240`/`0x4222` write-opcode split, the new `0x0E15` "wrong write opcode" error code, and the read-write-verify cadence Desigo follows for property modifications.
  - **Read-all-subpoints capture** (~2.7 MB) — operator-driven "list all subpoints" against two TEC-attached devices. Surfaces all data-type codes seen across the captures (`0x00`, `0x02`, `0x03`, `0x06`) in the same session, enabling a cross-checked count.
  - **Mixed supervisor sessions** (~5 MB and ~5 MB) — long Desigo sessions covering steady-state polling, COV traffic, periodic identity refreshes, and incidental writes. Used to confirm that opcode and error inventories don't surprise across longer time windows.
  - **Multicast presence capture** (~30 KB, 91 seconds) — small dedicated capture of the BLN multicast beacons. Confirms beacon endpoint, payload, and cadence (corrected from prior "UDP 5033" hypothesis to actual UDP 10001 / 233.89.188.1).
  - **Enumerate-iteration captures** — small focused captures of a scanner attempting different `0x0986` request body shapes against a live panel. Reveals which cursor formats the panel accepts (two distinct encodings) and which silently fail with `0x0003`.
  - **Comprehensive all-interface capture** — supervisor-side capture of all interfaces simultaneously (Ethernet + IPv6 loopback). Surfaces the dual-emission of the presence beacon (multicast + directed broadcast as a paired emission), and confirms that the supervisor's loopback IPC (`BCM\0`-prefixed framing on TCP/4998) is a separate Desigo-internal protocol — not P2 — and out of scope for this document.
  - **Schedule-editing capture** (~4.9 MB) — extended Desigo session that walks, reads, and writes weekly schedules across multiple panels. Surfaces a previously undocumented schedule-operation family in the `09xx` range (`0x0961`, `0x0964`, `0x0965`, `0x0966`, `0x0969`, `0x0971`, `0x0974`, `0x0975`, `0x0976`, `0x0979`, `0x098B`–`0x098F`), the schedule property-write pair `0x5022` / `0x5020`, and a third connection mode (see *Connection modes*). First wire-level evidence of the BACnet 4-byte date encoding inside schedule entries.
  - **Schedule-reading capture** (~641 KB) — supervisor reading a single schedule object's properties end-to-end. Confirms the `0x098C`–`0x098F` sub-property family on a single object: setpoint table, daily entries, PID/gain config, and deadband respectively.
  - **Site-discovery capture** (~341 KB) — Desigo CC initial-bind session against a fresh PXC. Surfaces opcode `0x040A` (multi-state label catalog fetch — returns named state-sets like `ZONE_MODE` / `UNOCC_OCC`) and `0x5038` (cursor-based enumerate of object-name → display-label → state-set-reference triples).
  - **PPCL-edit capture** (~63 KB) — operator editing a single PPCL line in Desigo CC. Surfaces the program editor opcode family `0x4100` (line write/create), `0x4103` (program enable/disable hint), and `0x4104` (line read/delete by line number) — companions to the previously-known `0x4106` ClearTracebits.
  - **UI-browse capture** (~686 KB) — operator clicking through tree views in Desigo CC. Surfaces the small-form (~30–40 byte) variant of `0x4200` PropertyQuery, distinct from the large pre-allocated 222-byte form used by deep property reads.
  - **Cold-probe captures** (`enumeratetest1-3.pcapng`) — focused tests of malformed / experimental request bodies. Useful as negative examples: probes `0x0245` and `0x4500` with 3–4 byte bodies always error; this is included as a guard for scanner authors.

Every stream across all captures parsed cleanly against the framing rules below with zero desyncs.

Treat every claim here as "observed to be true in tested environments, not officially documented."

**Terminology note.** The network on which P2 runs is called the **BLN** (Building Level Network) in original APOGEE documentation and the **ALN** (Automation Level Network) in newer Desigo-era Siemens documentation — the two names refer to the same network layer. Above it sits the **MLN** (Management Level Network) where Desigo CC / Insight workstations live; below it sits the **FLN** (Field Level Network, running the P1 protocol) where TEC devices live. This document uses BLN throughout, consistent with APOGEE-era naming and the panels it describes.

---

## Transport

P2 is a **peer-to-peer protocol with two listening sides**, not a client/server protocol. Both the supervisor (Desigo CC / Insight / WCIS) and every PXC listen on well-known TCP ports, and either side initiates connections to the other as needed.

| Port | Listener | Typical caller | Carries |
|------|----------|----------------|---------|
| **TCP 5033** | PXC | Supervisor | Point reads, enumerations, writes of BLN-sourced virtuals into panel model, mid-session identity refreshes |
| **TCP 5034** | Supervisor (DCC / WCIS) | PXC | COV notifications (0x0274), quality-rich value pushes (0x0240), BLN routing-table announcements (0x4634) |

The `|5034` suffix in the supervisor's identity string (`DCC-SVR|5034`) is a literal declaration of its listen port — it tells each PXC where to send asynchronous pushes. Every PXC on the BLN opens outbound TCP to the supervisor's 5034 at boot and keeps it up.

Consequence for tooling: a "P2 scanner" that only speaks the 5033 side sees polling traffic and nothing else. A passive listener on 5034 captures live COV streams from every panel on the BLN without issuing any reads — roughly one message per device-point-change event.

### Multicast presence beacons (UDP 10001 / 233.89.188.1)

Out-of-band from the TCP point-read traffic, BLN gateways emit a periodic IPv4 multicast beacon. **Despite older documentation suggesting it lives on UDP 5033, the beacon is actually on UDP 10001 to multicast group `233.89.188.1`.** No UDP 5033 traffic appears in any of the 40+ captures analyzed across multiple sites and capture vantages — the doc-historical claim that "UDP 5033 exists for multicast discovery" is wrong and is corrected here.

Beacon characteristics:

| Field | Value |
|-------|-------|
| Destinations | **Both** multicast group `233.89.188.1` (Siemens-allocated) **and** directed broadcast `255.255.255.255` — emitted as a pair |
| Destination port | UDP `10001` |
| Source port | Ephemeral (varies per emission) |
| Payload | 4 bytes: `01 00 00 00` |
| UDP datagram length | 12 bytes (8-byte UDP header + 4-byte payload) |
| Cadence | One emission pair roughly every 10.5 seconds, very regular |
| Senders | BLN gateway/router devices (multiple senders observed simultaneously on multi-VLAN sites) |

**Dual emission**: each beacon is sent twice in immediate succession — once to the multicast group, once to the directed broadcast — typically within 1 millisecond of each other from the same source (observed deltas range 0.000–0.460 ms across the corpus, with most pairs <100 µs apart). This redundancy presumably ensures presence detection works regardless of whether the receiving switch has IGMP snooping configured. Earlier captures saw only the multicast variant because their SPAN port filtered broadcast frames; a comprehensive any-interface capture surfaces both. The 10.50-second inter-pair cadence is consistent across every capture in the corpus and across multiple sources on multi-VLAN sites, so it is a hardcoded interval rather than a configurable timer.

**Corpus-wide statistics (51 pcaps from the OCC site):** 1040 beacon packets observed across 26 pcaps. Every one carries the identical 4-byte payload `01 00 00 00` (zero variation in 1040 samples). Two unique source IPs: `10.0.0.1` (547 packets, HVAC VLAN gateway) and `10.0.1.1` (493 packets, HVAC-Ext VLAN 6 gateway). Two destinations: `233.89.188.1` (534 packets) and `255.255.255.255` (506 packets). Of 906 inter-emission intervals, 474 fall in the [10.0 s, 11.0 s] band (the real cadence — median 10.4906 s, max 10.6546 s) and 415 are sub-millisecond (the multicast/broadcast pair-emission deltas). The pattern is mechanically regular.

The beacon is a presence-announcement, not a discovery query — it carries no node name, no BLN identifier, no routing data. A scanner that wanted to use it for site discovery would see only "something Siemens-shaped is alive on this segment" and would still need to brute-force-attempt the TCP handshake to identify specific nodes. The cartesian-attack discovery flow documented later remains the reliable approach.

The existence of the multicast/broadcast pair does mean a passive listener on a SPAN port can detect Siemens BLN presence without sending any packets — useful for inventory/audit. Either reception path works (multicast subscription via IGMP, or broadcast reception on the local segment).

A small number of PXCs in the reference capture used non-ephemeral source ports (e.g. one panel used TCP source port 3513 for its outbound 5034 connection). This appears to be a per-panel configuration choice, not a separate service. Treat any `PXC_IP:* → DCC_IP:5034` flow as P2 regardless of the PXC-side source port.

---

## Message envelope

Every message starts with a 12-byte header:

```
+----------+----------+----------+
|  u32 BE  |  u32 BE  |  u32 BE  |
|   len    |   type   |   seq    |
+----------+----------+----------+
| payload bytes ...              |
```

- **`len`** — total message length including the 12-byte header
- **`type`** — message type code (see below)
- **`seq`** — monotonically increasing sequence number, incremented per message by each side independently

Multiple messages can arrive coalesced in a single TCP segment; the `len` field delimits them. A scanner that doesn't respect `len` and treats each TCP segment as one message will silently lose up to ~5% of messages due to coalescing; parse strictly on `len`, not on segment boundaries.

**Sequence number echo:** The PXC echoes the client's `seq` value in its response. In the reference pcap, 3848 of 4025 C2S→S2C pairs (95.6%) match by seq; the remaining 177 are all CONNECT/ANNOUNCE which occupy a separate seq space. Use seq-echo as your primary request/response pairing primitive.

---

## Message types

| Code | Name | Purpose |
|------|------|---------|
| `0x2E` | CONNECT | Initial connection announcement (legacy-dialect handshake) |
| `0x2F` | ANNOUNCE | Initial connection announcement (modern-dialect handshake) |
| `0x33` | DATA | Operational request/response (legacy-dialect only) |
| `0x34` | HEARTBEAT | Session maintenance + operational ops (both dialects — see below) |

**Type 0x33 vs type 0x34 is firmware-dialect-dependent, not reads-vs-keepalive.** See the dedicated dialect section below. Old analyses hypothesized 0x34 was reserved for "idempotent operations" based on error-rate skew in early captures — that hypothesis is wrong. The actual explanation is that legacy-firmware panels (PME1252 and earlier) route operational traffic through 0x33 DATA; modern-firmware panels (PME1300 platform) route it through 0x34 HEARTBEAT. The 0x33-with-errors / 0x34-without-errors pattern in one-site captures is just the ratio of legacy-to-modern panels on that BLN.

---

## Firmware dialects (PME1252 vs PME1300)

Siemens PXC firmware splits into two incompatible message-type dialects. A scanner that only speaks one will silently fail against half the panels on a mixed-firmware site. Detection and auto-selection is mandatory.

### The two dialects

| Aspect | Legacy dialect | Modern dialect |
|--------|---------------|----------------|
| **Firmware lineage** | PME1252 and earlier (BACnet ASC, original APOGEE) | PME1300 platform and later |
| **Example build date** | Oct 2013 | Sep 2019 |
| **Initial handshake** | C2S type `0x2E` CONNECT | S2C type `0x2F` ANNOUNCE (PXC initiates) |
| **Operational msg_type** | `0x33` DATA | `0x34` HEARTBEAT |
| **Response msg_type** | matches request (`0x33`) | matches request (`0x34`) |
| **Behavior on wrong msg_type** | silently dropped (no RST, no error) | silently dropped (no RST, no error) |

All other protocol structure — opcodes, routing headers, TLV format, sequence-number echoing — is identical between dialects. Only the `msg_type` byte in the 12-byte frame header differs.

### Evidence

Across the reference capture (~1100 seconds of supervisor↔PXC traffic on a mixed-firmware BLN with multiple PXCs):

| Dialect class | msg_type 0x2E | 0x2F | 0x33 | 0x34 | Typical firmware |
|---|---|---|---|---|---|
| Legacy (8 panels observed) | ~100 each | 0 | 300–10k each | 0 | PME1252 / V2.8.1x |
| Modern (1 panel observed) | 0 | ~100 | 0 | ~2000 | PME1300 / V2.8.18 |

The modern-dialect panel shows zero overlap with the legacy-dialect pattern — different initiator, different operational msg_type, zero crossover.

### Detection algorithm

The dialect is not advertised anywhere before the handshake completes, so the detection is empirical. The working algorithm:

1. Send the handshake (routing header + `0x4640` IdentifyBlock payload) with `msg_type = 0x33`
2. Wait for a response with a short timeout (~2 seconds)
3. If a response arrives with `msg_type = 0x33` or `0x34`, lock that in as the session's operational msg_type
4. If no response, retry the handshake with `msg_type = 0x34` and a longer timeout
5. If that wins, lock in `0x34`; otherwise the connection is unusable

A dialect cache keyed by host IP avoids repeating the probe on subsequent connections to the same panel. See `_probe_dialect()` and `_DIALECT_CACHE` in the scanner source.

### What happens if you pick wrong

The panel silently drops the message. No TCP RST, no error response, no log entry visible from outside — just timeout. This is why an early scanner appeared to "succeed" at connecting to a modern-dialect panel (TCP accept worked) but then every subsequent read returned None (operational reads were being ignored). Visible in Wireshark as a stream of PSH/ACK packets from the scanner to the PXC with zero response payloads from the PXC.

### Known unknowns about dialects

- **Whether PME1300 also accepts 0x33.** Based on the reference-site captures it doesn't — the 0x34 dialect appears strict. A panel running transitional firmware might accept both, but we haven't observed one.
- **What triggered the change.** The PME1300 is a newer hardware generation than the PME1252 APOGEE line — likely a different internal architecture, so the wire-format change may correspond to a complete networking-stack rewrite rather than a tunable config.
- **Whether there are other dialects in the field.** PXCM/PXC Compact lines, BLN routers like the 101000 virtual entry, and BACnet-gateway appliances may use different wire conventions. Not observed in any pcap so far.

---

## Session model

You cannot just open a TCP connection and send a read. The PXC will silently drop operational messages from a connection that hasn't completed a valid identity handshake. Required sequence:

1. TCP connect to port 5033
2. Send a type `0x2E` CONNECT (or `0x34` HEARTBEAT containing a `0x4640` IdentifyBlock)
3. Receive the identity response (validates you're allowed in)
4. Send type `0x33` DATA messages carrying operation opcodes
5. Send `0x4640` IdentifyBlock messages periodically to keep the session alive (see "Session keepalive" below)

If step 2's identity check fails, the PXC responds in one of two ways described in "The bouncer" below.

**Note on the handshake carrier:** The original protocol assumed heartbeat-carries-identity was the only path, but the reference pcap shows explicit CONNECT (type `0x2E`) and ANNOUNCE (type `0x2F`) messages used by Desigo CC for the initial handshake. See "Connection handshake" below for full wire format. Both paths are accepted by the PXC.

### Session keepalive — empirical cadence

Captures of long-running Desigo CC ↔ PXC sessions show the supervisor emitting a fresh `0x4640` IdentifyBlock every **10.0 seconds, exactly**, on each established TCP connection. Cadence measured across 5 streams × 155 emissions each — zero variance. This isn't documented in vendor materials but is the de-facto interval Desigo CC uses.

A scanner can probably stretch this — panels haven't been observed dropping idle connections at 11s, 30s, or 60s — but the safe choice is to match Desigo's cadence: send a `0x4640` every 10 seconds on each open TCP connection regardless of whether other traffic is active. The 0x4640 frame is small (~80 bytes) so the bandwidth cost is negligible.

For sessions that must survive multi-day runs: P2 sequence numbers are u32 monotonic per side. Wraparound at `2^32` has not been observed in any capture (would take ~13.6 years at 10 messages/second), but a robust implementation should handle the wraparound silently (modular increment, not error).

---

## Routing header

Every message payload begins with a direction byte followed by four null-terminated ASCII strings:

```
[dir] [BLN name]\0 [name A]\0 [BLN name]\0 [name B]\0
```

The direction byte is:

| Byte | Meaning |
|------|---------|
| `0x00` | Request (C2S) |
| `0x01` | Successful response (S2C) |
| `0x05` | Error response (S2C) |

These are the only three values observed on the wire. No other values appear across 7873 messages.

### Name ordering: NOT the same for all message types

**This is a correction to the original doc.** The ordering of names A/B differs by message type:

| Message type | Slot 2 | Slot 4 |
|--------------|--------|--------|
| `0x33` DATA (C2S) | destination node | source scanner |
| `0x33` DATA (S2C) | destination (= original source) | source (= original dest) |
| `0x34` HEARTBEAT | same as DATA | same as DATA |
| `0x2E` CONNECT | sender (self) | recipient (peer) |
| `0x2F` ANNOUNCE | sender (self) | recipient (peer) |

Concrete examples from the reference pcap:

DATA C2S (client addresses PXC):
```
00 "SITEBLN" "node6" "SITEBLN" "DCC-SVR|5034"
       BLN    DEST      BLN         SRC
```

DATA S2C (PXC response):
```
01 "SITEBLN" "DCC-SVR|5034" "SITEBLN" "NODE6"
       BLN         DEST            BLN      SRC
```

CONNECT C2S (client introduces itself to PXC):
```
00 "SITEBLN" "DCC-SVR" "SITEBLN" "NODE1"
       BLN      SELF         BLN      PEER
```

The safest parser rule: don't hardcode which slot is dest vs src. Parse the 4 names with the message type in mind. Validate them against known pairs.

**Scanner identity conventions:**
- Desigo CC servers: `<SITE>DCC-SVR|5034`
- Insight servers: `<SITE>WCIS-SVR`
- Engineering tools (field techs): varies, often includes the tool name

The `|5034` suffix on the scanner identity is the port the scanner is listening on for responses — it's not a separator, it's part of the scanner's identity string. Interestingly, CONNECT/ANNOUNCE messages use the bare form `DCC-SVR` without the `|5034` suffix, while DATA messages use `DCC-SVR|5034`. Both forms must be recognized.

---

## The bouncer (identity validation)

The PXC validates three fields on every handshake. Each has a distinct failure signature:

| Field | If wrong | Why it matters |
|-------|----------|----------------|
| **BLN name** | TCP RST | BLN is both security AND routing — wrong BLN means the PXC has no valid route for the packet |
| **Scanner name** | Silent drop | TCP connection stays up; all data messages discarded |
| **Node name** | Silent drop | Same as scanner — connection looks healthy, nothing works |

The site name and trailer bytes in the handshake are **decorative** — the PXC doesn't validate them. This is empirically confirmed via isolation testing (mutate one field at a time, observe the response).

The distinct BLN-RST vs scanner/node-silent behavior is what makes cold-site discovery tractable: you can enumerate BLN candidates in parallel by looking at TCP RST vs silent drop, without having to send actual reads.

---

## Connection handshake: CONNECT (0x2E) and ANNOUNCE (0x2F) wire format

CONNECT and ANNOUNCE have **structurally identical payloads**. The only differences are the message type code (0x2E vs 0x2F) and slight byte-length variation for the embedded node name.

A CONNECT with node name `NODE1` (5 chars) is 76 bytes; an ANNOUNCE with node name `NODE11` (6 chars) is 78 bytes. The delta is exactly the character-count difference in the node name, which appears twice in the payload.

Full layout (CONNECT example with node6):

```
00                         direction byte (request)
"SITEBLN"\0                BLN (routing header slot 1)
"DCC-SVR"\0             sender / self (routing header slot 2)
"SITEBLN"\0                BLN (slot 3)
"NODE1"\0                  peer / target node (slot 4)
46 40                      0x4640 IdentifyBlock marker
01 00 05 "NODE1"           TLV: node name (tag=0x01, u16 BE length)
01 00 03 "ACM"             TLV: site name
01 00 07 "SITEBLN"         TLV: BLN name
00 01 01 00 00 00 00 00    8 bytes constant (flags?)
00 XX XX XX XX             5 bytes: null-pad + 32-bit Unix epoch (big-endian)
00 00 00                   3 bytes trailer
```

### The embedded timestamp

Bytes at offset `len-7 .. len-4` of the payload are a **big-endian 32-bit Unix epoch timestamp** in seconds. The preceding byte is always `0x00` (padding or a u40 high byte).

In the reference capture, 177 CONNECT/ANNOUNCE messages spanned 274 seconds of wall-clock time, and the decoded timestamps span exactly 274 seconds — each timestamp matches the capture time of the message within 1 second. This confirms the field is a live wall-clock timestamp rather than a session-relative counter.

**Practical implication:** the PXC almost certainly validates (or at least logs) this timestamp. A scanner sending CONNECT with a wildly wrong timestamp may get rejected or flagged in panel logs. Always send `int(time.time())` encoded big-endian into these bytes.

### The inner TLV format

The IdentifyBlock's strings use a simple tag-length-value form:

```
tag (u8, always 0x01 for string)
length (u16 BE)
value (raw ASCII bytes, not null-terminated)
```

This inner TLV format also appears in DATA message bodies for point names, device names, and response payloads. It is **distinct from** the outer routing-header strings, which are null-terminated with no length prefix.

### Three connection modes

Captures across the corpus reveal **three distinct connection patterns** that the supervisor uses to talk to a PXC. Scanner authors must recognize all three or they will mis-frame traffic.

| Mode | First-frame type | Subsequent frames | Identity exchange? | Where seen |
|------|------------------|-------------------|---------------------|-----------|
| **Mode A: Standard handshake** | `0x2E` CONNECT | `0x33` DATA / `0x34` DATA / `0x40` heartbeat | Yes — CONNECT carries IdentifyBlock | Steady-state Insight / Desigo sessions, all `5033`-side polling |
| **Mode B: Reverse handshake** | `0x2F` ANNOUNCE | `0x33` / `0x34` / `0x40` | Yes — symmetric to Mode A but PXC-initiated | PXC→supervisor connections to TCP `5034` |
| **Mode C: Single-msg-type carrier** | `0x2E` or `0x2F` | **Every** subsequent frame is also `0x2E` (or `0x2F`) — never `0x33`/`0x34` | **Optional** — see two sub-variants below | Schedule-edit and PPCL-edit sessions; specific Desigo workflows; PXC→DCC alarm bursts |

**Mode C is undocumented in any prior reference and easy to miss.** The defining property of a Mode C connection is that **the message-type byte never transitions from `0x2E`/`0x2F` to `0x33`/`0x34`** for the entire lifetime of the TCP connection. Operational opcodes (reads, writes, schedule ops, alarms) all ride inside `0x2E` (or `0x2F`) framing. The routing header is the bare `OCCDCC-SVR` form (without the `|5034` listen-port suffix).

Within Mode C there are **two sub-variants**, distinguished by what's in the very first frame:

| Mode C sub-variant | First frame | Use case |
|--------------------|-------------|----------|
| **Mode C with handshake** | `0x2E`/`0x2F` carrying a normal `0x4640` IdentifyBlock | A regular session that just keeps using the CONNECT/ANNOUNCE framing for its operational frames instead of switching to `0x33`/`0x34`. Indistinguishable from a stalled Mode A/B handshake unless you watch the whole flow. |
| **Mode C headless** | `0x2E`/`0x2F` going straight to an operational opcode (`0x0961`, `0x0969`, `0x0271`, `0x0508`, etc.) — no `0x4640` at all | Short bursty workflows: schedule queries, ad-hoc reads, alarm pushes. The supervisor (or panel) opens a fresh TCP connection just to fire off a few opcodes and tear it down — too short to be worth a handshake. |

**Both directions exist.** Mode C is **not** uniquely DCC→PXC. Across the corpus, fresh Mode C connections (caught at SYN) split roughly evenly:
- DCC→PXC:5033 — DCC initiates, sends schedule operations (`0x0961`, `0x0969`, `0x0974`)
- PXC→DCC:5033 — PXC initiates, sends reads (`0x0271`) or alarm reports (`0x0508`)

The PXC-initiated Mode C connections all target the **DCC's port 5033**. This means at least at the OCC site, the DCC service listens on **both 5033 and 5034**. (Many references describe DCC as "5034-only" — that may be a deployment-specific simplification. Treat 5033/5034 as both-ways-listenable in any robust scanner.)

Sample headless Mode C flow from the schedule-edit capture, supervisor `10.0.0.108:55811 → 10.0.0.90:5033`:

```
Frame  Type  Direction  Opcode   Notes
1      2E    →          --       fresh TCP, bare CONNECT, no IdentifyBlock
2      2E    →          0x0964   schedule-name query (TITLE.PARTNERS)
3      2E    ←          0x0964   response carrying value+units+limits
4      2E    →          0x0971   enhanced point read (same target)
5      2E    ←          0x0971   response
...    2E    →/←        0x098C-0x098F  schedule sub-property reads
27     2E    →/←        --       FIN
```

All 27 frames in the connection are `0x2E`. There is no `0x33` or `0x34` anywhere. The opcodes carried inside are full-form (real opcode bytes followed by a real body, not a 2-byte bare-opcode probe).

**Distinguishing Mode C from a Mode A handshake's bare-opcode session pings.** PROTOCOL.md previously documented bare 2-byte CONNECT frames carrying opcodes like `0x0951`/`0x0954`/`0x0955`/`0x0956`/`0x0959` as session-keepalive pings inside an established session. Those still exist and remain PXC→DCC-only inside an active Mode A session — they are 2 bytes total, no body, no response expected. Mode C is the opposite: it is the *initial* frame on a fresh connection and carries a full body. Tell them apart by:

- Frame size: bare-opcode pings are exactly 2 bytes of payload after the routing header; Mode C frames are typically 30–250 bytes
- TCP state: bare-opcode pings appear mid-session after a Mode A handshake; Mode C frames appear immediately after the TCP three-way handshake on a new connection
- Direction: bare-opcode pings are PXC→DCC; Mode C connections are bidirectional (either side may initiate)

**Dialect coupling.** Mode C connections from the schedule-edit capture all used `0x2E`, which is the legacy-dialect message type. Other captures show Desigo using `0x2F` for the equivalent flow against newer-firmware panels. Treat Mode C type as following the same dialect rules as Mode A (see *Firmware dialects* above).

**Implementation note.** A scanner that only dispatches on `0x33`/`0x34` will silently drop every byte of a Mode C-headless session and report "no traffic from panel." A robust dispatcher must accept opcode payloads inside `0x2E` and `0x2F` whenever the first two bytes after the routing header are not `0x46 0x40`. The marker that selects the inner parser is: "first 2 bytes after routing header == `0x46 0x40` → IdentifyBlock (Mode A/B initial frame, or Mode-C-with-handshake initial frame, or mid-session identity refresh); otherwise → operational opcode." Importantly, **`0x4640` IdentifyBlock TLVs can also appear mid-session inside `0x2E`/`0x2F` frames as periodic identity refreshes (see Session keepalive)** — those are normal in any mode and not a signal of mode transition.

**Retry doubling.** Mode C requests in the schedule-edit capture were often sent twice back-to-back (~30–80 ms apart) before the response arrived. Whether this is a Desigo client quirk or a protocol-level retry policy is unclear; a scanner replicating this isn't necessary, but a *parser* that observes Mode C traffic should not flag the duplicate as a desync.

---

## Operation opcodes (inside type `0x33` and `0x34` payloads)

After the routing header, the payload contains a big-endian 16-bit opcode followed by opcode-specific data. The full opcode map observed in the reference pcap:

### Point reads and writes

| Opcode | Direction | Operation | Notes |
|--------|-----------|-----------|-------|
| `0x0220` | 5033 | ReadShort | Desigo CC's preferred read, compact request |
| `0x0271` | 5033 | ReadExtended | Legacy-client dialect; returns full value block |
| `0x0272` | 5033/5034 | **ReadExtended-MetaOnly** (likely) | Wire format identical to `0x0271` but the trailing 2-byte sentinel is **omitted** (just stops at the second TLV). Body shape: `02 72 00 00 [01 00 LL <name>] [01 00 LL <subname>]`. Compare: `0x0271` ends with `00 FF` (request-the-value sentinel), `0x0273` ends with `00 00` (no-value sentinel). `0x0272` ends with neither — likely a "look up the property descriptor without fetching its current value" form, used by Desigo CC during schedule probes. **All 37 corpus samples come from `pcap2429.pcapng` and 35/37 return `0x0003 not_found`** — meaning the opcode is recognized but the named targets don't exist as schedule objects. Carried inside both Mode-C `0x2E` framing and ordinary `0x33` DATA frames |
| `0x0273` | 5033 | WriteNoValue / AlarmAckTrigger | Same wire format as 0x0271, trailer `00 00` instead of `00 FF`. Gets ACK-only response. Now observed sent immediately before `0x0509` AlarmAck for the same point in operator alarm-acknowledgement flows — likely the operator-action trigger or a state-clear precondition for the formal ack. Wire format is identical to a legacy read; the trailer is the only structural difference |
| `0x0274` | both | ValuePush / COVNotification | See below — behavior depends on direction |
| `0x0240` | 5034 only | WriteWithQuality | PXC→DCC push of a BLN-sourced virtual point value, with a quality/sentinel header. Device name is literally `"NONE"` for panel-global points. ACK-only response. **DCC also issues this on 5033 against `SYST`-tagged properties — those reliably error with `0x0E15`, see "Property writes" below** |
| `0x0241` | 5033 | Unknown | Adjacent to 0x0240 but no value payload on the wire; body carries a `SYST\0#` prefix and device/point TLVs. Hypothesized: a property-operation (flag-set, reset, or trigger) against a subpoint. Only 4 samples, semantics unconfirmed |
| `0x4221` | 5033 | BulkPropertyRead | Bulk read of all properties on a SYST-tagged point. Constant-size 273-byte body. Used by Desigo CC when populating a property dialog |
| `0x4222` | 5033 | **BulkPropertyWrite** | Write a value to a SYST-tagged property. Body is a SYST-prefixed point reference + value bytes. **The correct opcode for setpoint writes** — `0x0240` rejects with `0x0E15` on these properties. Wire format and end-to-end workflow documented in "Property writes" below |
| `0x4220` | 5033 | BulkProperty (variant) | Single sample observed; same SYST/point structure as 0x4221/0x4222 but appears to carry a configuration header rather than a value. Exact semantic unconfirmed |
| `0x4200` | 5033 | PropertyQuery | "Does this property exist / give me its descriptor" against a SYST-tagged point. **Two forms**: small (~30–40 byte) form used by Desigo's tree-browse UI: `[01 00 04 "SYST"][23][3F FF FF FF][00 00][LP point-name][00 00 01 00 00 FF FF]` — trailing `FF FF` is a wildcard property-id. Large (222-byte preallocated) form used by deep property reads: same structure but zero-padded to 222 bytes |
| `0x0508` | 5033 + 5034 | AlarmReport (PXC→DCC) | Panel sends this to report alarm state. Rich payload: alarm-class string + alarmed point name (typically repeated) + human description + 8-byte BACnet datetimes (raise / current / last-transition) + alarm-active value + priority/status flags. **Often duplicated across both 5033 and 5034 in the same alarm transition — same payload, sent on both connections within a few milliseconds.** Wire format below |
| `0x0509` | 5033 | AlarmAck (DCC→PXC) | Sent by the supervisor when an operator acknowledges an alarm. Compact — alarm-class header + point name only, no value or timestamps. Wire format below |
| `0x5003` | 5033 | Unknown | Small request, `SYST` prefix + one point name (sample seen carried a single zone-level point name). Possibly a zone-level or schedule-level read. 6 samples, semantics unconfirmed |

### Point enumeration (09xx family)

All 09xx enumeration opcodes share a cursor-based pagination model. The three main ones (`0x0981` walk points, `0x0985` read PPCL, `0x0986` enumerate FLN) are distinct in request shape — the "same request format with a different opcode byte" assumption is WRONG and will fail with `0x05 0x00 0x03` (not found).

| Opcode | Operation | Notes |
|--------|-----------|-------|
| `0x0981` | EnumeratePoints | Walks **every point on the panel** — more complete than `0x0986`. Returns panel-internal points (PPCL variables, schedule points, global analogs) in addition to FLN-device points. Live-tested against a panel returning 91 points on a ~25-device FLN. |
| `0x0985` | EnumeratePrograms | Walks PPCL programs and returns their source text in chunks. Live-tested against a panel returning all 5 of its programs totaling 103 lines of source, including a 57-line PPCL block. |
| `0x0986` | EnumerateFLN | Lists TEC devices on the FLN bus. The simplest and oldest enumerate; works on every firmware. |
| `0x0982` | EnumerateTrended | Like `0x0981` but entries carry embedded timestamps. Likely trend or schedule points; exact semantic not fully mapped. |
| `0x0988` | EnumerateMulti | Takes a multi-string filter (device AND subpoint AND variant). Useful for targeted enumeration like "every `DAY.NGT` point across all `AC_x` zones." |
| `0x0983`, `0x0984`, `0x0987`, `0x0989`, `0x098C–F` | EnumerateVariants | Additional 09xx variants with different selectors; mostly return `0x00AC` "not supported" on V2.8.10 firmware. |
| `0x099F` | GetPortConfig | Returns panel port configuration indexed by port number. Request is 5 bytes: `09 9F 00 04 XX` where `XX` is the port index. Response carries three dot-separated config fields followed by a port label: `;bd=<baud>;pa=<parity>;mk=<mask>` (serial parameters), `;mid=<BLN-id>;ety=<encoding-type>;pdl=<pad-length>` (BLN routing), and a port label string (e.g. `"USB Modem port"`, `"HMI port"`). Observed indices: `0xFF` = USB Modem port, `0x00` = HMI port, `0x04` = undefined |

#### 0x0986 EnumerateFLN — request format

The simplest of the three. Two cursor TLVs stating "start from here" — on the first call both are `*`, on subsequent calls you pass the previous response's device name.

The panel accepts **two different cursor encodings**, and Desigo CC and minimalist scanners use different ones. Both work; this is the cleanest dual-format observation in the protocol.

**Verbose form** (Desigo CC):

```
09 86                            opcode
00 00 00  00 01  <cursor1>       [3-byte pad][u16 BE length][value]
00 00 00  00 01  <cursor2>       same format
```

The full 14-byte first-call body with wildcards: `09 86 00 00 00 00 01 2A 00 00 00 00 01 2A`.

**Compact form** (alternate, accepted by all panels seen):

```
09 86                            opcode
00 LL  <cursor1>                 [tag=0x00][u8 length][value]
00 LL  <cursor2>                 same format
```

The full 8-byte first-call body with wildcards: `09 86 00 01 2A 00 01 2A`.

Both forms decode to the same panel response. The compact form is 6 bytes shorter and a scanner wanting to minimize bandwidth can use it freely. Empirical confirmation: a wide-iteration capture of a scanner attempting ~20 candidate body shapes against a real PXC showed exactly these two formats accepted, all others returning `0x0003` not_found. **Common malformed variants that look right but don't work**:

- Missing one of the 3-byte pad bytes in the verbose form (e.g. `09 86 00 00 00 01 2A …` — only 2 pad bytes instead of 3)
- Mixing pad bytes with `01 00 LL` LP-string headers (the pattern used in *responses*, not requests)
- Trailing extra `00` or `FF` bytes after the second cursor
- Single cursor only (just `09 86 00 01 2A`)

The asymmetry is structural: **requests use simple cursor TLVs (no leading `01` tag); responses use the full LP-string format with `01 00 LL` prefix**. Don't conflate them.

#### 0x0981 EnumeratePoints — request format

DIFFERENT shape from `0x0986`. Six TLV fields, not two. The first two filter TLVs stay `*` forever; only the fifth slot advances as the cursor.

```
09 81                      opcode
00 00                      2-byte header
01 00 01 2A                filter TLV 1: always "*"
01 00 01 2A                filter TLV 2: always "*"
00 00                      separator
01 00 LL <cursor>          cursor TLV: empty on first call, previous device name thereafter
01 00 00                   trailing empty TLV
```

Byte-verified first call: `09 81 00 00 01 00 01 2A 01 00 01 2A 00 00 01 00 00 01 00 00` (20 bytes).

Byte-verified continuation with cursor `"A04SPS"`: `09 81 00 00 01 00 01 2A 01 00 01 2A 00 00 01 00 06 41 30 34 53 50 53 01 00 00` (26 bytes).

**Critical TLV framing note:** the inner TLV format here is `[tag 0x01][u16 BE length][value]` — 3 bytes of header. An easy bug is to write `[0x01, 0x00][u16 length][value]` assuming the tag is 2 bytes; that shifts every length field by one and corrupts the trailing structure. The PXC responds to a malformed request by returning the first matching entry and then refusing to advance the cursor.

#### 0x0981 — response shapes

Responses come in two shapes depending on whether the enumerated entry is a regular device/point or a panel-level "Title"-style entry.

**SHAPE A — regular device/point with value** (e.g. a physical sensor returning `11.42 PSI` with units):

```
[routing header]
00 00                       separator
01 00 LL <device>           device name TLV
01 00 00 04 00 02 00 00     metadata block
01 00 LL <device>           device name (repeated — yes, 3 times total)
01 00 00 00 01              metadata
01 00 LL <device>           device name (3rd occurrence)
01 00 00                    separator
01 00 LL <point>            POINT name TLV (distinct from device)
3F FF FF F7                 quality sentinel (value block begins)
00 00 NN                    data-type byte (0x02=int, 0x03=analog, 0x06=analog32)
XX XX XX XX                 f32 BE value
01 00 LL <units>            units string TLV (e.g. "DEG F", "PSI", "CFM")
[trailer]
```

**SHAPE B — PPCL-computed variable with value but no quality register** (e.g. `BLR.MIN.STPT / "BLR HW STPT MIN" / 100.00 DEG F` on a modern-dialect panel):

```
[routing header]
00 00
01 00 LL <n>                name (device == point) — repeated 3x
01 00 00 <metadata-block>
01 00 LL <n>
01 00 00 00 01
01 00 LL <n>
01 00 00
01 00 LL <description>      human description (e.g. "BLR HW STPT MIN")
00 00 00 00 00 00 NN        7-byte metadata — 6 zeros + data-type code (see Data-type codes table below)
XX XX XX XX                 f32 BE value
00 00 00                    3-byte pad
01 00 LL <units>            optional units TLV (may be absent on binary points)
[trailer]
```

**SHAPE C — "Title"-only panel entry, no value** (e.g. a label-only row describing what a piece of equipment serves):

```
[routing header]
00 00
01 00 LL <n>                name (repeated)
01 00 00 03 00 02 00 00
01 00 LL <n>
01 00 00 00 01
01 00 LL <n>
01 00 00
01 00 LL <description>      human description only
[metadata trailer — NO sentinel, NO value, NO units TLV]
```

### Disambiguating the three shapes

The parser must try the discriminators in order:

1. **SHAPE A detection**: scan the body for the `3F FF FF F?` quality sentinel. If found, the f32 value sits at sentinel-offset +7 (sometimes +4 or +8 for edge cases). The sentinel is unambiguous — it only appears on physical points with a quality register.

2. **SHAPE B detection**: if no sentinel, scan for the pattern `[00 00 00 00 00 00 XX]` (6 zero bytes followed by a small data-type code in `{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}`) occurring **after the last ASCII TLV**. The f32 value is the 4 bytes immediately following. This pattern is distinct from the SHAPE A metadata because it lacks the quality sentinel.

3. **SHAPE C detection**: if neither pattern found, treat as Title-only — `device == point`, `value = None`, description from the last ASCII TLV.

### The units-TLV trap

A tempting shortcut is "if there's a units TLV, extract the value from just before it." This is wrong in two ways:

- **Binary points have no units TLV** but do have values. Site examples like `PUMP1.RUN`, `PUMP1.ENB`, `PUMP1.ALM` (or any panel-binary status point) all return `3F 80 00 00` (= 1.0 for ON) or `00 00 00 00` (= 0.0 for OFF) with no trailing units string. Don't require a units TLV to extract a value.
- **Descriptions can be short.** "VAV INLET" is 9 chars, "BLR 2 ALM" is 9 chars. A naive length-based "short TLV = units" heuristic will eat descriptions. Use a whitelist of unit patterns (alphanumerics + `%` + known space-bearing patterns like `DEG F`, `IN H20`) to distinguish.

### Compound-name entries (fourth structural variant)

Some panels return enumeration entries with a **compound identity** — two ASCII name TLVs in a row at the top of the body, where normal entries have a single name TLV followed by an empty-TLV separator.

```
Normal entry layout:
  00 00
  01 00 07 <name>            <- one name TLV
  01 00 00                   <- empty separator TLV
  02 00 02 00 00 ...         <- metadata

Compound entry layout:
  00 00
  01 00 04 <name_part1>      <- first name TLV
  01 00 07 <name_part2>      <- second name TLV (subkey)
  02 00 02 00 00 ...         <- metadata
```

Live examples (sanitized):
- `METER1 / DAY.NGT / VARIANT` — a metering point with a "DAY.NGT" subkey on a metering panel
- `MAIN.PGM / OUTPUT1` — a PPCL program output with a named subkey on another panel

The two ASCII parts together form the panel's internal index key. The first part is what clients typically display; the second part is a disambiguator (possibly a sub-field like a schedule slot or program label).

**Important cursor behavior:** when walking via 0x0981 and the current cursor matches a compound entry's first name, the panel returns the same record repeatedly — a single-name cursor can't advance past a compound key. The walker must detect this condition and try mutating the cursor to force advance.

**Cursor-mutation order matters.** A naïve byte-increment (`VAR1` → `VAR2`) is too aggressive — it skips adjacent entries with the same prefix (`VAR10.STPT`, `VAR10.TEMP`, `VAR1T`). The correct order, from least- to most-disruptive:

1. Append `\x01` — smallest string strictly > cursor, returns the very next adjacent entry
2. Append `' '` (0x20), `'0'` (0x30), `'A'` (0x41), `'a'` (0x61), `'~'` (0x7E) — covers longer-prefix entries not caught by `\x01`
3. Byte-increment last character — skips all same-prefix entries, only use as last resort

Observed impact: on a busy panel, skipping the `\x01` append and jumping straight to byte-increment loses approximately 200 points (entire ranges of related points sharing a prefix get skipped in a single jump).

Parser note: don't treat the second name TLV as units or description. It's a structural field unique to compound-name entries. The scanner surfaces it as a `subkey` field in its return dict.

### 0x0220 as an alternative to walking

Desigo does not walk panels with 0x0981 during report generation. Instead it fires individual 0x0220 point-read requests for each point name it already knows about. The request format:

```
[routing header]
02 20                       opcode
00 00                       separator  
01 00 04 SYST               first TLV — always "SYST" (system/scope marker)
01 00 LL <point_name>       second TLV — the point to read
00 00                       separator
[additional TLVs]
```

Observed in live Desigo CC reports: several hundred `0x0220` requests per panel over a single report-generation cycle. The pre-commissioned point database in Desigo Server means it never needs cursor-based walking.

For scanners without a pre-commissioned point list, 0x0981 walking remains necessary — but knowing the 0x0220 approach is useful for validating walk completeness (just compare your walk results against a Desigo-generated request stream).

### SHAPE B value extraction — scan window

A practical gotcha when implementing the SHAPE B f32 extraction: the scan for the `00 00 00 00 00 00 NN` marker must be **bounded by the description TLV and the units TLV** — not just "after the last ASCII TLV."

```
Correct scan window:
  [description TLV] <-- scan starts after this
      [7-byte meta] [f32] [3-byte pad]
  [units TLV]       <-- scan ends before this
  [trailing metadata — do not scan here]
```

If the scan starts after the units TLV (the last ASCII TLV for most SHAPE B responses), it falls into the trailing metadata region where stray zero-runs cause false matches. Classic symptom: values like `2.35e-38` (tiny denormals from misaligned reads) or `0.0` where the real value is something else.

### Walker behavior across firmware versions

A parser that only handles SHAPE A and returns None on B or C will **stop the walker mid-enumeration**. All three shapes interleave alphabetically in a typical panel. Firmware breakdown from live observation:

| Panel firmware | SHAPE A count | SHAPE B count | SHAPE C count |
|---|---|---|---|
| PME1252 (legacy dialect) | ~80 | 0 | ~12 |
| PME1300 (modern dialect) | ~10 | ~70 | 0 |

PME1300 panels strongly prefer SHAPE B for computed variables and timers; PME1252 panels use A and C exclusively. A universal scanner must handle all three.

**Cursor advance:** set the next call's cursor to the **device name** from the response. Dedup cursor keys on device name alone, not on `(device, point)` tuples — all three shapes emit exactly one entry per advance step, and the next response either moves alphabetically forward or returns `0x05 0x00 0x03` to signal end of list.

#### 0x0985 EnumeratePrograms — request format

DIFFERENT AGAIN from both `0x0981` and `0x0986`. Only ONE filter TLV. And instead of a trailing empty TLV, there's a 2-byte u16 big-endian **line number** cursor that advances within a program.

```
09 85                      opcode
00 00                      2-byte header
01 00 01 2A                single filter TLV: "*" (walks all programs)
                           — or the program name itself, for "refresh this one"
00 00                      separator
01 00 LL <cursor>          program-name cursor: empty on first call,
                           otherwise the name of the program to continue in
NN NN                      u16 BE line number: 0 on first call,
                           otherwise the "next_line" hint from the previous response
```

Byte-verified first call: `09 85 00 00 01 00 01 2A 00 00 01 00 00 00 00` (15 bytes).

Byte-verified continuation with cursor `"MAIN_PPCL"` line 10: `09 85 00 00 01 00 01 2A 00 00 01 00 09 4D 41 49 4E 5F 50 50 43 4C 00 0A` (24 bytes).

#### 0x0985 — response format

Each response carries ONE chunk of PPCL source (typically 10 lines) for ONE program, plus pagination hints for the next call.

```
[routing header]
00 00                       separator
01 00 LL <program_name>     program name TLV
01 00 06 <6-char tag>       module type ("ET    ", "DT    ", "D     ") — trailing spaces padded
01 00 LL <source_chunk>     PPCL source text (one or more lines as a single string)
NN NN                       u16 BE: next-line hint (where to resume — feed this back as the line cursor)
HH                          has-more flag: 0x01 or 0x00. NOT a reliable program-boundary signal.
01 00 00 00                 4-byte trailer
```

**Termination:** when the walker asks for a line past the end of the LAST program, the PXC returns a 2-byte error body `00 03` (`DIR_ERROR` + code 0x0003). That's the authoritative end-of-list signal.

**The `has_more` flag is unreliable.** In captures it's `0x01` for the very first chunk and `0x00` for every other chunk, including mid-program. Ignore it. Use the PXC's 0x0003 error as the termination signal instead, and keep feeding the program name + next-line hint back until that fires.

**Program boundaries:** when a program is exhausted, the PXC's next response carries the NEXT program's name and a line number reset to 10 (or whatever its minimum line is). No explicit boundary marker — the scanner detects the transition by noticing that the program name in the response changed.

**Module tag** (second TLV in the response): a 6-character field identifying which PPCL module/memory area the program lives in. Observed values: `"ET    "`, `"DT    "`, `"D     "`. Probably encodes something about scheduling priority or execution context but exact semantic unknown. Surface it in tool output — it's metadata Siemens engineers would recognize.

**Typical run:** enumerating all 5 programs on a representative panel (total 103 source lines) takes ~104 round trips because each response carries ~1-10 lines. PPCL source lines themselves can be up to ~400 characters long (single-line `SET(...)` or `LOOP(...)` statements with many arguments).

#### A 0x0985 alternate mode: "refresh a single program"

When the operator clicks Refresh in Desigo's PPCL editor, Desigo calls `0x0985` with the filter set to the program name instead of `*`:

```
09 85 00 00
01 00 LL <program_name>    filter TLV is program name (NOT "*")
00 00
01 00 LL <program_name>    cursor TLV is same program name
NN NN                      u16 line cursor
```

This refetches the single program without walking the full list. Not needed for a scanner — walk mode covers everything.

### Schedule operations (09xx family — `0x0961`, `0x0964`–`0x0976`, `0x0979`, `0x098B`–`0x098F`)

A previously undocumented family of `09xx` opcodes drives Desigo CC's weekly-schedule editor. These are **not** point-enumerate variants — they are object-targeted property reads against schedule, PID, and setpoint tables. They run almost exclusively inside Mode C connections (see *Three connection modes*), embedded in `0x2E`/`0x2F` framing.

| Opcode | Operation | Body shape (after routing header) | Returns | Notes |
|--------|-----------|-----------------------------------|---------|-------|
| `0x0961` | AnalogPointQuery (legacy) | Same shape as `0x0981` | Often `0x0003` | Returns data on a small number of points; mostly errors. Likely a deprecated form of `0x0971` |
| `0x0964` | TitleAnalogQuery | `[01 00 04 "SYST"][01 00 LL <obj>][01 00 LL <subpoint>]` | Value + units + min/max limits | Used to populate Desigo "TITLE.PARTNERS" room temperature widget. Carries f32 value, units string, and engineering limits |
| `0x0965` | NodeDiscoveryEnumerate | Cursor TLV pair; same as `0x0986` | Node name(s) on the BLN | Used early in a session to confirm panel reachability. Equivalent in function to a slim `0x0986` |
| `0x0966` | ShortQuery | 4-byte body, no SYST tag | Mostly `0x0003` | Probe op; rarely returns useful data |
| `0x0969` | ScheduleObjectList | `[01 00 04 "SYST"][01 00 LL <object>]` | List of schedule object names under a parent | Returns names like `"LIGHTING.2AFLR.OCC"` — schedule objects in a panel namespace |
| `0x0971` | EnhancedPointRead | Like `0x0981` but with extra trailing config bytes | Description + value + units + resolution + min + max + type-code | More complete than `0x0981`. Returned `ROOM TEMP = 71.75 °F`, resolution `0.25`, max `48.0` for one tested point. Use this when a UI needs limits, not just current value |
| `0x0974` | MultistatePointEnumerate | Like `0x0964` but state-set-aware | Object name + current state index + state-set ref | Used for points like `OCC.DUNKIN.HP.ZN/MODE` — pulls current multistate value plus the cursor reference into the matching state-set |
| `0x0975` | NodeDiscoveryWithLines | Cursor + line-number trailer like `0x0985` | Node + line + column index | Used to map PPCL programs to nodes. Sample returned `NODE9TEST / D / 00010 C / 0A` |
| `0x0976` | DeviceAllSubpointsRead | `[01 00 04 "SYST"][01 00 LL <device>]` plus 2-byte slot count | App number (u16) + description + per-slot `(slot_index, f32)` tuples | Powerful "give me everything on this device" op. Sample returned app=`0x07E7` (= 2023, indicating the application code), description "VAV-19", and 18 (slot, value) pairs |
| `0x0979` | ShortVariant | `0x0976`-like body with trailing `02 71` | Variable | The `02 71` trailer references opcode `0x0271` (extended point read). Looks like a "cross-opcode lookup" — request says "use 0x0271 semantics on this object" |
| `0x098B` | NewerFeature | `0x0981`-shape | 100% `0x0003`/`0x00AC` on PME1252 | Newer-firmware enumerate. Captures show Desigo trying it, panels rejecting it |
| `0x098C` | ScheduleSetpointTable | `[01 00 04 "SYST"][01 00 LL <schedule>]` | 5–7 floats representing temperature setpoints | Sample returned `[32.0, 68.0, 53.6, 78.8, 86.0]` °F — a heating/cooling setpoint band table |
| `0x098D` | ScheduleEntries | Same body as `0x098C` | Daily schedule entries with multiple setpoints per entry | The "weekly schedule" payload — see *0x098D wire format* below |
| `0x098E` | ScheduleGainConfig | Same body | 7 floats per row representing a PID/gain configuration | Sample returned `[600.0, 12.2, 1.8, 60.0, ...]` — looks like proportional/integral gains, deadtime, sampling period |
| `0x098F` | ScheduleDeadband | Same body | Single f32 — deadband / threshold | Sample returned `2.0` °F |

All `0x098C`–`0x098F` responses end with the 2-byte sequence `fc 13`, which is a **state-set reference** (matches the cursor returned by `0x040A` for the object's state-set; see *Multi-state label catalog* below). The supervisor uses that reference to render schedule values with the matching state labels.

#### 0x098D wire format — schedule entries

The most complex member of the family. One response can carry an entire week of programmed transitions for one schedule object.

```
[routing header]
01                              direction: success
00 00                           separator
01 00 LL <schedule_name>        e.g. "LIGHTING.2AFLR.OCC"
01 00 02 00 NN                  NN = entry count
[per entry, repeated NN times]:
  01 00 01 [day-of-week 1=Mon..7=Sun]
  00 00 00 [slot in day]
  01 00 01 01 00 00 00 [setpoint count]
  [per setpoint:]
    [BACnet date 4B]            year-1900, month, day, dow
    88 0C XX YY                 4-byte schedule-time field
    [priority 1B]
    00 00 00
    [value 4B u32 BE]            multistate index OR f32 setpoint
    00 00 00 00 00              5-byte trailer
fc 13                           state-set reference
```

The 4-byte BACnet date encoding is **the same one used in alarm timestamps** (see *BACnet date+time format* under alarm parsing) — `[year-1900][month][day][day-of-week]` where `day-of-week` is 1=Mon … 7=Sun. Decoded samples from the schedule-edit capture verify against actual calendar weekdays:

| Bytes | Decoded | Verified day |
|-------|---------|--------------|
| `7B 03 0F 01` | 2021-03-15 | Mon ✓ |
| `7B 03 10 02` | 2021-03-16 | Tue ✓ |
| `7B 03 11 03` | 2021-03-17 | Wed ✓ |
| `7B 03 12 04` | 2021-03-18 | Thu ✓ |
| `7B 03 14 06` | 2021-03-20 | Sat ✓ |

The 4-byte `88 0C XX YY` field that follows is partly understood: byte 0 is always `0x88`, byte 1 is always `0x0C`, byte 2 varies (`0x19`–`0x1F` observed — possibly time-of-day in a packed format), byte 3 matches the date's day-of-week. The constant-prefix bytes look like a BACnet schedule-time encoding marker; precise format is not yet decoded.

The setpoint value is encoded as a 4-byte field after the priority byte. For multistate schedules (lighting on/off, mode select) it's a u32 index into the state-set referenced by the trailing `fc 13`. For analog schedules (temperature setpoints) it's an f32 in the engineering unit indicated by the schedule's units TLV.

#### 0x0976 wire format — DeviceAllSubpointsRead

The most useful new op for scanner authors who want a fast overview of a device. One round trip yields every analog subpoint on the device along with its current value.

Request:
```
09 76                           opcode
00 00                           separator
01 00 04 "SYST"                 scope tag
01 00 LL <device-name>          target device, e.g. "VAV-19"
00 NN                           u8 slot count expected (or 0x00 = all)
```

Response:
```
[routing header]
01                              success
00 00
01 00 LL <device-name>          echoed back
07 E7                            u16 BE app-number (e.g. 0x07E7 = APOGEE app code 2023)
01 00 LL <description>          human-readable, e.g. "VAV-19"
00 NN                            u8 entry count
[per entry:]
  00 SS                          u8 slot index (1..NN)
  XX XX XX XX                    f32 BE value
[trailer]
01 00 LL <units>                 e.g. "DEG F"
fc 13                            state-set ref
```

Live sample (sanitized): a VAV controller returned 18 entries in 286 bytes — way faster than walking the same 18 points individually via `0x0220`.

**Caveat.** `0x0976` only returns analog (`f32`) subpoints. Multistate or binary subpoints on the same device are skipped from the response. To get those, fall back to `0x0974` for multistates or `0x0220`/`0x0271` for binaries.

#### Why this family exists

These opcodes give Desigo CC's schedule editor an O(1) round-trip to render a full schedule with all its supporting metadata (setpoint table, daily entries, PID config, deadband, state labels). Without them, rendering the same view via `0x0220` would take ~50–100 round trips per schedule object. Practically, this means: if a scanner observes Mode C `0x098C`–`0x098F` traffic, an engineer is editing schedules in Desigo right now.

### Schedule property writes (`0x5020` / `0x5022`)

Schedule edits land via a paired write: an init/allocate (`0x5022`) followed by an entry-write (`0x5020`). Both observed in the schedule-edit capture (sequence numbers 529731 → 529732) targeting schedule objects `LIGHTING.2AFLR.OCC` and `ABSOLUTE HEALTH OCC`.

#### 0x5022 — schedule slot init

A 222-byte preallocated body that "claims" a schedule slot for subsequent writes. Most of the body is zero padding; the meaningful fields are the schedule name and the slot index.

```
50 22                           opcode
01 00 04 "SYST"                 scope
23                              separator (0x23 — same as 0x4222 writes)
3F FF FF FF                     property wildcard
00 00
01 00 LL <schedule-name>
01 00 00 00 [slot u32 BE]       slot to allocate
00 ...                          zero-pad to 222 bytes total body
```

Response is empty success ACK.

#### 0x5020 — schedule entry write

Variable-length write that fills an allocated slot with the actual schedule entry data. Format:

```
50 20                           opcode
01 00 04 "SYST"                 scope
23
3F FF FF FF
00 00
01 00 LL <schedule-name>
00 00 00 [slot u32 BE]          which slot (matches the prior 0x5022)
01 00 01 01                     entry header
00 00 00 [byte-count u32 BE]
[BACnet date 4B]                year-1900, month, day, dow
88 0C XX YY                     schedule-time field (same as 0x098D)
[priority 1B]
00 00 00 
[value u32 BE]                  multistate index OR f32 setpoint
00 00 00 00 00
```

Response is empty success ACK.

**Use pattern.** Editing one schedule entry takes one `0x5022` (allocate slot 4) + one `0x5020` (write the entry data into slot 4). Adding multiple entries to a schedule means looping the pair, advancing the slot index each time. Deletion appears to use `0x5022` with a sentinel slot value, but no clean delete operation has been captured.

**Auditing.** A passive listener that flags every `0x5020`/`0x5022` pair on the BLN is the cleanest possible "who changed a schedule" detector. There is no separate audit-log opcode; the writes themselves are the audit trail.

### Multi-state label catalog (`0x040A`)

`0x040A` returns a **named state-set** — a list of label strings indexed by integer position. State-sets are referenced from schedule and multistate-point responses via the trailing 2-byte `fc XX` cursor.

#### Request

```
04 0A                           opcode
01 00 04 "SYST"                 scope
01 3F FF FF FF
00 00 [cursor u16 BE]           which state-set to fetch (e.g. 0xF82A)
[zero-pad to 222 bytes total body]
```

The cursor is **the value previously returned in the trailer of a multistate-point response**. State-set IDs are panel-internal; a scanner walking unknown state-sets must enumerate cursors by trial.

#### Response

```
[routing header]
01                              success
[next-cursor u16 BE]            ID to use for the next 0x040A call (or 0xFFFF = end)
01 00 LL <state-set-name>       e.g. "ZONE_MODE", "UNOCC_OCC"
[count u16 BE]
[per state, repeated count times]:
  [index u16 BE]                state index (typically 0..count-1)
  01 00 LL <label>              ASCII label (e.g. "VAC", "OCC1", "WARMUP")
```

**The order is name-then-cursor-then-count, then per-state index-then-label.** This is the OPPOSITE order from what an early reverse-engineering pass might assume (label-first, index-second). Get this right or every state index will be off-by-one.

Decoded sample from the site-discovery capture:

| Cursor | State-set name | States |
|--------|----------------|--------|
| `0xF82A` → `0xF82B` | `ZONE_MODE` | 12: `VAC, OCC1, OCC2, OCC3, OCC4, OCC5, WARMUP, COOLDOWN, NGHT_HTG, NGHT_CLG, STOP_HTG, STOP_CLG` |
| `0xFC12` → `0xFC13` | `UNOCC_OCC` | 2: `UNOCC, OCC` |

The 12-state ZONE_MODE catalog (not 7 as a partial earlier RE pass suggested) is the canonical APOGEE zone-control mode list. UNOCC_OCC is the most common 2-state label set used for occupancy-driven schedules.

**A scanner can pre-populate** a state-set cache by walking `0x040A` from cursor 0 forward until the next-cursor returns 0xFFFF. The catalog is small (typically <30 state-sets per panel) and fully fetchable in <1 second.

### Object display labels (`0x5038`)

`0x5038` is a cursor-based enumerate that pairs every panel object with its UI display label and the state-set cursor for any associated multistate value. It is what populates Desigo's tree view with human-readable names.

#### Request — first call

```
50 38
01 00 04 "SYST"
01 3F FF FF FF
00 00
01 00 01 2A                     cursor: "*" wildcard, first call
00 00 01 00 01 2A 00 00         padding
01 00 LL <prev-name>            on continuation, the previous response's programmatic name
[zero-pad to 222 bytes total]
```

#### Response

```
[routing header]
01
00 00
01 00 LL <programmatic-name>    e.g. "AC1.SF.STS"
01 00 LL <display-label>        e.g. "AC-1 Supply Fan Status"
[state-set cursor u16 BE]       e.g. 0xFC13 → look up via 0x040A to get the state names
```

Continuation: pass the programmatic name back as the cursor on the next call. The PXC walks alphabetically through every named object in the panel.

**Why this matters for scanners.** A bare `0x0981` walk gives you point names but not labels. To produce a Desigo-quality readout, walk `0x5038` once at session start, build a `name → label` dict, and decorate `0x0981` results with the labels at display time.

Termination: the PXC returns `0x0003` (object not found) when asked to continue past the last object.

### PPCL editor opcodes (`0x4100` / `0x4103` / `0x4104` / `0x4106`)

Desigo CC's PPCL line editor uses a small command family for individual line operations. `0x4106` (ClearTracebits) was already documented; the others surfaced in the PPCL-edit capture.

| Opcode | Operation | Body | Effect |
|--------|-----------|------|--------|
| `0x4100` | LineWrite/Create | `[01 00 LL <program>] 00 00 00 [01 00 LL <line-content>] 00 0A` | Inserts or overwrites a PPCL line at line number 10 (the `00 0A` trailer). The line content TLV is the literal source line, e.g. `"00010 C"` for a comment or `"00010 IF X > 5 THEN"` for a statement |
| `0x4103` | ProgramEnableHint | `[01 00 LL <program>] 00 01 7F FF` | Same trailer shape as `0x4106` ClearTracebits. Hypothesized as Enable/Disable for the program (mode + scope) |
| `0x4104` | LineRead/Delete | `[01 00 LL <program>] 00 0A 00 0A` | Two u16s: line number (target) + length-or-mode. Captured during a line-deletion operation |
| `0x4106` | ClearTracebits | `[01 00 LL <program>] 00 01 7F FF` | Already documented above |

**The `00 01 7F FF` trailer** is shared between `0x4103` and `0x4106` and may be a generic "program-runtime command" framing rather than ClearTracebits-specific. The differing opcode bytes select the runtime action.

**Operational signature.** A Desigo operator editing a PPCL line emits this sequence on the wire:

1. `0x0985` — read existing program source
2. `0x4104` — read or stage the target line
3. `0x4100` — write the new line content
4. `0x4106` — clear tracebits to force re-execution
5. `0x0985` — re-read program source to verify

Auditing PPCL changes therefore requires tracking the `0x4100` opcode specifically — that is the one that actually mutates the panel program text.



| Opcode | Operation | Notes |
|--------|-----------|-------|
| `0x4640` | IdentifyBlock | Mid-session identity refresh. Client sends its own IdentifyBlock; PXC responds with its own. Same TLV structure as inside CONNECT |
| `0x4634` | PushRoutingTable | Client pushes its known BLN routing table to the PXC. Body is a list of `{TLV name, u32 BE cost}` tuples. Response is ACK-only. Useful footprint: reveals the full list of panel names the scanner thinks exist on the BLN |
| `0x010C` | GetSystemInfo | Request is literally 2 bytes (`01 0C`). Response is ~269 bytes containing: panel model TLV (e.g. `"PME1252 "`, `"PME1300 "`), firmware string (e.g. `"PXME V2.8.10 APOGEE"`), build date (e.g. `"Oct 28 2013 12:31:01"`), then binary state/capability bytes. The byte at offset ~0x68 encodes the panel node number |
| `0x0100` | GetRevString | Named in original doc; probably the older-firmware equivalent of 0x010C |

### Bulk property operations

| Opcode | Operation | Notes |
|--------|-----------|-------|
| `0x4200` | BulkRead | Short form |
| `0x4220`, `0x4221`, `0x4222` | BulkReadExtended | Fixed-size 222-byte preallocated request with ~180 bytes of trailing zero padding. Takes a device name and a wildcard or specific point. Response carries a full value block plus config metadata |

### PPCL runtime control

| Opcode | Operation | Notes |
|--------|-----------|-------|
| `0x4106` | ClearTracebits | Clears PPCL tracebits on a named program and triggers re-execution. Observed on the wire when the operator clicks "Clear Tracebits" / "Refresh" in Desigo CC's PPCL editor. **Modifies panel runtime state** — not a read. |

**0x4106 wire format** (captured during a Desigo "Clear Tracebits" click on a named PPCL program):

```
41 06                          opcode
00 00                          2-byte header
01 00 LL <program_name>        program name TLV
00 01                          u16 BE — hypothesized as mode (0x0001 = clear)
7F FF                          u16 BE — hypothesized as scope bitmap (all bits)
```

Response: empty success ACK (routing header only, direction byte `0x01`). The trailer bytes `00 01 7F FF` haven't been varied across captures, so the mode/scope interpretation is a guess — other Desigo operations using the same opcode may send different values.

**Observed operational sequence.** When the operator clicks the button, Desigo performs a read-verify-modify-verify pattern rather than firing the command blind:

1. **Read** — enumerate the program source via ~10 `0x0985` calls.
2. **Check** — read an associated status point via one `0x0220`.
3. **Modify** — send the single `0x4106` command with the program name.
4. **Verify** — re-enumerate the program source via ~10 more `0x0985` calls.

A passive listener on the BLN watching for `0x4106` opcodes is a reliable way to detect PPCL trace/refresh operations, which in turn can flag who's actively engineering on the system.

### Error / not-supported

| Opcode range | Typical response |
|--------------|------------------|
| `0x09A3`, `0x09A7`, `0x09AB`, `0x09BB` | Most return `05 00 03` (not found) or `05 00 AC` (not supported) — these appear to be extended enumerate variants that some firmware revs don't implement |
| `0x400F`, `0x4010`, `0x4011`, `0x4133` | All return `05 00 AC` — client-side capability probes that this firmware rejects |
| `0x5354` | Returns `05 00 03` — unknown purpose |

Codes `0x0050`, `0x0291`, `0x0294`, `0x02A8`, `0x0606` also appear with low counts; shapes look like read variants but not deeply mapped.

---

### Rare opcodes observed in supervisor traffic

The captures consistently show Desigo CC emitting a wider opcode set than panels accept. These opcodes appear in real Desigo sessions but rarely (one to a few times each), and panels respond with `0x00AC` "not supported" or with shaped responses that have not been fully decoded. Opcodes that *have* been fully decoded (`0x040A`, `0x5038`, `0x098C`–`0x098F`, schedule writes, PPCL editor) are documented in their own sections above.

| Opcode | Direction | Frames seen | Body shape | Notes |
|--------|-----------|-------------|------------|-------|
| `0x0050` | 5033 | 4 | `00 50 01 00 04 "SYST" 23 3F FF FF FF` | Tiny (12-byte body). Status / flag query under SYST scope. **Returns the registered supervisor name list (`OCCDCC-SVR`) without authentication** — useful for cold discovery |
| `0x0241` | 5033 | 14 | SYST + device + point | Point existence probe — returns echo of `(device, point)` on success. Shape is similar to `0x0220` but no value extracted |
| `0x0244` | 5033 | 2 | SYST-scoped query | Returns `0x0002` (object_unknown) on out-of-scope objects; scope-restricted variant of `0x0240` |
| `0x0245` | 5033 | 2 | 3-byte body | Test probe; always errors. Not a real op — appears only in `enumeratetest1.pcapng` |
| `0x0263` | 5033 | 4 | Object lifecycle / delete-related | Pairs with `0x0260` |
| `0x0203`, `0x0204`, `0x0260` | 5033 | 2–4 each | `XX XX [02–04] 00 02 00 00 [LP name] 01 00 00 00 01 [LP name] 01 00 00 01 00 00 3F FF FF FF` | **Object lifecycle family.** Probes seen carrying client-test names (`test1`, `test2`, `test4`, `test434`). The trailing `3F FF FF FF` is the same property-state sentinel used in `0x0050`. `0x0204` is doc-named CreateObject (returns `0x0E11 already_exists` if the name is taken). `0x0203` and `0x0260` likely sibling create/probe variants — only seen with client-debug names in the corpus, so semantics aren't pinned down beyond "object-lifecycle 02xx family" |
| `0x0291`, `0x0294`, `0x02A8` | 5033 | 2–8 each | SYST + device + point + value-like trailing bytes; some carry an inline byte `0xC8` followed by a type code and 4-byte float | Read/write variants in the 02xx family. `0x0291` and `0x02A8` carry value bytes (writes); `0x0294` carries no value (read). Separator after SYST is `0x23` for the value-carrying ones, `0x00` for the read-only one. **Two body shapes for 0x0294**: small (53-byte) form uses separator `0x00`; large (222-byte) preallocated form uses separator `0x01` |
| `0x0368` | 5033 | 1 | `03 68 04 01 00 00 01 00 05 <node-name> 00 01 00 1F` | Node-routing query. Carries a node name and what looks like a 16-bit flag/mask field |
| `0x0606`, `0x5354` | 5033 | 6 / 6 | `XX YY 01 00 04 "SYST" 23 3F FF FF FF` | Same shape as `0x0050`. `0x0606` returns empty body (heartbeat-like ping); `0x5354` always errors `0x0003` |
| `0x4220` | 5033 | 1 | SYST + point + property descriptor bytes | Bulk variant adjacent to `0x4221` and `0x4222`. Single sample; appears to read or modify property metadata rather than the value itself |
| `0x4500` | 5033 | 5 | 4-byte body | Test probe; always errors. Not a real op — appears only in `enumeratetest{1,2,3}.pcapng` |
| `0x400F`, `0x4010`, `0x4011`, `0x4133` | 5033 | 1–6 each | Constant 12–17 byte bodies with `00 13` or `00 10` prefixes | Newer-firmware ops. Panel responds with `0x00AC` not_supported |
| `0x09A3`, `0x09A7`, `0x09AB`, `0x09BB`, `0x09C3`, `0x098B` | 5033 | 1–6 each | Cursor-pagination shape | All return `0x00AC` not_supported on legacy firmware. Newer-firmware features |
| `0x0961`, `0x0964`–`0x0976`, `0x0979` | 5033 (Mode C) | 4–29 each | See *Schedule operations (09xx family)* | Schedule operation family — fully documented above |
| `0x098C`–`0x098F` | 5033 (Mode C) | 16 each | See *Schedule operations (09xx family)* | Schedule sub-property family — fully documented above |
| `0x040A` | 5033 | 2 | See *Multi-state label catalog* | State-set fetch — fully documented above |
| `0x5038` | 5033 | 3 | See *Object display labels* | Display-label enumerate — fully documented above |
| `0x5020`, `0x5022` | 5033 | 2 each | See *Schedule property writes* | Schedule write pair — fully documented above |
| `0x4100`, `0x4103`, `0x4104` | 5033 | 1–2 each | See *PPCL editor opcodes* | PPCL line edit family — fully documented above |
| `0x099F` | 5033 | 36 | `09 9F 00 04 XX` (5-byte body — confirmed by capture) | GetPortConfig — see *Point enumeration (09xx family)*. Response carries dot-separated config: `;bd=<baud>;pa=<parity>;mk=<mask>` then `;mid=<BLN-id>;ety=<encoding-type>;pdl=<pad>` then port label. Index `0xFF` = USB Modem port, `0x00` = HMI port, `0x04` = undefined |
| `0x5003` | 5033 | 39 | `[01 00 04 "SYST"][01 00 LL <object>]` | Schedule object info query. Returns object name (twice) plus state-set ref `fc 13`. Used as a probe before deeper schedule reads |

These are documented for forensic completeness — a passive listener will see them appear, and parsing should not fail on them.

---

## Response status codes

As noted above, the first byte of an S2C payload is the status code:

- `0x01` — success
- `0x05` — error, followed immediately after the routing header by a 16-bit error code

Observed error codes:

| Error code | Occurrences | Typical triggering opcode |
|------------|-------------|---------------------------|
| `0x0003` | ~1369 | Object not found / point doesn't exist |
| `0x00AC` | ~42 | Operation not supported / unknown opcode on this firmware |
| `0x0E15` | ~7 | **Wrong write opcode for this property type.** Always seen as the panel's response to `0x0240` WriteWithQuality issued against a `SYST`-tagged property. Desigo CC handles it by retrying with `0x4222` BulkPropertyWrite — the retry succeeds. See "Property writes" below |
| `0x0002` | ~2 | Object unknown — returned by scope-restricted ops (e.g. `0x0244`) when the target is out of the requesting scope |
| `0x0E11` | ~2 | Object already exists — returned by `0x0204` (CreateObject) when the named object is already present. Desigo handles by treating as success |

The `0x05` / `0x0003` pair is the dominant error in the pcap — it fires on ~46% of `0x0220` reads, consistent with scanners probing for BLN-sourced virtual points that don't exist on the target panel. A naive parser that doesn't check the status byte will attempt to parse an error response's `00 03` prefix as the start of a point value block and hallucinate a value; the first-byte check is cheap and mandatory.

---

## Reading a point

Both `0x0220` and `0x0271` address points **by string name**, not by numeric ID. The wire request contains the device name and the point name as adjacent TLV strings:

```
[opcode][sub-opcode bytes][device TLV][point TLV]
```

Example — reading `TEC1/APPLICATION` via 0x0271:
```
02 71 00 00 01 00 04 "TEC1" 01 00 0B "APPLICATION" 00 FF
```

The subpoint slot number (1–99 shown in Desigo CC's UI) is **not transmitted on the wire.** Clients resolve slot → name via the vendor's point-definition metadata and send the name.

The two-byte trailer at the end of the request appears to select which property is being read:
- `00 FF` — typical for 0x0271 (wildcard property / default)
- `00 00` — seen on 0x0273 (different semantic — see below)

### Reading a BLN virtual point (system-wide point)

When the point being read is a BLN-sourced virtual (a system-wide point that doesn't live on any specific TEC device — alarm conditions, panel-internal globals, schedules), the request format changes:

- For **`0x0271`** (legacy): the **device-name TLV is empty** (length 0). Only the point-name TLV is populated. Wire shape: `02 71 00 00 01 00 0D "<POINT.NAME>" 01 00 00 00 FF` — note the `01 00 00` after the point name where a typical TEC read would have a second TLV.
- For **`0x0220`** (modern): the device-name slot carries the literal string **`"SYST"`** as a tag. Wire shape: `02 20 01 00 04 "SYST" 00 3F FF FF FF 00 00 01 00 0D "<POINT.NAME>" 01 00 00 00 00 01 00 00 01 00 00`. The supervisor uses `SYST` to declare "this is a system-level point" rather than emitting an empty device TLV.

These two variants address the same underlying virtual point — Desigo emits both during the same operator action when probing a panel of unknown firmware vintage. The panel responds with the value block in the standard format; only the request shape differs.

### The four read-ish opcodes are NOT four flavors of the same read

A Desigo CC session to a single panel typically uses all four of `0x0220`, `0x0271`, `0x0273`, `0x0274` mixed together:

- **`0x0271`** — canonical read; returns full value block
- **`0x0220`** — compact read, preferred for high-volume polling; errors with `0x05 00 03` if point doesn't exist
- **`0x0273`** — same wire shape as `0x0271` but ACK-only response. Semantics unclear from the pcap; plausibly a write-permission probe, cache invalidation, or parameter reset
- **`0x0274`** — **a bidirectional value-push opcode** whose semantic depends on which port it crossed:
  - **On TCP 5033 (supervisor → PXC)**: supervisor pushes a value for a BLN-sourced virtual point into the PXC's local model. Common for points like `OAT.MIRROR.BN` (outdoor-air temp mirror from a weather-station panel) that the PXC needs but doesn't own.
  - **On TCP 5034 (PXC → supervisor)**: PXC reports a changed value for one of its own TEC-device points. This is **the genuine unsolicited COV notification** that was previously hypothesized but not captured. One message per point-change event, carrying device TLV + point TLV + f32 value + padding.

The wire formats differ slightly between directions — both start with `02 74 00 01 00 00` but the PXC→supervisor variant carries a `{device TLV}{point TLV}{f32}` triple while the supervisor→PXC variant carries a shorter `{point TLV}{01 00 00}{f32}` inner block. The opcode number is the same; consumers need to branch on the listening port (or equivalent: direction of the TCP connection) to parse correctly.

---

## Response parsing — point reads (0x0220, 0x0271)

This section covers the response format for direct point reads — `0x0220` and `0x0271`. For `0x0981` enumerate-walk responses (which share some structure but have distinct layouts), see the 09xx section earlier.

Successful point-read responses carry a trailing value block with this reliable structural signature:

```
[last byte of point name] [01 00 00] [7-byte metadata] [IEEE-754 float]
                                                       ^ offset +10
```

The float always sits at offset +10 from the `01 00 00` marker.

### Observed point-read response variants

Labeled R1–R4 to keep them distinct from the SHAPE A/SHAPE B names used for `0x0981` enumerate responses.

| Variant | Opcode | 7 metadata bytes | Condition |
|---------|--------|------------------|-----------|
| R1 | `0x0271` | `3F FF FF FF 00 00 00` | Quality flags unset |
| R2 | `0x0271` | `00 00 00 00 00 00 00` | Quality flags explicit, all clear |
| R3 | `0x0220` | `00 00 00 00 00 00 XX` | XX = data-type code (see "Data-type codes" sub-section) |
| R4 | any | (R2/R3 pattern but float starts `0xBF`) | Negative values |

### Scan-loop bounds for the value block

A scanner implementing the marker-based scan must bound the loop so the float at offset `+10` is fully addressable. The correct bound is `i + 13 < len(payload)` — the marker occupies 3 bytes (`01 00 00`), then 7 metadata bytes, then 4 float bytes, total 14 bytes from `i` through `i+13`. **Off-by-one trap**: writing `range(1, len(payload) - 14)` (one too small) silently misses the case where the float sits at the very end of the payload with no trailing data — symptom is digital points without a units TLV failing to parse for no obvious reason. The reference scanner had this exact bug; the patched form uses `range(1, len(payload) - 13)`.

### Data-type codes (the `XX` byte in R3 / SHAPE B metadata)

Empirical distribution from 5 large captures (~575 R3 responses across mixed point types):

| Code | Count | Inferred role | Value distribution observed |
|------|-------|---------------|------------------------------|
| `0x00` | 215 | Digital / binary / enum | Mostly 0.0 / 1.0; integer values −1 to 2200 also seen |
| `0x01` | 3 | Rare — semantics not pinned | Too few samples to characterize |
| `0x02` | 125 | Small integer (likely `int16`) | Integer values 72–74 in setpoint contexts |
| `0x03` | 204 | Analog (the dominant type) | Floats 0.01 to ~2500, integer-valued majority |
| `0x06` | 28 | "Analog32" / extended numeric | Mixed; needs more samples to characterize |

`0x04` and `0x05` are listed in the SHAPE B detection heuristic but **not observed in any of the captures analyzed**. Either they're rare types not yet exercised by the captures (string? blob?), or the heuristic's allowable-set was over-broad. Either way, treat them as theoretical until a capture surfaces them.

### The false-positive trap

A naive parser that scans for `[01 00 00]` byte patterns will false-positive on the response's **trailing configuration block** — the PXC appends min/max/resolution metadata with a near-identical structure. The reliable disambiguator:

> The byte *immediately before* the real value block's `01 00 00` marker must be a printable ASCII character (the last byte of a TLV point-name string).

The trailing config block's preceding byte is part of the float value itself (non-ASCII bytes).

Accepted preceding bytes: A–Z, a–z, 0–9, space, period, underscore, hyphen. This rule correctly parses 274/309 captured responses with zero false values. The remaining 35 unparsed responses are all legitimate non-value traffic (enumeration responses, heartbeats, bulk device-summary reads).

---

## Comm status (the stale-cache trick)

This is the single most operationally important detail in the protocol.

**PXCs cache the most recent value read from each TEC device.** When a TEC goes offline (unplugged, comm-faulted, power lost), the PXC continues returning the last cached value to read requests — indefinitely — instead of erroring.

Without accounting for this, a scanner will confidently report "72°F" for a VAV controller that's been dead for two weeks.

The live-vs-stale indicator is the **second byte of the metadata block** after the `01 00 00` marker:

| Value | Meaning |
|-------|---------|
| `0x00` | Device is online, value is live |
| `0x01` | Device is comm-faulted, value is stale cached data |

The **third byte** is an error code; `0x06` is the typical comm-error code. Other codes surface for different failure modes.

Desigo CC's UI displays comm-faulted points with a `#COM` flag. This scanner does the same thing.

**Note:** this `0x01` in the *value block metadata* is a TEC-level comm-fault flag for the underlying device. It is distinct from the `0x05` *response-level* status byte described earlier, which indicates a PXC-level operation failure (point doesn't exist, opcode unsupported). Both can appear in the same parser workflow — one for device health, the other for operation outcome.

### Observed stale-sensor signature: `-62.5°F`

A second, separate signal of sensor trouble is a repeated `-62.5°F` (or adjacent values like `-63.5`) across multiple unrelated points on the same device. This has been observed where one AHU's mixed-air / return-air / supply-air temperatures and all its zone temperatures reported `-62.5 DEG F` while adjacent AHUs on the same panel reported plausible values.

This isn't a protocol signal per se — the PXC returns these values with `comm_status=0x00` (healthy), so the comm-fault byte won't catch it. The pattern is that the underlying sensor or wiring is broken, but the PXC's input side is still reading valid analog-to-digital conversions of whatever is on the wire (typically open-circuit rail or a shorted input). Worth flagging in scanner output when many points on one device report the same implausible temperature — it indicates a hardware issue downstream of the PXC.

---

## Property state sentinel (partially unresolved)

The `3F FF FF FF` vs `00 00 00 00` pattern appearing in variants R1 vs R2 almost certainly corresponds to a quality-flag register — analogous to OPC's uncertain/good/bad triad, or IEC 61131's quality bits.

**Hypothesized meaning:** `3FFFFFFF` = "no specific quality flags set"; `00000000` = "explicit quality flags, all cleared."

**Empirical testing does not confirm a clear user-facing distinction.** A write-test against a point repeatedly returned either sentinel unpredictably, and the value was live in both cases. The parser surfaces the raw bytes as `property_state_hex` for users to spot patterns, but doesn't assign meaning.

**Cross-opcode observation:** the same `3F FF FF FF` sentinel appears inside `0x0220` read requests (as a middle field of the compact request format) AND inside `0x4221` bulk-read requests (at a fixed offset). This suggests it's a generic "no filter / wildcard property" sentinel used across multiple opcodes, not a quality-flag register at all — it may just be "match any property state." This reframes the mystery but doesn't solve it.

If you figure this one out, vendor FCD documentation would probably clarify it — the relevant constants almost certainly live in the client-side binaries but the code paths that consume them aren't fully mapped.

---

## Device addressing

A TEC device (VAV, unit controller, fume hood, etc.) sits on a PXC's FLN (Floor Level Network) bus. Each device has:

- **Name** — a short ASCII string, unique on the FLN (e.g. `TEC1`, `VAV01`, `PUMP1`)
- **Application number** — identifies which Siemens TEC library app the device runs (e.g. `2023` = VAV cooling/reheat, `2500` = VAV cooling-only, `6525` = fume hood)
- **Description** — optional free-form text from commissioning (e.g. `"CONFERENCE RM A"`, `"ROOM 412"`)

The application number determines which subpoint slots (1–99) are defined and which point names they map to. A slot number is only meaningful in the context of an app:

- App 2023 slot 5 = `HEAT.COOL`
- App 2500 slot 5 = *(undefined — not used by this app)*

Slot ranges aren't fully packed — apps typically use 50-90 of the 99 available slots, with gaps for slot numbers Siemens reserved but didn't wire up for that particular application.

**Fully-qualified point address:** `NODE / DEVICE / POINT`
- NODE = PXC controller name (e.g. `node1`, `NODE1`)
- DEVICE = TEC name on the FLN (e.g. `TEC1`)
- POINT = subpoint name (e.g. `ROOM TEMP`)

This is also the hierarchy Desigo CC and Insight use in their tree views.

**Point-name suffix conventions (observed):**
- `.BN` — BLN-sourced virtual point. The value doesn't originate on this panel; it's pushed in from elsewhere on the BLN (typically by the DCC server via `0x0274` writes). Example: `OAT.MIRROR.BN` = mirror of outdoor air temp from another panel.
- `.BAC` — BACnet-bridged point. This panel exposes the point via BACnet or received it from BACnet.
- `.DP`, `.ENB`, `.OCC`, `.NGT` — internal PPCL variables, typically booleans or small enums.
- `.SPM`, `.CSTM` — set-point / custom programmed values.

These are conventions, not syntax rules. The PXC doesn't validate them.

---

## BLN routing table (0x4634)

The `0x4634` opcode is how a scanner tells the PXC what panels it knows about. The request body is a fixed header followed by a list of entries; each entry is a TLV name followed by a u32 BE cost/metric value.

Example body shape (synthetic illustrative values):

```
46 34 00 00 00 00 0C 07 00 0E          header
01 00 0D "$paneldefault" 00 00 00 0C    default entry, cost=12
01 00 06 "<SITE>" 00 00 05 BB           site code entry
01 00 05 "NODE1" 00 00 0A 90            NODE1, cost=2704
01 00 05 "NODE2" 00 00 0A 72            NODE2
01 00 05 "NODE3" 00 00 09 DB            NODE3
... (one entry per known peer) ...
01 00 0A "DCC-SVR" 00 00 09 AD           supervisor
01 00 0F "DCC-SVR|5034" 00 00 0A E5      supervisor 5034 listener
00 00 00 00                              terminator
```

The costs cluster around the low thousands for PXCs and jump higher for non-PXC supervisory nodes. The actual cost function isn't pinned down, but across 155 routing-table observations from multiple source panels, a clear pattern emerges:

**Cost is a per-observer metric, not a global topology constant.** The same peer is reported with different costs depending on which panel is publishing the routing table:

| Peer | as seen by DCC | as seen by panel A | as seen by panel B |
|------|----------------|-------------------|-------------------|
| `NODE1` | ~2700 | ~3150 | ~3150 |
| `NODE2` | ~2660 | ~3120 | ~3120 |
| `NODE3` | ~2670 | ~3080 | ~3190 |

The DCC server consistently reports lower costs than peer panels do for the same targets. Panels at similar network positions tend to report identical costs for most peers. This is consistent with a latency- or quality-based metric measured from the observer's own vantage, not a static link-cost. Plausibly an EWMA of round-trip time or an integer ping-count-style sample.

Three special entries appear in every routing table:
- `$paneldefault` (cost always 12) — Siemens internal fallback / default-route placeholder. Safe to ignore for topology discovery.
- `101000` (cost always 1467) — numeric-named entry. Possibly a legacy MSTP/BACnet gateway registration or a site-code identifier.
- `SITE-BMS` (cost ~5400) — the BAS's registered name on the BLN. The same entry can appear with case variants (`site-bms`) in the same routing table, presumably from separate registrations.

**For a scanner, this is reconnaissance gold:** passively observing `0x4634` from a real supervisor reveals the complete BLN topology in one message. A single clean routing-table capture enumerates every panel name and every peer cost in one round trip — no brute-force node attack required.

---

## System info (0x010C)

The smallest request in the protocol. Body is literally two bytes:

```
01 0C
```

Response (269 bytes typical) decodes as:

```
TLV: panel model          "PME1252 " or "PME1300 " (trailing space preserved)
TLV: firmware             "PXME V2.8.10 APOGEE" / "PXME V2.8.18 APOGEE"
TLV: build date           "Oct 28 2013 12:31:01" / "Sep 26 2019 12:41:20"
16 bytes: feature bytes   (bit layout unmapped; byte ~0x68 encodes node number)
IdentifyBlock             standard TLV identity (node + site + BLN + flags)
~80 bytes: panel state    (bit fields — panel health, point counts, etc.)
20+ bytes: timing fields  (two 6-byte structures; may be schedule or trend metadata)
3-byte trailer            "00 03 00"
```

In the reference pcap, different PXCs reported different firmware / panel models on the same BLN:

- Legacy-dialect panels: PME1252, V2.8.10, Oct 2013 build
- Modern-dialect panel: PME1300, V2.8.18, Sep 2019 build

This is normal in a retrofit environment. The response format is stable across model/firmware differences.

**Dialect note:** `0x010C` can be carried inside either a type `0x33` DATA or a type `0x34` HEARTBEAT frame depending on the PXC's firmware dialect. See "Firmware dialects" above — PME1252 panels reply on 0x33, PME1300 panels reply on 0x34. The opcode itself and response format are identical across both.

---

## FLN enumeration

See the consolidated **Point enumeration (09xx family)** section above for wire formats. In brief:

- `0x0986` enumerates TEC devices on the FLN bus. Simple, works on every firmware. Response entries contain device name, description, application number (often `0` — read APPLICATION point separately to fill in), and status flags.
- `0x0981` is more complete — walks every point on the panel including panel-internal PPCL variables and schedule points. The scanner in this repository uses it as the primary enumeration path.
- `0x0985` walks PPCL programs and returns their source text. Not really "enumeration" in the device-listing sense, but it shares the 09xx family's cursor-pagination model.

Some older PXC firmware revisions don't implement `0x0986` cleanly and return partial or empty responses. The fallback is brute-force probing against a dictionary of common device-name patterns (`TEC1`, `TEC2`, ..., `VAV001`, `VAV002`, ...) — slow but works. The reference live panel (PME1252 V2.8.10) handles `0x0986` correctly.

For a scanner, the practical hierarchy is: try `0x0981` first (most complete), fall back to `0x0986` for FLN-specific walks, use `0x0985` separately when PPCL dump is needed.

---

## Type 0x34 carrying operational opcodes

Type `0x34` frames are not pure keepalives. They carry real opcodes — the same opcodes that appear in `0x33` DATA frames — because they are how modern-dialect panels (PME1300) send all operational traffic. See "Firmware dialects" above for the full explanation. Observed distribution in the reference capture:

- On the modern-dialect panel in the capture, 100% of operational C2S traffic was 0x34: point reads, identity refreshes, COV pushes, everything
- On legacy-dialect panels, 100% of operational traffic was 0x33 and 0x34 appeared only as the outer wrapper for CONNECT/ANNOUNCE framing

The earlier hypothesis — that 0x34 was a fire-and-forget priority channel for idempotent operations — was wrong. The pattern that generated that hypothesis (0x34 never returning errors) is just a side-effect of: modern panels use 0x34 for all ops, and the specific modern panel in the capture happened to be busy enough that none of its reads failed during the capture window.

**Practical implication for a scanner:** dialect is picked by the PXC, not by the scanner's choice of operation. Use `_probe_dialect()` to learn which one a given panel wants, then lock that in for the rest of the session.

---

## The PXC→supervisor push channel (TCP 5034)

This is the other half of the P2 protocol. Every PXC opens an outbound TCP connection to the supervisor's 5034 and uses it for three kinds of asynchronous notifications. The supervisor only ever replies with 39-byte routing-header-only ACKs on this port — all real data flows upstream from the panels.

Observed traffic mix in a 10-minute reference capture across six panels:

| Opcode | Purpose | Count | Typical size |
|--------|---------|-------|--------------|
| `0x0240` | WriteWithQuality — BLN-sourced virtual-point value report | 547 | ~84 B |
| `0x0274` | COV notification — device-point value change | 484 | ~82 B |
| `0x4634` | BLN routing-table announcement | 20 | ~256 B |

### 0x0240 WriteWithQuality wire format

Sent when a panel computes a new value for a BLN-sourced virtual (a `.BN`-suffixed point or similar globally-published point). The device field is always the literal string `"NONE"` — meaning "no TEC device, this lives at the panel level."

```
[routing header: BLN / dest=supervisor / BLN / src=panel]
02 40                         opcode
01 00 04 "NONE"               device TLV (always "NONE" for panel-global)
00                            separator
3F FF FF FF                   wildcard / quality-default sentinel
00 00                         reserved
01 00 0A "AHU.OAT.BN"         point name TLV
01 00 00                      empty TLV (start of value block)
00 00                         2 bytes
01 00 00                      empty TLV
01 00 00                      empty TLV
42 6C 40 4C                   f32 BE value (59.0625 °F)
00                            trailer
```

### 0x0274 COV notification wire format (PXC→supervisor direction)

Sent when a device-point value changes enough to cross the COV threshold. The format is slightly different from the supervisor→PXC 0x0274 — both strings are carried as adjacent TLVs, and the value block is simpler:

```
[routing header: BLN / dest=supervisor / BLN / src=panel]
02 74 00 01 00 00             opcode + header
01 00 0A "WBLMVAVB12"         device TLV
01 00 09 "ROOM TEMP"          point TLV
42 90 00 00                   f32 BE value (72.0 °F)
00 00 00 00 00 00 00 00 00 00 00 00 00   trailer padding
```

### 0x4634 routing-table announcement (PXC→supervisor direction)

Same format as the DCC→PXC 0x4634 documented above, but initiated by the panel. The panel enumerates every BLN peer it knows about, with a 4-byte cost metric per entry. The supervisor can cross-check these against its own topology to spot out-of-sync panels.

### No explicit subscribe mechanism observed

The reference capture shows PXCs pushing on 5034 continuously throughout, with no visible subscribe/unsubscribe exchange preceding the pushes. Three possibilities:

1. PXCs push to any known supervisor peer unconditionally (topology from 0x4634 alone).
2. The subscription was established at panel boot, before the capture started.
3. The subscription is implicit from the TCP connection being open — as long as the panel's outbound connection to supervisor:5034 is alive, it pushes.

To distinguish, you'd need a capture that includes a panel first coming online (after a PXC reboot) or a fresh DCC server startup. That moment would expose any initial subscribe handshake if one exists.

---

## 0x0274 — directional semantics summary

Because this one opcode is the most commonly misunderstood, here's the summary:

| Direction | Port | Meaning |
|-----------|------|---------|
| Supervisor → PXC | 5033 | **Push-write** of a BLN-sourced virtual into the panel's local model (e.g. mirroring an OAT reading from another panel) |
| PXC → Supervisor | 5034 | **Genuine unsolicited COV notification** — the panel reporting that one of its device points changed value |

Both directions carry the same opcode byte. The wire formats differ in small ways (documented in the 5034 push channel section above). Consumers need to branch on the listening port to parse correctly.

The first revision of this doc only had 5033-side captures and concluded `0x0274` was "a write, not a notification." That was wrong — it's both, direction-dependent. The doc has since been verified against a DCC-server-side capture containing 484 PXC→supervisor `0x0274` notifications alongside the 155 supervisor→PXC push-writes.

---

## Alarm reporting (0x0508 / 0x0509)

Alarm flow uses a dedicated opcode pair distinct from the value-update opcodes. The pair was first observed in a Desigo CC supervisor-side capture covering an operator-driven alarm acknowledgement of two simultaneously-active alarms.

### High-level behavior

1. Panel detects an alarm condition internally and pushes a `0x0508` AlarmReport to the supervisor's 5034 listener.
2. Operator sees the alarm in the Desigo CC alarm queue and clicks "Acknowledge."
3. Supervisor (over its 5033 outbound connection to the panel) issues a small flurry:
   - `0x0271` legacy read of the alarmed point (probe current state).
   - `0x0220` modern read of the same point with the `SYST` virtual-point tag (probe under modern dialect).
   - `0x0273` WriteNoValue against the same point — a few seconds later, after the operator clicks Ack.
   - `0x0509` AlarmAck — the formal acknowledgement.
4. Panel responds with a fresh `0x0508` AlarmReport — sent on **both** the active 5033 connection AND the 5034 push channel, same payload, within a few milliseconds. The duplication appears to be a deliberate redundancy mechanism so an alarm transition isn't lost if one channel is wedged.
5. Supervisor follows up with another `0x0220` read to confirm post-ack state.

The whole round-trip from operator-click to confirmed-ack is observed completing in roughly 3 seconds.

### 0x0508 AlarmReport wire format

Sent by a panel to the supervisor. Payloads observed range from ~127 to ~195 bytes depending on the alarm record's optional fields. Skeleton (after the routing header):

```
05 08                            opcode
01 00 02 "CC"                    LP-string: alarm-class identifier (always "CC" in current samples;
                                 may take other values on different sites or alarm classes)
23                               separator byte (literal '#')
3F FF FF FF                      property-state sentinel (4 bytes)
01 00 02 00 00                   2-byte LP-string of two NULs (padding/reserved)
01 00 LL <point-name>            LP-string: alarmed point name (BLN-virtual style; no
                                 enclosing device)
01 00 00 00 01                   5 bytes of flags / type bits
01 00 LL <point-name>            same point name repeated (full-path form?)
01 00 00 01                      4 bytes of flags
00 LL <description>              long-form description, u8-length prefix (e.g. 16 chars
                                 of human text)
00 00 00 00 ... 06               zeros + status byte
01 01 00 02 00 00 00 00          fixed-pattern bytes
[4-char ASCII marker]            optional internal alarm-instance marker — 4 ASCII bytes
                                 between two 4-byte zero pads. Present in some samples,
                                 absent in others; meaning unknown
00 00 00 00                      zeros
[BACnet datetime 8B]             timestamp #1 — appears to be alarm raise time
[float 4B BE]                    alarm-active value (e.g. 1.0 = active)
[float 4B BE]                    secondary value (raw reading? threshold?)
00 00 00 00                      zeros
[BACnet datetime 8B]             timestamp #2 — repeat of raise time in observed samples
04
[BACnet datetime 8B]             timestamp #3 — current report time (clock at
                                 send-time on the panel)
[BACnet datetime 8B]             timestamp #4 — last-transition time
[BACnet datetime 8B]             timestamp #5 — repeats #3 in observed samples
00 00 00 00 00 00 00 00 00 01 01 00 00 00 1E
00 00 01 00
FF FF FF FF FF FF                priority/state mask (?)
01 00 FF FF
01 00 00 00 00 00 00             trailer
```

The structure is partially regular but not all fields are present in every sample — small alarms (~127 bytes) omit the secondary float and the optional 4-char marker. Treat the layout as a sequence of typed blocks (LP-strings, sentinels, BACnet datetimes, floats) rather than a fixed offset map.

### 0x0509 AlarmAck wire format

Sent by the supervisor when an operator acknowledges an alarm. Much smaller — no value, no timestamps:

```
05 09                            opcode
01 00 02 "CC"                    alarm-class identifier (matches the report)
23                               separator byte
3F FF FF FF                      sentinel
00 00                            2-byte gap
01 00 LL <point-name>            LP-string: point being acknowledged (BLN-virtual style)
01 00 00 00 00 01 00 00 01 00 00 trailer (11 bytes; exact field meanings TBD)
```

The trailer's structure is consistent across the few samples available but its individual fields aren't yet attributable. The point-name is the operative payload.

### BACnet date+time format (8 bytes)

The 0x0508 record uses a fixed 8-byte BACnet date+time encoding for every timestamp:

| byte | meaning |
|------|---------|
| 0 | year minus 1900 (e.g. `0x7E` = 126 → 2026) |
| 1 | month (1–12) |
| 2 | day of month (1–31) |
| 3 | day of week (1=Mon, 7=Sun) |
| 4 | hour (0–23) |
| 5 | minute (0–59) |
| 6 | second (0–59) |
| 7 | hundredths (0–99) |

This is the standard BACnet `DateTime` primitive. Other opcodes that carry timestamps (e.g. 0x0982 enumerate-trended, hypothesized) likely reuse the same encoding. A reasonable detection heuristic for any unknown 8-byte field: `b[0] >= 0x70` (year ≥ 2012), `1 <= b[1] <= 12`, `1 <= b[2] <= 31`, `b[3] <= 7`, `b[4] <= 23`, `b[5] <= 59`, `b[6] <= 59`, `b[7] <= 99` — all plausible only when the bytes are in fact a BACnet datetime.

### Cross-port duplication

A single alarm transition produces TWO `0x0508` frames from the panel — one on each port:

- Frame A: panel's 5033 source port → supervisor's 5033 destination port (same TCP flow the supervisor uses for reads)
- Frame B: panel's high-numbered ephemeral source port → supervisor's 5034 destination port (the panel's outbound push connection)

Same payload bytes, same alarm class, same point name. Sent within ~10 ms of each other. A consumer that processes both ports' traffic without deduplication will count every alarm transition twice. Deduplicate by `(point-name, timestamp-of-last-transition)` not by frame.

### What's still unknown about alarms

- The "CC" alarm-class identifier is constant across all observed samples. Different alarm classes (priority levels, types — fault vs limit vs system) may surface different values. The trailing `0x23` separator may also vary.
- The optional 4-char ASCII marker between zero pads in 0x0508 (present in some samples, absent in others) — meaning unknown.
- The 30-byte trailer of 0x0508 contains priority/status/escalation flags but bit-level mapping isn't pinned down.
- 0x0509 trailer's 11 bytes — likely encode "ack source" (operator vs auto), "ack timestamp," or "ack-with-comment" hooks; not yet tested with a Desigo write-comment ack.
- Whether other opcodes in the 0x05xx range exist for alarm subscribe/unsubscribe, alarm summary queries, or operator-comment writes. Only `0x0508` and `0x0509` have appeared so far.
- Whether `0x0273` is *required* before `0x0509`, or whether sending 0x0509 alone would also work. The Desigo client emits 0x0273 every time, but the panel's response to either alone hasn't been tested.

---

## Property writes — the `0x0240` / `0x4222` split

Two separate write opcodes exist, neither is universal, and Desigo CC's standard pattern is to try the wrong one first and fall back. A scanner that wants to write must understand which opcode to use against which kind of property.

### Two writes, two scopes

| Opcode | Works against | Device name in body | Response |
|--------|---------------|---------------------|----------|
| `0x0240` WriteWithQuality | Panel-global BLN-sourced virtuals (the kind whose value gets pushed in by another panel via 5034) | literal `"NONE"` | ACK on success |
| `0x4222` BulkPropertyWrite | `SYST`-tagged BLN virtuals (system-wide settable points like setpoints, schedules, modes) | omitted; point name is referenced under the `SYST` tag | ACK on success |

`0x0240` against a `SYST`-tagged property reliably returns the new error code `0x0E15`. `0x4222` against a `NONE`-style virtual hasn't been observed in any capture; the two scopes don't overlap.

### Empirical workflow — operator changes a setpoint

Sequence captured during a 50→40 numeric setpoint change. Times are seconds-relative-to-capture-start; sequence numbers are the wire `seq` field; floats are the value being written.

```
t=6.876   0x0220  DCC reads current value (SYST/<point>)         → success
t=6.934   0x0240  DCC writes float=50 with WriteWithQuality      → ERROR 0x0E15
t=6.952   0x4222  DCC retries write float=50 via BulkPropertyWrite → success
t=6.990   0x4222  DCC sends a duplicate                          → success
t=7.083   0x0220  DCC re-reads to verify                          → success, value=50

[Operator changes back to 40 ~7 seconds later — same exact pattern]
t=14.124  0x0240  float=40 → ERROR 0x0E15
t=14.142  0x4222  float=40 → success
t=14.187  0x4222  duplicate
t=14.238  0x0220  verify
```

The duplicate `0x4222` ~50ms after the first one is consistent across both transitions — it's not a retry on failure, it's how Desigo confirms the write took. A scanner that issues `0x4222` once and stops is structurally fine; the duplicate is Desigo's safety belt.

### `0x4222` BulkPropertyWrite wire format

Body skeleton (after the routing header):

```
42 22                        opcode
01 00 04 "SYST"              LP-string: SYST tag (declares system-level property)
23                           separator byte (literal '#')
3F FF FF FF                  property-state sentinel
00 00                        2-byte gap
01 00 LL <device-name>       LP-string: device name (e.g. TEC tag)
01 00 LL <point-name>        LP-string: point name (the "subpoint" within the device)
FF FF                        property-id wildcard (write to canonical writable property)
01 00 00                     empty TLV
01 00 00 00 00 00            6-byte zero pad
[type-code byte]             data-type code (0x00, 0x02, 0x03, 0x06 — same set as read responses)
[value 4 bytes BE]           f32 IEEE-754 value to write
00 00 00 00 00 00 00 00 00   trailing zeros / reserved
```

Total body length: 55 bytes for the captured setpoint writes. The `WriteWithQuality` (`0x0240`) variant against the same property is 51 bytes — 4 bytes shorter because it omits the type-code header.

### `0x4200` PropertyQuery wire format

Used by Desigo as a precondition probe before write attempts — "does this property exist on this panel, and what's its writable type?" Body:

```
42 00
01 00 04 "SYST"              SYST tag
23                           separator
3F FF FF FF                  sentinel
00 00                        gap
01 00 LL <point-name>        LP-string
00 00 01 00 00 FF FF         trailer with FFFF wildcard property-id
```

Response is shaped like a read response — value block + metadata.

### Implementation note for scanners

A scanner that wants to write must:

1. Detect property scope: is the target `NONE`-style or `SYST`-style? The cleanest signal is whether the point appears in the panel's `0x0986` FLN list (NONE-style) or only in `0x0981` virtuals (SYST-style).
2. Use `0x0240` for `NONE`-style, `0x4222` for `SYST`-style — don't try one and fall back, just dispatch correctly.
3. If you must guess (no point-list available), default to `0x4222` for any setpoint-shaped name (`*.STPT`, `*.SP`, `*.MIN`, `*.MAX`) and treat `0x0E15` as "switch to the other opcode."

---

## Cold-site discovery (the cartesian attack)

A scanner with no prior knowledge of a site can still identify a PXC by exploiting the bouncer's distinct failure signatures:

1. **Port-scan** a subnet for TCP/5033 listeners
2. **BLN attack** — try candidate BLN names (`P2NET`, site-prefix guesses, common patterns) against a known PXC IP. A TCP RST means "wrong BLN"; a silent accept means "BLN correct, scanner or node wrong." The first silent-accept gives you the BLN.
3. **Scanner attack** — with the BLN locked, try candidate scanner names. Silent drop continues until you get a heartbeat response, then the scanner name is valid.
4. **Node attack** — with BLN and scanner locked, try node names (`node1`, `node2`, ..., `NODE1`, ..., named variants). The first one that gets a valid read response is the PXC's actual node name.

This is the "cartesian attack" — up to `|BLN| × |Scanner| × |Node|` probes in the worst case, but well-ordered candidate lists usually hit within a few dozen probes.

The whole workflow fits inside `cold_discover_site()` in the scanner code with pre-built candidate dictionaries for each field.

**New shortcut:** once you have a valid session, send one `0x4634` probe or observe one from a real supervisor — it reveals the complete BLN topology (every panel name, every scanner name, plus costs). One successful `0x4634` observation is worth hundreds of brute-force node attacks.

**Earlier shortcut:** the `0x0050` status query (`00 50 01 00 04 "SYST" 23 3F FF FF FF`) returns the registered supervisor name list (e.g. `OCCDCC-SVR`) **without requiring a full identity handshake** — it works inside any successful session bouncer pass. Sending `0x0050` after the `0x33` CONNECT probe (before sending an IdentifyBlock) confirms whether the panel knows a supervisor and gives you the supervisor name to use as a "scanner attack" candidate. Cuts cold-discovery time roughly in half on sites where the supervisor is reachable.

---

## Identity-leak surfaces (cold-discovery shortcuts)

Multiple opcodes leak the panel's own canonical identity in their responses, even when the request fails. A scanner that wants to identify a panel without prior knowledge can chain these to extract every name it needs without exhaustive cartesian probing. Ranked by how cheaply they leak useful information:

### 1. Routing-header leak in **any** response (success OR error)

Every DATA-style response from a panel includes the panel's own canonical name in **slot 4 of the routing header**, regardless of whether the response carried success (`0x01`) or an error (`0x05`). Crucially, the bouncer is **case-insensitive on the destination node name in slot 2 of the request** — sending `node1` (lowercase) gets a response routed back with `NODE1` (canonical case) in slot 4. So a scanner that has guessed even an approximately-correct node name receives the canonical form for free, in the very first response.

Worked example, observed verbatim in `pcap2429.pcapng`:

```
DCC sends:  00 "OCCEBLN" "node1" "OCCEBLN" "OCCDCC-SVR" 09 61 ...
              dir   BLN    DEST     BLN       SOURCE   opcode

Panel replies:  05 "OCCEBLN" "OCCDCC-SVR" "OCCEBLN" "NODE1" 00 03
                  dir    BLN      DEST          BLN     SOURCE  err=not_found
                                                         ^^^^^
                                                         canonical name leaked
```

The panel did not implement the request (returned `0x0003 not_found`) but still leaked `NODE1` as its canonical name. **A passive observer on any conversation gets the panel's name from the very first response, regardless of payload.** Likewise, an active scanner sending a single garbage request that produces an error gets the panel's name back for free.

### 2. `0x4640` IdentifyBlock success response

A successful response to a panel-bound IdentifyBlock request carries the panel's **full identity** as a TLV-encoded body. Sample from a successful exchange:

```
01                              dir = success
"OCCEBLN" "OCCDCC-SVR|5034" "OCCEBLN" "NODE6"     routing (panel name in slot 4)
01 00 05 "NODE6"                LP-string: panel's node name (in body)
01 00 03 "OCC"                  LP-string: site name
01 00 07 "OCCEBLN"              LP-string: BLN name
00 01 01 00 00 00 00 00         8-byte fixed pattern
00 69 EA 3E F5                  panel-side timestamp (BE u32 epoch)
00 00 00                        trailer
```

A successful IdentifyBlock to a single panel reveals the full `(BLN, site, panel)` triple in one round trip. Of course, you need a valid IdentifyBlock to get a successful response — but the leak in #1 above gives you the panel name, and the BLN name is what got you past the TCP RST in the first place. So by the time you can run this, you already had the data.

### 3. `0x010C` SystemInfo response — the firmware-fingerprint leak

After a valid handshake, a single `0x010C` request (2-byte body — the smallest in the protocol) returns a richly identifying response:

```
PME1300                         <-- firmware family
PXME V2.8.18 APOGEE             <-- detailed firmware version
Sep 26 2019 12:41:20            <-- build timestamp
... binary status flags ...
NODE11                          <-- node name (also in routing slot 4)
OCC                             <-- site name
OCCEBLN                         <-- BLN name
```

Different panels carry different application identifiers in the same field — observed values include `R911FTR`, `DIVV9`, `DIVV9-Peter`, `APPLICATION`. These are the application-program names installed on each panel. **A scanner that hits `0x010C` against every IP on a subnet builds a complete asset inventory: firmware version, build date, application program, node/site/BLN — in one frame per panel.**

### 4. `0x0050` and `0x0606` lightweight probes

Both have `00 XX YY 01 00 04 "SYST" 23 3F FF FF FF` request shapes — the same `SYST`-scoped "give me the system" probe with different opcode bytes:

- **`0x0050`** response body: `01 00 04 "SYST" 23 3F FF FF FF [00 02] 01 00 0A "OCCDCC-SVR" 01 00 00` — the registered supervisor name string. Plus the panel name in routing slot 4. So `0x0050` leaks **panel name + supervisor name** in one round trip. This is the opcode the doc has long marked as the "early shortcut" for cold discovery.
- **`0x0606`** response body: empty (`00 00`) — pure ACK. Still leaks the panel name in routing slot 4.

Use `0x0050` when you want supervisor name (for the "scanner attack" step); use `0x0606` when you only want a panel-presence ACK.

### 5. `0x4634` routing-table push — the topology-in-one-message goldmine

Documented above — a single `0x4634` observation (passive or actively triggered) reveals **the entire BLN topology**: every panel name, the supervisor name (with and without `|5034` suffix), the panel-default route name (`$paneldefault`), the site identifier (`101000`), the BMS registration (`SITE-BMS` / `OCC-SIEMENS-BMS`), each with its 4-byte cost. One frame, complete reconnaissance. If you can passively listen on the BLN segment for ~1 minute, a real supervisor will publish this without you sending anything.

### Cold-discovery flow chart, optimized

Putting these together, the most efficient cold-discovery sequence is:

1. **Passive listen 60 seconds** for any `0x4634` from a real supervisor → if heard, you're done; you have everything.
2. **Active probe** TCP/5033 on candidate IPs. RST = wrong BLN; silent or accept = candidate alive.
3. **Send a deliberately-malformed request** (or a `0x0606` with a guessed BLN and arbitrary slot 4) to any responsive IP. Any response — success or error — leaks the panel's canonical name in routing slot 4.
4. **Send `0x0050`** to that IP using the leaked name in slot 2. Response leaks the registered supervisor name.
5. **Construct a valid IdentifyBlock** with the now-known BLN, panel, and supervisor names. Send it.
6. **Send `0x010C`** to harvest firmware/application/build-date.
7. **Send `0x4634`** to harvest the rest of the BLN topology.

Step 1 is no-touch and yields complete topology if a supervisor is active. Steps 2–4 cost a handful of probes and yield enough names to make step 5 succeed. The cartesian attack from the prior section is the fallback when steps 1–4 don't yield. In the OCC corpus, every panel responded to step 4 within the first probe.

### Practical caveat: case-sensitivity for the BLN name

The bouncer's BLN check appears to be **case-sensitive**: `OCCEBLN` works, `occebln` issues a TCP RST. The node-name check is case-insensitive (lowercase variants get routed-and-canonicalized). Treat BLN as exact-match-or-RST when iterating; treat node name as case-folded.

---

## What's still unknown

- **Property state sentinel** (`3FFFFFFF` vs `00000000`) — still not cracked; observation across all pcaps suggests it's a generic "wildcard / no filter" sentinel rather than a quality-flag register
- **Opcode `0x0273` (full semantics)** — now observed only in alarm-acknowledgement workflows immediately preceding `0x0509`. ACK-only response, same wire shape as `0x0271` but `00 00` trailer. Whether it's strictly required before `0x0509`, or has independent uses outside alarm flows, hasn't been tested in isolation
- **Alarm-class identifier (`"CC#"` in 0x0508 / 0x0509)** — constant in observed samples; may take other values for different alarm priorities, fault types, or system contexts. Triggering different alarm classes deliberately would surface variants
- **0x0508 optional 4-char marker** — present in some alarm records (a 4-byte ASCII string between two zero-pad runs), absent in others. Likely an alarm-instance identifier or a class-derived tag, but specific encoding not pinned down
- **0x0508 trailing flag block** — the ~30 bytes after the last BACnet datetime contain priority/escalation/state flags. Bit-level mapping not yet determined; would benefit from captures spanning multiple alarm transitions on the same point (raise → ack → return-to-normal → re-raise)
- **0x4106 parameter bytes** — the trailing `00 01 7F FF` is stable across observations but only one variant has been observed. If Desigo has a "clear SOME tracebits" or "clear on condition" mode, those parameters would surface different values here. The same trailer appears in `0x4103`, suggesting the trailer is a shared "program-runtime command" framing rather than ClearTracebits-specific
- **Subscription / unsubscription opcodes** — not observed. The 5034 push channel operates without a visible handshake in captures. A capture of a PXC coming online from reset would resolve this
- **Subscribe-from-graphic path** — if Desigo uses a different mechanism to request ad-hoc subscriptions when a floor plan is opened (vs the always-on 5034 pushes), that exchange wasn't in any capture window
- **Full data-type code table** — empirically pinned for the dominant codes (0x00, 0x02, 0x03, 0x06; see "Data-type codes" sub-section under point-read responses). Codes `0x01`, `0x04`, `0x05` referenced in the SHAPE B detection heuristic but unobserved across all captures analyzed — semantics speculative
- **0x4634 cost function** — now known to be a per-observer metric (not a global link cost), with DCC reporting consistently lower values than PXCs. Exact computation (latency EWMA? hop-weighted RTT? integer ping sample?) still not pinned down
- **0x0982 timestamp format** — embedded timestamps (e.g. `79 09 07 02 0C 16 FF 2A`) match the BACnet date+time encoding documented in the alarm-reporting section: `year-1900 / month / day-of-month / day-of-week / hour / minute / second / hundredths`. The `0xFF` byte in observed samples is BACnet's "unspecified / wildcard" sentinel — probably indicates trend or schedule queries that match any value in that field. Whether the trailing byte is `hundredths` (as in 0x0508) or a `tz/dst` field unique to 0x0982 needs more samples
- **0x098D `88 0C XX YY` schedule-time field** — bytes 0–1 are constant (`0x88 0x0C`); byte 3 always matches the date's day-of-week. Byte 2 varies across `0x19`–`0x1F`, possibly a packed time-of-day field. Not yet decoded
- **0x098C–0x098F state-set trailer** — every response in the family ends with `fc 13`, which decodes via `0x040A` as the `UNOCC_OCC` state-set. Whether the trailer is always this specific cursor, or whether it varies by schedule type, would need more samples from non-occupancy schedules to determine
- **0x0976 multistate / binary handling** — the op only returns analog (f32) subpoints. Whether a separate flag in the request can include multistate / binary subpoints, or whether they require separate ops, is not yet established
- **MSTP gateway traffic** — BACnet-over-P2 tunneling may use a different opcode set when PXCs bridge to third-party BACnet devices
- **Backup/restore, firmware-upload** — distinct opcode sets used by Siemens' engineering tools, out of scope
- **Opcodes `0x09A3 / 0x09A7 / 0x09AB / 0x09BB / 0x400F–0x4133`** — supervisor sends them, PXC rejects with `00 AC`; probably newer-firmware features. Not mapped.
- **`has_more` flag in 0x0985 responses** — present at byte-offset -5 of the response body, but its value doesn't correlate with program boundaries in observed data. Either the semantic is different from what it appears to be, or it encodes something that happens to be almost constant in our captures. Ignored by the reference implementation.

---

## References and corrections to common misunderstandings

### "The heartbeat uses opcode `0x4640`"

Partially misleading. `0x4640` is an **identity block marker** that can appear in CONNECT (0x2E), ANNOUNCE (0x2F), inside DATA (0x33) bodies, and inside HEARTBEAT (0x34) bodies. It is not specific to any one message type. Operation opcodes like `0x0100`, `0x0271`, `0x0274`, `0x0986` also appear inside both 0x33 and 0x34 bodies.

### "The routing header puts destination first, source second"

Only true for DATA (0x33) and HEARTBEAT (0x34). **CONNECT (0x2E) and ANNOUNCE (0x2F) reverse the order**: the sender's own name is in slot 2, the target in slot 4. Don't write a parser that assumes dest-src for all message types.

### "`0x0271` is an extended read, `0x0220` is a short read"

Oversimplified. Both are point-read opcodes. They're two different flavors produced by two different eras of Siemens client software (WCIS/Insight vs Desigo CC). The response shapes differ slightly but both return the same underlying data. Calling one "extended" and the other "short" is a description of response sizes, not of functionality.

### "You can tell a device is offline from the response"

Only if you check the comm status byte. The PXC happily returns stale cached data for offline devices without any indication in the value itself. The `0x00` vs `0x01` comm status byte in the metadata block is the only way. And note this is *distinct from* the response's leading status byte (`0x01` success vs `0x05` error) — the comm-fault byte is inside the value block metadata.

### "`0x0274` is an unsolicited COV notification"

Partly right, partly wrong. `0x0274` is **bidirectional** — it's a push-write when supervisor→PXC (on 5033) and a COV notification when PXC→supervisor (on 5034). The original doc stated only the COV side; an earlier revision of this doc over-corrected and called it "a push-write, not a notification" because the first pcap only captured the 5033 direction. Captures taken from the DCC server side show both directions simultaneously. Treat the opcode as "the generic value-update opcode" with direction-dependent semantic.

### "The `3F FF FF FF` sentinel is the quality-flag register"

Probably not. It appears in too many unrelated places — inside `0x0220` request bodies, inside `0x4221` bulk-read bodies, and in response value blocks. It looks more like a generic "wildcard property / match-any" marker used across opcode families, with different consumers attaching different meanings.

### "CONNECT is optional — you can skip straight to heartbeat"

Both paths work against this firmware: explicit `0x2E` CONNECT, or a `0x34` HEARTBEAT carrying a `0x4640` identity block, will each establish a session. Desigo CC tends to use the explicit CONNECT path; minimalist scanners (and the scanner in the parent repository) can get away with the heartbeat-only path. Don't assume one is required — depending on your client library's history, it may be sending either.

### "All 09xx enumerate opcodes use the same request format"

No. The 09xx range spans at least three distinct families:

- **Point enumerates** — `0x0981`, `0x0982`, `0x0985`, `0x0986`, `0x0988` — each has its own request shape (see *0x0986*, *0x0981*, *0x0985* sections above)
- **Schedule operations** — `0x0961`, `0x0964`–`0x0976`, `0x0979`, `0x098C`–`0x098F` — object-targeted property reads, not enumerates (see *Schedule operations*)
- **Status / port queries** — `0x099F` — short fixed-format probes

The three mainstream enumerate opcodes each have a different request shape:

- **`0x0986`** (FLN devices): two cursor TLVs, no filter.
- **`0x0981`** (all points): two filter TLVs (always `*`) + cursor TLV + trailing empty TLV — six TLV fields total.
- **`0x0985`** (PPCL programs): ONE filter TLV + ONE cursor TLV + a u16 BE line-number trailer (not another TLV).

Using the wrong shape returns `0x05 0x00 0x03` "not found" from the PXC, even though the opcode is supported. If you get "not found" on an opcode you know exists on that firmware, the request body framing is the first thing to check.

### "Bare 09xx CONNECT frames are always PXC→DCC keepalives"

Partially right. The genuine 2-byte session-keepalive pings (`0x0951`/`0x0954`/`0x0955`/`0x0956`/`0x0959`) are PXC→DCC and carry no body. But the schedule-operation 09xx family (`0x0961`, `0x0964`–`0x0976`, `0x0979`, `0x098C`–`0x098F`) is DCC→PXC and rides inside Mode C connections (`0x2E`/`0x2F`-only TCP flows; see *Three connection modes*). Don't assume direction from the message-type byte alone — check the body length: <3 bytes = bare-opcode ping, ≥10 bytes = full operation.

### "TLV fields start with `01 00`"

Subtle off-by-one trap. The TLV format is `[tag: 1 byte = 0x01][length: u16 BE][value: LL bytes]` — three bytes of header. An easy bug when writing Python `struct.pack` is to treat the header as `[\x01\x00][u16 length][value]`, which silently adds an extra zero byte of header and shifts every downstream length by one. This will parse fine in isolation because TLVs are length-delimited, but it corrupts fixed-position trailers. Symptom: requests look right in a packet dump, but the PXC returns the first matching entry and refuses to advance the cursor on continuation calls.

### "The `has_more` flag in 0x0985 responses tells you when a program ends"

It doesn't, reliably. The one byte at offset -5 in a `0x0985` response body looks like a has-more flag, but its observed values don't correlate with program boundaries. Use the `0x05 0x00 0x03` error response — PXC returns it when you ask for a line past the end of the last program — as the authoritative termination signal.

### "Every PXC accepts type `0x33` DATA for operational requests"

No. Modern-firmware panels (PME1300 platform) accept only type `0x34` HEARTBEAT for operational requests, and silently drop `0x33` frames. Legacy panels (PME1252 and earlier) accept only `0x33` and silently drop `0x34` operational frames. See "Firmware dialects" above. Symptom of picking the wrong type is connection-accepts-but-reads-never-complete, with zero error messages anywhere. Always detect the dialect at handshake time.

### "Multicast discovery beacons live on UDP 5033"

False. Across 40+ captures across multiple sites and capture vantages, **zero** UDP 5033 traffic appears anywhere. The actual multicast presence beacon is on `233.89.188.1:10001` UDP, payload `01 00 00 00`, ~10.5-second cadence. See "Multicast presence beacons" in the Transport section above.

### "0x0986 EnumerateFLN requires the 14-byte verbose request body"

Partially right — the verbose form works, but it's not the only accepted form. Captures of a scanner iterating through ~20 candidate body shapes against a live panel show **two formats** that succeed: the verbose `[3-byte pad][u16 BE length][content]` form (14 bytes for the wildcard call) and a compact `[tag=0x00][u8 length][content]` form (8 bytes). Both decode to the same panel response. See "0x0986 EnumerateFLN — request format" for both layouts. The off-by-one variants (e.g. 5-byte pad instead of 6-byte cursor) all silently fail with `0x0003`.

---

## Empirical validation status

What's been tested end-to-end against live PXCs on the reference site — both PME1252 V2.8.10 legacy-dialect panels and a PME1300 V2.8.18 modern-dialect panel:

| Capability | Method | Status |
|------------|--------|--------|
| Session handshake (legacy) | `0x33` + inner `0x4640` | ✓ Routinely working |
| Session handshake (modern) | `0x34` + inner `0x4640` | ✓ Working against the modern-dialect panel once implemented |
| Mode C bare-CONNECT carrier | `0x2E`-only or `0x2F`-only TCP flow | ✓ Observed end-to-end in schedule-edit capture; parser handles |
| Dialect auto-detection | probe 0x33 with short timeout, fall back to 0x34 | ✓ Implemented; per-host cache avoids repeat probes |
| Point read by name | `0x0220` / `0x0271` | ✓ Routinely working on both dialects |
| Enhanced point read | `0x0971` | ✓ Returns description + value + units + resolution + min/max + type-code |
| Device-all-subpoints read | `0x0976` | ✓ Returns app number + description + per-slot f32 tuples for one device |
| Multistate point enumerate | `0x0974` | ✓ Returns object name + state index + state-set ref |
| Schedule object list | `0x0969` | ✓ Returns child schedule objects under a parent name |
| Schedule property reads | `0x098C`–`0x098F` | ✓ All four sub-properties decoded for a single schedule |
| Multistate label catalog | `0x040A` | ✓ Walked end-to-end; ZONE_MODE (12 states) and UNOCC_OCC (2 states) decoded |
| Object display labels | `0x5038` | ✓ Cursor enumerate decoded; programmatic-name → display-label mapping |
| Status / port-config probes | `0x0050`, `0x099F`, `0x0606` | ✓ Wire format decoded from captures |
| FLN enumeration | `0x0986` | ✓ Returns ~17–21 devices on representative panels |
| All-point enumeration | `0x0981` | ✓ Returns ~91 points on a representative panel including panel-internal |
| PPCL source dump | `0x0985` | ✓ Returns all 5 programs, 103 total source lines |
| Compact sysinfo | `0x010C` | ✓ Returns model/firmware/build date |
| Legacy sysinfo | `0x0100` | ✓ Returns same fields in different layout |
| pcap decoding | Offline | ✓ Parses all 52 captures cleanly across the corpus |

What's wire-format-documented but NOT live-tested:

| Capability | Reason not tested |
|------------|-------------------|
| 5034 passive listener | Scanner machine isn't the configured supervisor IP; PXCs don't push to it |
| 0x4106 tracebit clear | Intentionally excluded from the read-only scanner |
| 0x4100 / 0x4103 / 0x4104 PPCL line edits | Modify panel program text; out of scope for read-only scanner |
| 0x5020 / 0x5022 schedule writes | Modify schedule data; out of scope for read-only scanner |
| 0x0274 COV receive | Requires 5034 listener above |
| 0x0240 virtual-point push | Observed passively in captures; scanner doesn't write |
| `0x4222` BulkPropertyWrite | Wire format reverse-engineered from a Desigo-driven setpoint-change capture (50→40 round-trip). Scanner doesn't write — `0x4222` is documented for completeness but not exercised |
| `0x0E15` error response handling | Observed in capture; the scanner won't trigger it because it doesn't send `0x0240` against `SYST` properties |
| 0x0508 / 0x0509 alarm pair | Observed end-to-end in a real Desigo CC alarm-ack capture (operator-initiated, multiple panels). Not tested by sending an `0x0509` from the scanner — that's a write operation and out of scope for the read-only design |
| 0x0273 in alarm context | Observed sent by Desigo during alarm acknowledgement. Not tested in isolation — whether 0x0509 alone (without the preceding 0x0273) is accepted by the panel hasn't been probed |
| Cold-site discovery on modern dialect | Cold-probe path still uses legacy-dialect-only probes; modern panels may fingerprint differently |
| 0x0988 multi-string filter | Low priority — 0x0981 covers enumeration needs |

Every wire format documented above has been either live-tested OR observed in a real Desigo CC capture and byte-verified against that capture. No speculation-only entries remain in the opcode tables.

---

## Appendix: Minimum viable scanner — annotated worked example

The smallest end-to-end scanner: open TCP, send CONNECT, send one read, parse the float, repeat. All byte sequences below are the real wire format used by the legacy dialect (`msg_type = 0x33` DATA frames), reproduced from real captures with placeholder names substituted for site-specific identifiers. Lengths shown are exact.

The placeholder names used throughout:
- BLN name: `MYBLN` (5 chars)
- Target panel: `panel1` (6 chars)
- Scanner identity: `scanner|5034` (12 chars)
- Site code: `site` (4 chars)
- Device name (FLN side): `TEC1` (4 chars)
- Subpoint: `TEMP` (4 chars)

Substitute these for whatever your environment uses; only string lengths matter to the framing.

### Step 1 — TCP connect

```python
import socket
s = socket.create_connection((pxc_ip, 5033), timeout=5)
```

That's it. No P2 magic until you write a frame to the socket.

### Step 2 — Send the CONNECT handshake (95 bytes)

```
HEADER (12 bytes)
  00 00 00 5F                  total length = 95
  00 00 00 33                  msg_type = 0x33 (DATA, legacy dialect)
  00 00 00 01                  seq = 1 (you pick — monotonic per side)

PAYLOAD
  00                           direction byte = request
  
  Routing header — 4 null-terminated ASCII strings:
  4D 59 42 4C 4E 00            "MYBLN\0"            BLN name
  70 61 6E 65 6C 31 00         "panel1\0"           target node
  4D 59 42 4C 4E 00            "MYBLN\0"            BLN name (repeated)
  73 63 61 6E 6E 65 72 7C 35 30 33 34 00     "scanner|5034\0"     your identity
  
  Identity block:
  46 40                        opcode 0x4640 (Identify)
  01 00 0C                     LP-string header: tag=01, pad=00, len=12
  73 63 61 6E 6E 65 72 7C 35 30 33 34         "scanner|5034"
  01 00 04                     LP-string header: len=4
  73 69 74 65                  "site"
  01 00 05                     LP-string header: len=5
  4D 59 42 4C 4E               "MYBLN"
  
  Trailer (16 bytes — flags + timestamp + pad):
  00 01 01 00 00 00 00 00      8 bytes of mostly-zero flags
  69 EB 62 22                  4-byte timestamp (any value; PXC ignores)
  00 FE 98 00                  4-byte trailing pad (constant)
```

The PXC validates this and replies with a routing-flipped success acknowledgement carrying the panel's identity. You don't need to parse the response in detail — just confirm `msg_type=0x33`, `seq=1`, direction byte = `0x01`. If you get direction byte `0x05` instead, the bouncer rejected you (see "The bouncer" section).

### Step 3 — Send a read request (71 bytes)

```
HEADER (12 bytes)
  00 00 00 47                  total length = 71
  00 00 00 33                  msg_type = 0x33 (legacy dialect)
  00 00 00 02                  seq = 2

PAYLOAD
  00                           direction byte = request
  
  Routing header (4 strings, same shape as CONNECT):
  4D 59 42 4C 4E 00            "MYBLN\0"
  70 61 6E 65 6C 31 00         "panel1\0"
  4D 59 42 4C 4E 00            "MYBLN\0"
  73 63 61 6E 6E 65 72 7C 35 30 33 34 00     "scanner|5034\0"
  
  Read body:
  02 71                        opcode 0x0271 (ReadProperty, legacy)
  00 00                        2-byte separator
  01 00 04                     LP-string header: len=4
  54 45 43 31                  "TEC1"               (device on the FLN)
  01 00 04                     LP-string header: len=4
  54 45 4D 50                  "TEMP"               (subpoint name)
  00 FF                        trailer (00 = property selector, FF = wildcard)
```

The two-byte trailer is significant: `00 FF` reads the canonical default property; `00 00` is the `0x0273 WriteNoValue` semantic. Don't truncate the body before the trailer.

### Step 4 — Receive the read response (typical 137 bytes)

```
HEADER (12 bytes)
  00 00 00 89                  total length = 137
  00 00 00 33                  msg_type = 0x33
  00 00 00 02                  seq = 2 (echoed from your request)

PAYLOAD
  01                           direction byte = success
  
  Routing header (4 strings, src/dst swapped from request):
  4D 59 42 4C 4E 00            "MYBLN\0"
  73 63 61 6E 6E 65 72 7C 35 30 33 34 00     "scanner|5034\0"
  4D 59 42 4C 4E 00            "MYBLN\0"
  70 61 6E 65 6C 31 00         "panel1\0"
  
  Response body (variable layout — example shown):
  00 04 00 02 00 00            6-byte response header
  01 00 04 54 45 43 31         LP-string "TEC1" — device echoed
  01 00 04 54 45 4D 50         LP-string "TEMP" — point echoed
  00 01                        separator
  01 00 04 54 45 43 31         "TEC1" again (sometimes appears in description block)
  01 00 04 54 45 4D 50         "TEMP" again
  
  ───────────── value block starts here ─────────────
  01 00 00                     ★ VALUE BLOCK MARKER (the byte before is the
                                 last char of the point name — "P" = 0x50
                                 — printable ASCII; this is the rule that
                                 disambiguates this from the trailing
                                 config-metadata block)
  00 00 00 00 00 00 00         7-byte metadata (R2 variant: quality flags
                                 explicit zero, no embedded type code)
  42 91 00 00                  ★ FLOAT at offset +10 from marker — IEEE-754
                                 big-endian = 72.5
  ───────────── value block ends here ─────────────
  
  00 00 00                     3-byte pad
  01 00 03 44 45 47            LP-string "DEG" — units (when present)
  ...                          trailing configuration block (min/max/units —
                                 ignored by simple scanners)
```

### Step 5 — Parse the float (the entire algorithm in 12 lines)

```python
def parse_value_block(payload: bytes) -> float | None:
    """Returns the f32 value or None if no value block found."""
    ASCII_END = b"-_.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
    # Bound the loop so payload[i+10..i+14] is fully addressable
    for i in range(1, len(payload) - 13):
        if payload[i:i+3] != b"\x01\x00\x00":
            continue
        # The byte before the marker MUST be a printable ASCII char (last
        # byte of a point-name TLV). This rules out the trailing-config-
        # block false positive.
        if payload[i-1] not in ASCII_END:
            continue
        return struct.unpack(">f", payload[i+10:i+14])[0]
    return None
```

That's the whole parser for R1/R2/R3 variants. The 7-byte metadata (offsets +3 through +9) carries the quality sentinel and data-type code — see "Data-type codes" section if you need to distinguish analog vs binary at the byte level.

**Off-by-one trap**: the loop bound is `len(payload) - 13` (covers `payload[i]` through `payload[i+13]`). If you write `len(payload) - 14` (one less), digital points without a trailing units TLV silently fail to parse — the float sits at the last 4 bytes of the payload and your scan misses it. This is the single bug most likely to bite a re-implementation.

### Step 6 — Keep the session alive

Send a fresh `0x4640` Identify frame on the same TCP connection every 10.0 seconds (Desigo's empirical cadence — see "Session keepalive"). Same wire shape as Step 2, just bump the `seq` field. Panels haven't been observed dropping at longer intervals, but matching Desigo's cadence is the safe default.

### Step 7 — Putting it together (~60 lines of Python)

```python
import socket, struct, time

def lp_string(s: bytes) -> bytes:
    """Build a length-prefixed string TLV: 01 00 LL <bytes>."""
    return b"\x01\x00" + bytes([len(s)]) + s

def build_routing(bln: bytes, dst: bytes, src: bytes) -> bytes:
    return b"\x00" + bln + b"\x00" + dst + b"\x00" + bln + b"\x00" + src + b"\x00"

def build_frame(seq: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack(">III", total_len, 0x33, seq) + body

def build_connect(bln: bytes, dst: bytes, src: bytes, site: bytes, seq: int) -> bytes:
    routing = build_routing(bln, dst, src)
    identity = (b"\x46\x40"             # opcode 0x4640
                + lp_string(src)
                + lp_string(site)
                + lp_string(bln)
                + b"\x00\x01\x01\x00\x00\x00\x00\x00"
                + struct.pack(">I", int(time.time()))
                + b"\x00\xFE\x98\x00")
    # Note: the leading direction byte 0x00 is already in build_routing
    return build_frame(seq, routing + identity)

def build_read(bln, dst, src, device, point, seq):
    body = (build_routing(bln, dst, src)
            + b"\x02\x71\x00\x00"
            + lp_string(device)
            + lp_string(point)
            + b"\x00\xFF")
    return build_frame(seq, body)

def parse_value(payload: bytes) -> float | None:
    ASCII_END = b"-_.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
    for i in range(1, len(payload) - 13):
        if payload[i:i+3] == b"\x01\x00\x00" and payload[i-1] in ASCII_END:
            return struct.unpack(">f", payload[i+10:i+14])[0]
    return None

def recv_frame(sock: socket.socket) -> bytes:
    hdr = b""
    while len(hdr) < 12:
        chunk = sock.recv(12 - len(hdr))
        if not chunk: raise ConnectionError("closed")
        hdr += chunk
    total_len = struct.unpack(">I", hdr[:4])[0]
    body = b""
    while len(body) < total_len - 12:
        chunk = sock.recv(total_len - 12 - len(body))
        if not chunk: raise ConnectionError("closed")
        body += chunk
    return hdr + body

def read_one(pxc_ip: str, panel: bytes, device: bytes, point: bytes,
             bln=b"MYBLN", scanner=b"scanner|5034", site=b"site") -> float | None:
    s = socket.create_connection((pxc_ip, 5033), timeout=5)
    try:
        s.sendall(build_connect(bln, panel, scanner, site, seq=1))
        recv_frame(s)  # CONNECT ack
        s.sendall(build_read(bln, panel, scanner, device, point, seq=2))
        response = recv_frame(s)
        return parse_value(response[12:])  # strip 12-byte header
    finally:
        s.close()

# Usage:
# value = read_one("10.0.0.42", panel=b"panel1", device=b"TEC1", point=b"TEMP")
# print(f"reading: {value}")  # → 72.5
```

This is functional against legacy-dialect (PME1252) panels. For modern-dialect (PME1300) panels, change `0x33` → `0x34` in `build_frame` and switch the read opcode from `0x0271` to `0x0220` with the modified body shape (see "Reading a point"). For mixed sites, implement the dialect probe in "Firmware dialects → Detection algorithm."

That's the entire end-to-end scanner: ~60 lines, no dependencies beyond stdlib. Everything beyond this — point enumeration, COV listening, alarm handling, writes, multi-panel coordination — extends from the same primitives in the same way.
