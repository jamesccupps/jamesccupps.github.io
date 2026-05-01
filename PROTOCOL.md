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
  - **Two-node validation capture** (~1.6 MB, ~11k packets, 35 minutes, 2 panels) — server-side capture covering both legacy-dialect (NODE3, PME1252) and modern-dialect (NODE11, PME1300) panels in normal steady-state operation. Surfaced opcode `0x0295` (a previously-undocumented 02xx read variant), provided byte-level validation for the documented `0x0274` / `0x0240` wire formats against live data, and exposed an error in the previous routing-header "Name ordering" correction below — see *Routing header* for details.

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

**Corpus-wide statistics (51 pcaps from the reference site):** 1040 beacon packets observed across 26 pcaps. Every one carries the identical 4-byte payload `01 00 00 00` (zero variation in 1040 samples). Two unique source IPs: `10.0.0.1` (547 packets, HVAC VLAN gateway) and `10.0.1.1` (493 packets, HVAC-Ext VLAN 6 gateway). Two destinations: `233.89.188.1` (534 packets) and `255.255.255.255` (506 packets). Of 906 inter-emission intervals, 474 fall in the [10.0 s, 11.0 s] band (the real cadence — median 10.4906 s, max 10.6546 s) and 415 are sub-millisecond (the multicast/broadcast pair-emission deltas). The pattern is mechanically regular.

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

### Name ordering: slot 2 = destination, slot 4 = source

**Empirically verified across 7873+ messages spanning all four message types: slot 2 is always the destination node, slot 4 is always the source node.** The byte order does not depend on message type.

| Message type | Slot 2 | Slot 4 |
|--------------|--------|--------|
| `0x33` DATA | destination | source |
| `0x34` HEARTBEAT | destination | source |
| `0x2E` CONNECT | destination | source |
| `0x2F` ANNOUNCE | destination | source |

Concrete examples from real captures:

DATA C2S (supervisor addresses PXC):
```
00 "SITEBLN" "node6" "SITEBLN" "DCC-SVR|5034"
       BLN     DEST       BLN          SRC
```

DATA S2C (PXC response — slots swap to keep slot 2 = destination of *this* frame):
```
01 "SITEBLN" "DCC-SVR|5034" "SITEBLN" "NODE6"
       BLN          DEST            BLN     SRC
```

CONNECT (PXC opens Mode C connection to supervisor:5033):
```
00 "SITEBLN" "DCC-SVR" "SITEBLN" "NODE3"
       BLN       DEST          BLN     SRC
```

In the CONNECT example, IP source is NODE3 (the panel) and IP destination is the supervisor. The IdentifyBlock body's first TLV — the sender's self-name — is `NODE3`, agreeing with slot 4 (source), not slot 2. Both the IP-layer direction and the inner identity payload independently confirm that slot 4 holds the sender for CONNECT/ANNOUNCE just as it does for DATA/HEARTBEAT.

**Correction note.** An earlier revision of this document claimed CONNECT and ANNOUNCE reversed the ordering — slot 2 = sender, slot 4 = recipient. That claim is contradicted by all available evidence: the two-node validation capture contains 854 CONNECT/ANNOUNCE frames (426 `0x2E` + 428 `0x2F`), covering both panel→supervisor requests and the corresponding supervisor→panel responses, and every one follows the destination-first convention. The supervisor responses are particularly conclusive — they have IP src = supervisor and slot 4 = supervisor, so slot 4 is the source even when the supervisor is doing the sending. The likely source of the earlier error was a hand-annotated example whose IP-direction wasn't cross-checked against the routing slots. The corpus does not contain a supervisor-initiated `0x2E` CONNECT (Mode A flows in this capture used the alternative `0x33` + inner `0x4640` initiation path), so a residual possibility exists that some old Insight/Desigo client populates the slots differently — but no such client has been observed. Parser authors should treat slot 2 = destination as universal until counter-evidence appears.

**Scanner identity conventions:**
- Desigo CC servers: `<SITE>DCC-SVR|5034`
- Insight servers: `<SITE>WCIS-SVR`
- Engineering tools (field techs): varies, often includes the tool name

The `|5034` suffix on the scanner identity is the port the scanner is listening on for responses — it's not a separator, it's part of the scanner's identity string. Interestingly, CONNECT/ANNOUNCE messages use the bare form `DCC-SVR` without the `|5034` suffix, while DATA messages use `DCC-SVR|5034`. Both forms must be recognized.

---

## The bouncer (identity validation)

The PXC validates handshake fields with two distinct failure signatures. Field-tested against live panels:

| Field | If wrong | Why it matters |
|-------|----------|----------------|
| **BLN name** | TCP RST | BLN is both security AND routing — wrong BLN means the PXC has no valid route for the packet. Case-sensitive. |
| **Slot 2 (destination panel name)** | Silent drop | TCP connection stays up; the frame is silently discarded by the routing layer. Slot 2 must case-fold-match a name in the panel's known peer list — arbitrary strings (`*`, empty, IP literal, generic words) all silent-drop. Case-correction does fire for case-variants of known names. |

**Other fields are NOT validated.** Specifically:
- The **source identity in slot 4** can be any string — a scanner does not need to impersonate the supervisor name.
- The **IdentifyBlock body fields** (self-name TLV, site code TLV, BLN TLV) are not validated beyond internal consistency with the routing slots.
- The **trailer bytes** (timestamp, session ID) are not validated as authentication, though see "Panel persistent reconnect side effect" in Field-testing findings for context on what the panel does with these fields when registering runtime peers.

This means a read-only scanner only needs to know two things to establish a session: the **BLN name** (exact case-sensitive match) and **at least one panel name** (case-insensitive). Everything else is decorative.

The distinct BLN-RST vs slot-2-silent behavior is what makes cold-site BLN discovery tractable: you can enumerate BLN candidates in parallel by looking at TCP RST vs silent drop, without sending actual reads. See *Cold-site discovery* and *Identity-leak surfaces* below.

---

## Connection handshake: CONNECT (0x2E) and ANNOUNCE (0x2F) wire format

CONNECT and ANNOUNCE have **structurally identical payloads**. The only differences are the message type code (0x2E vs 0x2F) and slight byte-length variation for the embedded node name.

Total frame size depends on the lengths of the four name strings (BLN, panel-name, supervisor-name, site-code) — each appears in the payload at least once and the BLN appears twice. The delta between two CONNECTs from the same site is exactly the character-count difference in whichever name varies. Worked example with concrete byte counts is in the *Minimum viable scanner* appendix.

Full layout (CONNECT example, panel `NODE1` reaching back to supervisor `DCC-SVR`):

```
00                         direction byte (request, 0x00) or response (0x01)
"SITEBLN"\0                BLN (routing header slot 1)
"DCC-SVR"\0                destination — supervisor (slot 2)
"SITEBLN"\0                BLN (slot 3)
"NODE1"\0                  source — sender's self-name (slot 4)
46 40                      0x4640 IdentifyBlock marker
01 00 05 "NODE1"           TLV: self-name (tag=0x01, u16 BE length) — matches slot 4
01 00 03 "ACM"             TLV: site code
01 00 07 "SITEBLN"         TLV: BLN name
─── 16-byte trailer ───
00                         trailer separator (1 byte)
01 01 XX                   flags (3 bytes; XX = role flag, see below)
00 00 00 00 00             5 reserved/padding bytes (always zero in observed frames)
TT TT TT TT                4 bytes: Unix epoch timestamp (big-endian)
SS SS                      2 bytes: session identifier (per-session constant)
00                         trailing null
```

(Slot 2 is always the destination of the current frame and slot 4 is always the source — see *Routing header → Name ordering*. The IdentifyBlock body's first TLV is the sender's self-name, agreeing with slot 4.)

### The role flag (third byte of the flag triplet)

The third byte of the `01 01 XX` flag triplet — call it the role flag — takes different values depending on the relationship between sender and receiver:

| Sender | Context | msg_type | Third flag byte | Source |
|--------|---------|----------|-----------------|--------|
| Supervisor (Desigo CC) | Outbound CONNECT to panel | `0x33` (with embedded `0x4640`) | `0x00` | Verified in 52 corpus frames |
| Panel | Outbound CONNECT to **legitimately-configured supervisor** | `0x2E` | `0x00` | Verified in 51 corpus frames (NODE6 → real DCC) |
| Panel | Outbound CONNECT to **runtime-registered peer** | `0x2E` | `0x01` | Verified in listener test — NODE6 → scanner IP registered via `msg_type = 0x2E` CONNECT |

`0x01` in this position is the panel's signal that the destination is a peer registered at runtime (typically through an inbound `msg_type = 0x2E` CONNECT) rather than a peer configured via NVRAM/commissioning. Real DCC always sends `01 01 00`; real panels send `01 01 00` to their commissioned supervisor and `01 01 01` to runtime-registered peers.

**For scanner authors:** send `flags = 01 01 00` matching what real DCC and real panels both send to legitimately-configured peers. The `0x01` value is the panel's outbound signal, not something a supervisor-emulating scanner needs to set.

### The 2-byte session identifier

Bytes at trailer positions 13–14 are a 2-byte field with distinct conventions:

- **Panel-initiated CONNECTs always carry `00 00`** — verified in 51 corpus frames from a single panel. Panels do not set this field.
- **DCC-initiated CONNECTs carry a non-zero session-stable value** — verified in 52 corpus frames; a single DCC↔NODE6 session used `fe 98` for every frame within that session. Other sessions use other values; the field appears to be derived per-session and stable for the session's lifetime.

Since panels successfully establish sessions with `00 00` in this field, the panel-side bouncer apparently accepts this value. A scanner that uses `00 00` matches what real panels send. The exact derivation of DCC's non-zero value isn't pinned down (could be a hash of session parameters, a counter, or a random nonce per session); a scanner that wants to look like DCC could copy a value from a real capture, but doing so risks colliding with an active session.

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

**Mode C is undocumented in any prior reference and easy to miss.** The defining property of a Mode C connection is that **the message-type byte never transitions from `0x2E`/`0x2F` to `0x33`/`0x34`** for the entire lifetime of the TCP connection. Operational opcodes (reads, writes, schedule ops, alarms) all ride inside `0x2E` (or `0x2F`) framing. The routing header is the bare `DCC-SVR` form (without the `|5034` listen-port suffix).

Within Mode C there are **two sub-variants**, distinguished by what's in the very first frame:

| Mode C sub-variant | First frame | Use case |
|--------------------|-------------|----------|
| **Mode C with handshake** | `0x2E`/`0x2F` carrying a normal `0x4640` IdentifyBlock | A regular session that just keeps using the CONNECT/ANNOUNCE framing for its operational frames instead of switching to `0x33`/`0x34`. Indistinguishable from a stalled Mode A/B handshake unless you watch the whole flow. |
| **Mode C headless** | `0x2E`/`0x2F` going straight to an operational opcode (`0x0961`, `0x0969`, `0x0271`, `0x0508`, etc.) — no `0x4640` at all | Short bursty workflows: schedule queries, ad-hoc reads, alarm pushes. The supervisor (or panel) opens a fresh TCP connection just to fire off a few opcodes and tear it down — too short to be worth a handshake. |

**Both directions exist.** Mode C is **not** uniquely DCC→PXC. Across the corpus, fresh Mode C connections (caught at SYN) split roughly evenly:
- DCC→PXC:5033 — DCC initiates, sends schedule operations (`0x0961`, `0x0969`, `0x0974`)
- PXC→DCC:5033 — PXC initiates, sends reads (`0x0271`) or alarm reports (`0x0508`)

The PXC-initiated Mode C connections all target the **DCC's port 5033**. This means at least at the reference site, the DCC service listens on **both 5033 and 5034**. (Many references describe DCC as "5034-only" — that may be a deployment-specific simplification. Treat 5033/5034 as both-ways-listenable in any robust scanner.)

Sample headless Mode C flow from the schedule-edit capture, supervisor `10.0.0.10:55811 → 10.0.0.20:5033`:

```
Frame  Type  Direction  Opcode   Notes
1      2E    →          --       fresh TCP, bare CONNECT, no IdentifyBlock
2      2E    →          0x0964   schedule-name query (EXAMPLE.ROOM)
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
| `0x0272` | 5033/5034 | **ReadExtended-MetaOnly** (likely) | Wire format identical to `0x0271` but the trailing 2-byte sentinel is **omitted** (just stops at the second TLV). Body shape: `02 72 00 00 [01 00 LL <name>] [01 00 LL <subname>]`. Compare: `0x0271` ends with `00 FF` (request-the-value sentinel), `0x0273` ends with `00 00` (no-value sentinel). `0x0272` ends with neither — likely a "look up the property descriptor without fetching its current value" form, used by Desigo CC during schedule probes. **All 37 corpus samples come from `<reference-pcap>` and 35/37 return `0x0003 not_found`** — meaning the opcode is recognized but the named targets don't exist as schedule objects. Carried inside both Mode-C `0x2E` framing and ordinary `0x33` DATA frames |
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

1. **SHAPE A detection**: scan the body for the quality sentinel — match the **3-byte prefix `3F FF FF` only**, treating the 4th byte as opaque (commonly `FF` or `F7`, occasionally `F0`; all are equally valid). If found, the f32 value sits at sentinel-offset +7 (sometimes +4 or +8 for edge cases). The 3-byte prefix is unambiguous — it only appears on physical points with a quality register, and the unstable low nibble of the 4th byte must not be locked. (Matching the literal `3F FF FF FF` will silently miss the F7 majority on most sites — see "Property state sentinel" below.)

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
| `0x0964` | TitleAnalogQuery | `[01 00 04 "SYST"][01 00 LL <obj>][01 00 LL <subpoint>]` | Value + units + min/max limits | Used to populate Desigo "EXAMPLE.ROOM" room temperature widget. Carries f32 value, units string, and engineering limits |
| `0x0965` | NodeDiscoveryEnumerate | Cursor TLV pair; same as `0x0986` | Node name(s) on the BLN | Used early in a session to confirm panel reachability. Equivalent in function to a slim `0x0986` |
| `0x0966` | ShortQuery | 4-byte body, no SYST tag | Mostly `0x0003` | Probe op; rarely returns useful data |
| `0x0969` | ScheduleObjectList | `[01 00 04 "SYST"][01 00 LL <object>]` | List of schedule object names under a parent | Returns names like `"LIGHTING.SAMPLE.SCH"` — schedule objects in a panel namespace |
| `0x0971` | EnhancedPointRead | Like `0x0981` but with extra trailing config bytes | Description + value + units + resolution + min + max + type-code | More complete than `0x0981`. Returned `ROOM TEMP = 71.75 °F`, resolution `0.25`, max `48.0` for one tested point. Use this when a UI needs limits, not just current value |
| `0x0974` | MultistatePointEnumerate | Like `0x0964` but state-set-aware | Object name + current state index + state-set ref | Used for points like `EXAMPLE.HP.ZN/MODE` — pulls current multistate value plus the cursor reference into the matching state-set |
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
01 00 LL <schedule_name>        e.g. "LIGHTING.SAMPLE.SCH"
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

Schedule edits land via a paired write: an init/allocate (`0x5022`) followed by an entry-write (`0x5020`). Both observed in the schedule-edit capture (sequence numbers 529731 → 529732) targeting schedule objects `LIGHTING.SAMPLE.SCH` and `EXAMPLE.TENANT.SCH`.

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
| `0x0050` | 5033 | 4 | `00 50 01 00 04 "SYST" 23 3F FF FF FF` | Tiny (12-byte body). Status / flag query under SYST scope. **Returns the registered supervisor name list (`DCC-SVR`) without authentication** — useful for cold discovery |
| `0x0241` | 5033 | 14 | SYST + device + point | Point existence probe — returns echo of `(device, point)` on success. Shape is similar to `0x0220` but no value extracted |
| `0x0244` | 5033 | 2 | SYST-scoped query | Returns `0x0002` (object_unknown) on out-of-scope objects; scope-restricted variant of `0x0240` |
| `0x0245` | 5033 | 2 | 3-byte body | Test probe; always errors. Not a real op — appears only in `enumeratetest1.pcapng` |
| `0x0263` | 5033 | 4 | Object lifecycle / delete-related | Pairs with `0x0260` |
| `0x0203`, `0x0204`, `0x0260` | 5033 | 2–4 each | `XX XX [02–04] 00 02 00 00 [LP name] 01 00 00 00 01 [LP name] 01 00 00 01 00 00 3F FF FF FF` | **Object lifecycle family.** Probes seen carrying client-test names (`test1`, `test2`, `test4`, `test434`). The trailing `3F FF FF FF` is the same property-state sentinel used in `0x0050`. `0x0204` is doc-named CreateObject (returns `0x0E11 already_exists` if the name is taken). `0x0203` and `0x0260` likely sibling create/probe variants — only seen with client-debug names in the corpus, so semantics aren't pinned down beyond "object-lifecycle 02xx family" |
| `0x0291`, `0x0294`, `0x02A8` | 5033 | 2–8 each | SYST + device + point + value-like trailing bytes; some carry an inline byte `0xC8` followed by a type code and 4-byte float | Read/write variants in the 02xx family. `0x0291` and `0x02A8` carry value bytes (writes); `0x0294` carries no value (read). Separator after SYST is `0x23` for the value-carrying ones, `0x00` for the read-only one. **Two body shapes for 0x0294**: small (53-byte) form uses separator `0x00`; large (222-byte) preallocated form uses separator `0x01` |
| `0x0295` | 5033 | 25 | `02 95 [01 00 04 "SYST"][01 00 LL <obj>][01 00 LL <prop>]?` | Sibling of `0x0294` — SYST-scoped read against a single named object, optionally followed by a property-name TLV. Surfaced in the two-node validation capture, all 25 samples DCC→PXC. Most samples carry just an object name (short single-token plant-equipment status-register names — boiler/pump/tower enables, alarms, status); two carry `<schedule-object>, MODE` suggesting a multistate-aware variant. Wire shape mirrors `0x0294` small-form; semantics are the same family of "read a SYST-scoped property" probes. Add to the same dispatcher branch as `0x0294` |
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
| R1 | `0x0271` | `3F FF FF X? 00 00 00` | Quality flags partial (see below) |
| R2 | `0x0271` | `00 00 00 00 00 00 00` | Quality flags explicit, all clear |
| R3 | `0x0220` | `00 00 00 00 00 00 XX` | XX = data-type code (see "Data-type codes" sub-section) |
| R4 | any | (R2/R3 pattern but float starts `0xBF`) | Negative values |

**Critical: lock only the 3-byte prefix `3F FF FF`, NOT the full 4-byte `3F FF FF FF`.** The fourth byte varies on the wire — `3F FF FF FF` and `3F FF FF F7` are both real and very common, and at least `3F FF FF F0` has been observed. Field captures of one site's NODE3 returned `F7` for ~75% of live read responses and `FF` for the remainder, with no apparent correlation to point type or value. Bit pattern of the low nibble is unstable across reads of the *same point* in the same session, so this isn't quality-flag information the user can interpret reliably; treat it as opaque. A predicate that requires the literal `3F FF FF FF` will reject the F7 majority and produce false-offline classifications for most online devices — see "Property state sentinel" below.

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

### Panel-cached metadata vs live FLN data

A subtle and easily-missed distinction. Not all properties on a device behave the same way under FLN comm-fault:

- **Live FLN-sourced points** (ROOM TEMP, RM STPT DIAL, AUX TEMP, anything that's read from the device's I/O at request time) carry the comm-status flag described above. When the TEC is faulted, these come back with `comm_status=0x01` and a stale cached value.
- **Panel-cached configuration metadata** (APPLICATION number, descriptor strings, slot-table info — anything the panel knows because it commissioned the device, not because the device just told it) keeps reading successfully even when the TEC is fully faulted. APPLICATION reads on a #COM device return the configured app number with `comm_status=0x01` (in some firmware) or `comm_status=0x00` (in others, despite the device being dead) — it's unreliable as a liveness signal.

**The trap:** a scanner that uses APPLICATION-read-success as a "device exists / is registered" probe and treats that as "online" will silently mark every #COM-faulted device online, because APPLICATION is panel-cached and never fails for a commissioned device. Cross-checked against Desigo CC's own System Manager: when ROOM TEMP shows `#COM` for a device, APPLICATION still shows the configured app number with no fault indicator on that row — Desigo doesn't treat APPLICATION readability as a liveness signal either.

**Correct policy for a verifier:**
1. Read ROOM TEMP (or any other genuinely live-sourced point on the device).
2. If `comm_status=0x00` → online.
3. If `comm_status=0x01` → offline (#COM). Optionally read APPLICATION to surface the configured app number for display, but flag it as cached.
4. If ROOM TEMP doesn't exist on this device (some non-VAV apps), fall back to APPLICATION as a registration probe — but treat the result as "registered" not "online", and check `comm_status` on it too. APPLICATION-only confirmation is a weaker signal than ROOM TEMP confirmation.

### Observed stale-sensor signature: `-62.5°F`

A second, separate signal of sensor trouble is a repeated `-62.5°F` (or adjacent values like `-63.5`) across multiple unrelated points on the same device. This has been observed where one AHU's mixed-air / return-air / supply-air temperatures and all its zone temperatures reported `-62.5 DEG F` while adjacent AHUs on the same panel reported plausible values.

This isn't a protocol signal per se — the PXC returns these values with `comm_status=0x00` (healthy), so the comm-fault byte won't catch it. The pattern is that the underlying sensor or wiring is broken, but the PXC's input side is still reading valid analog-to-digital conversions of whatever is on the wire (typically open-circuit rail or a shorted input). Worth flagging in scanner output when many points on one device report the same implausible temperature — it indicates a hardware issue downstream of the PXC.

---

## Property state sentinel (partially unresolved)

The `3F FF FF X?` vs `00 00 00 00` pattern appearing in variants R1 vs R2 almost certainly corresponds to a quality-flag register — analogous to OPC's uncertain/good/bad triad, or IEC 61131's quality bits.

**Hypothesized meaning:** `3F FF FF FF` = "no specific quality flags set"; `00 00 00 00` = "explicit quality flags, all cleared"; the low nibble of the fourth byte (`F7`, `F0`, `FF`, ...) encodes individual flag bits.

**Empirical testing does not confirm a clear user-facing distinction.** A write-test against a point repeatedly returned either sentinel unpredictably, and the value was live in both cases. The parser surfaces the raw bytes as `property_state_hex` for users to spot patterns, but doesn't assign meaning.

### Sentinel-validation rule (the parser-critical part)

A naive parser that scans for `01 00 00` markers preceded by ASCII gets fooled by enumerate-response metadata. The robust filter is:

> Sentinel must be either `3F FF FF XX` (any 4th byte) **or** `00 00 00 00`.

The *first three bytes* are the lock; the fourth byte is opaque and must NOT be checked. Concrete reasons:

- A predicate that requires literal `3F FF FF FF` rejects the `3F FF FF F7` variant — which is the majority shape on at least some sites — and the parser silently returns `None` for those reads. Symptom: most live devices misclassified offline, no clear log signal.
- A predicate that omits the prefix entirely (just `01 00 00` + ASCII predecessor) false-matches the SHAPE A enumerate per-entry metadata block (`04 00 02 00 ...`, `03 00 02 00 ...`, etc. — second byte always `00`, third byte always `02`), producing fake floats like `3.6e-35` and phantom STALE tags pulled from whatever bytes happen to follow.

**Cross-opcode observation:** the same `3F FF FF FF` sentinel appears inside `0x0220` read requests (as a middle field of the compact request format) AND inside `0x4221` bulk-read requests (at a fixed offset). This suggests it's a generic "no filter / wildcard property" sentinel used across multiple opcodes, not a quality-flag register at all — it may just be "match any property state." This reframes the mystery but doesn't solve it. The `0x0220` request side appears to always send the literal `3F FF FF FF` (no `F7` variants observed in requests), so the request-side sentinel is genuinely a wildcard while the response-side sentinel carries opaque per-read state.

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
- `.DP`, `.ENB`, `.SITE`, `.NGT` — internal PPCL variables, typically booleans or small enums.
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
01 00 0A "VAV-12"         device TLV
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

A scanner with no prior knowledge of a site can still identify a PXC by exploiting the bouncer's distinct failure signatures. The bouncer validates two fields:

1. **Port-scan** a subnet for TCP/5033 listeners. Filter by Siemens OUI (`00:a0:03`, `00:c0:e4`) for higher confidence the listener is an Apogee panel.
2. **BLN attack** — try candidate BLN names (`P2NET`, site-prefix guesses, common patterns like `<SITE>BLN`, `<SITE>EBLN`) against a known PXC IP. A TCP RST means "wrong BLN"; a silent accept means "BLN correct, panel name wrong" (frame got past TCP layer, dropped at routing). The first silent-accept gives you the BLN. **The scanner identity in slot 4 does not need to be guessed** — any string works since the bouncer doesn't validate slot 4.
3. **Node attack** — with the BLN locked, try candidate panel names in slot 2 (`node1`, `node2`, ..., `NODE1`, ..., named variants). The first one that gets a CONNECT-ACK response is the PXC's actual node name. The case-correction leak (Surface 1) means a single lowercase guess like `node1` will return the canonical name (`NODE1`) in slot 4 of the response if the case-folded form matches.

This is the "cartesian attack" — up to `|BLN| × |Node|` probes in the worst case, but well-ordered candidate lists usually hit within a few dozen probes.

**Passive shortcut:** observing one `0x4634` frame from a real supervisor reveals the complete BLN topology (every panel name, every supervisor name, plus costs). One `0x4634` observation is worth hundreds of brute-force node attacks. Note: `0x4634` does **not** work as an active probe — panels TCP-RST inbound `0x4634` frames within milliseconds, treating them as a sender-restricted opcode (only the supervisor is allowed to push). See "0x4634 routing-table push — sender-restricted" in the field-testing findings section. Use `0x4634` as a passive surface only.

**Supervisor-name shortcut:** the `0x0050` status query (`00 50 01 00 04 "SYST" 23 3F FF FF FF`) returns the registered supervisor name list (e.g. `DCC-SVR`) **without requiring a full identity handshake** — it works inside any successful session bouncer pass. Sending `0x0050` after the CONNECT (before sending an IdentifyBlock) confirms whether the panel knows a supervisor and yields the supervisor name. The supervisor name is not strictly required for read-only scanning, but it's useful for cross-correlation with BACnet inventory or for impersonation testing.

---

## Identity-leak surfaces (cold-discovery shortcuts)

Multiple opcodes leak the panel's own canonical identity in their responses, even when the request fails. A scanner that wants to identify a panel without prior knowledge can chain these to extract every name it needs without exhaustive cartesian probing. Ranked by how cheaply they leak useful information:

### 1. Routing-header leak in **any** response (success OR error) — case-correction only

Every DATA-style response from a panel includes the panel's own canonical name in **slot 4 of the routing header**, regardless of whether the response carried success (`0x01`) or an error (`0x05`). The bouncer is **case-insensitive on the destination node name in slot 2 of the request** — sending `node1` (lowercase) gets a response routed back with `NODE1` (canonical case) in slot 4. So a scanner that has guessed even an approximately-correct node name receives the canonical form for free, in the very first response.

**Important scope clarification:** This leak fires only when slot 2 is a **case-variant of an existing panel name**. The bouncer's slot-2 check is otherwise strict — it routes only on names that case-fold to a name in the panel's known peer list. Slot 2 values that don't match any panel name (`*`, empty string, IP literal, generic words like `panel` or `BROADCAST`) get **silently dropped** with no leak. Field-tested with 8 such variants against a PME1252 panel: 8/8 silent drops, no responses. The leak is useful as a **case-correction primitive** (already-known approximate name → canonical name), not as a **discovery primitive** (unknown name → canonical name).

Worked example, observed verbatim in `<reference-pcap>`:

```
DCC sends:  00 "SITEBLN" "node1" "SITEBLN" "DCC-SVR" 09 61 ...
              dir   BLN    DEST     BLN       SOURCE   opcode

Panel replies:  05 "SITEBLN" "DCC-SVR" "SITEBLN" "NODE1" 00 03
                  dir    BLN      DEST          BLN     SOURCE  err=not_found
                                                         ^^^^^
                                                         canonical name leaked
```

The panel did not implement the request (returned `0x0003 not_found`) but still leaked `NODE1` as its canonical name. A passive observer on any conversation gets the panel's name from the very first response, regardless of payload. An active scanner that has correctly guessed even one approximately-correct node name (e.g. lowercase) gets the canonical form back. But a scanner sending arbitrary non-name strings gets silent drop.

**Empirical rate (case-correction only).** Across 6 captures totaling 39,820 P2 frames, 4,573 request/response pairs were checkable for the case-correction leak. Of those, 3,409 (74.5%) showed the lowercase→canonical-case correction (e.g. `node1` request → `NODE1` in slot 4 of the response); 1,164 (25.5%) returned an unrelated frame or didn't fire the leak. The 74.5% rate means a scanner that sends two distinct lowercase variants of a known-or-suspected panel name has ≈93.5% probability of harvesting the canonical name from at least one response.

### 2. `0x4640` IdentifyBlock success response

A successful response to a panel-bound IdentifyBlock request carries the panel's **full identity** as a TLV-encoded body. Sample from a successful exchange (note: this is a CONNECT response, not a DATA response — `slot 2 = "DCC-SVR"` bare form):

```
01                              direction byte = response (0x01)
"SITEBLN" "DCC-SVR" "SITEBLN" "NODE6"     routing (panel name in slot 4)
46 40                           0x4640 IdentifyBlock marker
01 00 05 "NODE6"                LP-string: panel's node name (matches slot 4)
01 00 03 "ACM"                  LP-string: site code
01 00 07 "SITEBLN"              LP-string: BLN name
00 01 01 00 00 00 00 00 00      9 bytes: separator + flags(01 01 00) + 5 zero pad
69 EA 3E F5                     4 bytes: Unix epoch timestamp
00 00                           2 bytes: session-id (panels send 00 00)
00                              1 byte: trailing null
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
ACM                             <-- site name
SITEBLN                         <-- BLN name
```

Different panels carry different application identifiers in the same field — observed values include `R911FTR`, `DIVV9`, `DIVV9-NAMED`, `APPLICATION`. These are the application-program names installed on each panel. **A scanner that hits `0x010C` against every IP on a subnet builds a complete asset inventory: firmware version, build date, application program, node/site/BLN — in one frame per panel.**

### 4. `0x0050` and `0x0606` lightweight probes

Both have `00 XX YY 01 00 04 "SYST" 23 3F FF FF FF` request shapes — the same `SYST`-scoped "give me the system" probe with different opcode bytes:

- **`0x0050`** response body: `01 00 04 "SYST" 23 3F FF FF FF [00 02] 01 00 0A "DCC-SVR" 01 00 00` — the registered supervisor name string. Plus the panel name in routing slot 4. So `0x0050` leaks **panel name + supervisor name** in one round trip. This is the opcode the doc has long marked as the "early shortcut" for cold discovery. Note that `0x0050` returns the supervisor name in its **bare form** (`DCC-SVR`, no `|5034` suffix), while `0x4640` IdentifyBlock returns the **listen-port form** (`DCC-SVR|5034`). Both forms are in use across the protocol — DATA frames and the routing-table-push body use the `|5034` form, CONNECT/ANNOUNCE and `0x0050` use the bare form. A scanner constructing a session identity should prefer `|5034` for DATA traffic.
- **`0x0606`** response body: empty (`00 00`) — pure ACK. Still leaks the panel name in routing slot 4.

Use `0x0050` when you want the registered supervisor name (e.g., for impersonation or cross-correlation); use `0x0606` when you only want a panel-presence ACK.

### 5. `0x4634` routing-table push — the topology-in-one-message goldmine

Documented above — a single passive `0x4634` observation reveals **the entire BLN topology**: every panel name, the supervisor name (with and without `|5034` suffix), the panel-default route name (`$paneldefault`), the site identifier (`101000`), the BMS registration (`SITE-BMS` / `SITE-BMS`), each with its 4-byte cost. One frame, complete reconnaissance. If you can passively listen on the BLN segment for ~1 minute, a real supervisor will publish this without you sending anything.

### 6. Panel-initiated CONNECT — the 10–16-second self-announcement

Each PXC opens a fresh outbound TCP/5033 connection to its configured supervisor every 10–16 seconds. Each connection sends, as its very first data frame, a fully-formed CONNECT (`msg_type` 0x2E for legacy or 0x2F for modern) with an embedded `0x4640` IdentifyBlock body — meaning each frame leaks `(BLN, supervisor_name, panel_name, site_code)` in plaintext.

Wire layout (verified, 88-byte legacy form):

```
00 00 00 58 00 00 00 2E <seq:4>           12-byte P2 header (msg_type 0x2E)
00 "SITEBLN" 00 "DCC-SVR" 00 "SITEBLN" 00 "NODE1" 00   routing slots
46 40                                              IdentifyBlock opcode
01 00 05 "NODE1"                                   LP-string: self-name
01 00 03 "ACM"                                     LP-string: site code
01 00 07 "SITEBLN"                                 LP-string: BLN
01 01 00 00 00 00 00 00 ...                        fixed pattern + tail
```

Empirical cadence across the corpus: 9 distinct PXCs each emit 95–100 announcements over a 25-minute capture, with mean inter-announcement interval 15.5 s (range 14.0–24.0 s, occasional outliers up to 35–45 s). On a different 24-minute capture targeting only 5/9 panels, the cadence tightens to a near-exact 10.0 s interval per panel — suggesting the cadence varies by firmware family or supervisor configuration. In either case, a passive observer on the supervisor↔PXC channel sees every panel self-identify within a minute.

This complements surface 5: surface 5 gives you the entire topology in one frame every 60 s; surface 6 gives you per-panel identity in many frames, every 10–16 s. They serve the same function (passive identity recovery) at different granularities. Same vantage requirement — the scanner has to be on a path that sees the supervisor's TCP/5033 traffic to/from the panels.

### 7. BACnet Who-Has broadcasts — site-code extraction from BACnet plane

Apogee Automation Stations periodically issue standard BACnet `Who-Has` broadcasts (Unconfirmed-Request, service `0x07`) to subnet broadcast (`x.x.x.255:47808`) carrying the object name they're searching for. Because BACnet sites overwhelmingly use site-prefixed object naming conventions (`<SITE>_RM<number>` for room points, `<SITE>.<subsystem>` for system points), these broadcasts carry site-prefixed strings in plaintext. Any host on the segment receives them — they're directed broadcasts, no special vantage required.

Verified across three BACnet-bearing captures in the corpus:

| Capture | Span | Who-Has broadcasts | Unique names | Site-prefixed |
|---------|-----:|-------------------:|-------------:|--------------:|
| `<reference-pcap-1>` | 396 s | 378 | 15 | 12 |
| `<reference-pcap-2>` |  82 s |  48 |  8 |  5 |
| `<reference-pcap-3>` | 204 s | 119 | 15 | 12 |

Wire format of the broadcast (verified frame, sanitized):

```
BVLC:    81 0B 00 1E                (Original-Broadcast, 30 bytes)
NPDU:    01 20 FF FF 00 FF          (ver=1, ctrl=0x20: DNET=0xFFFF broadcast)
APDU:    10 07                       (Unconfirmed-Request, service=0x07 Who-Has)
         09 00                       (context-tag 0: low instance limit = 0)
         1B 3F FF FF                 (context-tag 1: high instance limit = max)
         3D 0A 00                    (context-tag 3: objectName, length 10, charset 0)
         "ACM_RM416"                 the leaked string
```

A scanner that wants the site code without sending any packet binds to UDP/47808, filters for BVLC `0x0B` + APDU `10 07`, and extracts the context-tag-3 objectName from each frame. Apply regex `^([A-Z]{2,6})[._]` to the captured names; the most-frequent prefix is the site code. In all three corpus captures, the site code surfaced within the first 10 seconds of capture.

This is BACnet operating exactly as designed — the protocol broadcasts queries-by-name, and operators deploy their sites with prefixed naming conventions. The leak is structural rather than implementation-specific. It complements surfaces 1–6: those operate inside the P2 plane (TCP/5033) and require P2 frame visibility, while surface 7 operates entirely on the BACnet plane (UDP/47808 broadcast) and is reachable by any host on the local segment.

### 8. P2-over-BACnet transport (passive — SPAN required)

**Vantage caveat: this surface requires SPAN/mirror access to the supervisor↔PXC unicast traffic. Unprivileged observers on the segment do not see these packets.**

Apogee uses BACnet/IP `Confirmed-Private-Transfer` (service `0x12`) with vendor-id `7` (Siemens) and service-number `0x01FF` as a transport for tunneled P2 frames between Desigo CC supervisors and the higher-level Automation Stations. The body of each CPT carries a complete P2 frame (routing slots + IdentifyBlock body) in plaintext, with `msg_type` `0x2D` — a value used exclusively for the BACnet tunnel and not seen on TCP/5033. Wire layout:

```
BVLC:        81 0A 00 6C                       Original-Unicast-NPDU
NPDU:        01 04                              expecting reply, no routing
APDU header: 02 05 29 12                       Confirmed-Request, service=0x12 (CPT)
CPT params:  09 07                              vendor-id tag: Siemens=7
             1A 01 FF                           service-number tag: 0x01FF
             2E                                 opening tag for tunneled parameter
P2 frame:    00 00 00 5B 00 00 00 2D ...        msg_type 0x2D, full P2 routing
             routing: BLN / dst-instance / BLN / src-instance
             body:    46 40 ... IdentifyBlock with site code, BLN
```

The names in the routing slots use BACnet device-instance numbers (`9997`/`9998` for Desigo CC supervisors, `1xx000` for Automation Stations) rather than the NODE-style names used on TCP/5033. The two planes use **distinct BLN names** (`SITEBLN` for TCP/5033, `SITEBACBLN` for the BACnet tunnel) but share the same site-code prefix.

This is documented here for completeness of the protocol picture and because it explains why captures of UDP/47808 sometimes show P2-shaped payloads that don't decode as standard BACnet. It's a transport observation, not a discovery primitive — the unicast nature means it offers no advantage over surfaces 5/6 for an unprivileged observer.

### Cold-discovery flow chart, optimized

Putting these together, the most efficient cold-discovery sequence depends on what network vantage the scanner has:

**If the scanner is on a path that sees supervisor↔PXC TCP/5033 traffic** (e.g., on the supervisor host, on a SPAN port, on a flooding/unmanaged switch, or inline on the BLN segment):

1. **Passive listen for 0x4634 or panel-initiated CONNECT** (surfaces 5 + 6). Either fires within 60 s — surface 5 gives full topology in one frame, surface 6 gives per-panel identity per ~10–16 s. Done; you have everything.

**If the scanner is just another host on the local segment** (no path visibility into supervisor traffic) — the typical "non-supervisor vantage" case:

1. **ARP sweep + Siemens OUI filter** to identify Apogee Automation Station candidates. OUIs `00:a0:03` (legacy generations) and `00:c0:e4` (newer generations) cover the Siemens BAS family.
2. **TCP/5033 reachability probe** to rule out non-P2 endpoints. Open + immediate close. RST = no listener, no useful info; SYN-ACK = candidate alive on P2 plane.
3. **Passive listen UDP/47808 for BACnet Who-Has** (surface 7). Site-code prefix typically surfaces within 10–60 s. No packets sent. Field-verified to work from any segment-local host.
4. **BACnet ReadProperty on each BACnet-discoverable Siemens device** — `Who-Is` then `ReadProperty(Device:N, object-name)` for each I-Am respondent. Field-verified: returns the BACnet inventory and equipment tags, but **NOT** the P2 panel name. See `BACnet vs P2 naming` section — these are separate namespaces.
5. At this point you have the segment, the site code, and the BACnet inventory, but you do **not** have P2 panel names for legacy P2-only panels.

**Important field-testing finding on Surface 1.** Surface 1 (case-correction leak) does NOT close the gap from BACnet-only inventory to P2 panel names. Field testing against PME1252 V2.8.10 panels with eight non-name slot-2 variants (`*`, empty, `0`, `?`, IP literal, `panel`, `BROADCAST`, `unknown`) got 8/8 silent drops — no canonical name leak. The bouncer's slot-2 check is strict and routes only on known panel names. Surface 1 fires only when the slot-2 value case-folds to a real panel name; it is a normalization primitive, not a discovery primitive.

**What this means in practice:** for legacy P2-only panels, no single-frame cold-discovery primitive is available to a non-supervisor host. To get a P2 panel name, the scanner must either:

- (a) be configured with a naming convention (typical Siemens convention is `NODE<n>` with `n` as a small integer), or
- (b) get supervisor-host or SPAN vantage and use surfaces 5/6 directly.

Option (b) is operationally cleanest if the vantage is available. Option (a) is cleanest if a naming convention is known.

**For BACnet-bridged Siemens devices** (PXCC/PXCM compact and modular controllers exposed via BACnet, e.g., the `1xx000`-instance devices typical of Siemens commissioning):

- BACnet Method C (Who-Is + ReadProperty) gives complete site fingerprint plus equipment context (e.g., `AHU-1`, `EXHAUST FANS`, `10TH FLOOR DXRS`).
- These BACnet-side controllers may be a **different inventory** than the P2 panels. At the reference site, 0 of 8 P2 panels appeared in BACnet I-Am responses — the BACnet plane and P2 plane were completely disjoint inventories.
- For HVAC tooling that just needs to identify equipment by building system, BACnet Method C is sufficient. For P2 session work, BACnet provides no useful bridge.

### Practical caveat: case-sensitivity for the BLN name

The bouncer's BLN check appears to be **case-sensitive**: `SITEBLN` works, `sitebln` issues a TCP RST. The node-name check is case-insensitive (lowercase variants get routed-and-canonicalized). Treat BLN as exact-match-or-RST when iterating; treat node name as case-folded.

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
- **Panel persistent reconnect side effect — full mechanism** — sending an initial frame with `msg_type = 0x2E` to a panel from a non-panel source registers the source IP as a runtime peer; the panel will then persistently call back to that IP every ~16 seconds with `flags = 01 01 01` (the panel→runtime-peer marker). Verified at the reference site against PME1252 V2.8.10. This is documented protocol behavior — `0x2E` CONNECT is the panel-online-announcement message — not a parser bug. Read-only scanners that emulate DCC by sending `msg_type = 0x33` with inner `0x4640` IdentifyBlock as the initial frame do not trigger this, verified by extensive production scanning at the reference site. Open: whether responding to the panel's CONNECT with a `0x0100` SystemInfo causes operational data flow (COV, alarms); whether modern PME1300 panels exhibit the same behavior; whether vendor tooling can inspect/clear the registration; whether any deregistration opcode exists.
- **Modern PME1300 panel behavior** — the side effect above has only been observed on a PME1252. Whether modern PME1300 panels exhibit the same edge case is untested.
- **Whether modern PME1300 panels share legacy peer-state behavior** — only legacy PME1252 has been tested for the side effect. Worth verifying against NODE11 (PME1300 V2.8.18) at the reference site.
- **Cold-discovery from non-supervisor vantage for legacy P2-only panels** — no zero-cost single-frame primitive has been found. Tested negatively: arbitrary slot-2 strings (silent drop), active 0x4634 query (TCP RST), BACnet ReadProperty (returns BACnet name not P2 name; legacy panels often don't appear in BACnet at all). Open paths: Siemens proprietary BACnet properties (vendor-id 7) untested; UDP discovery protocols other than BACnet untested.

---

## References and corrections to common misunderstandings

### "The heartbeat uses opcode `0x4640`"

Partially misleading. `0x4640` is an **identity block marker** that can appear in CONNECT (0x2E), ANNOUNCE (0x2F), inside DATA (0x33) bodies, and inside HEARTBEAT (0x34) bodies. It is not specific to any one message type. Operation opcodes like `0x0100`, `0x0271`, `0x0274`, `0x0986` also appear inside both 0x33 and 0x34 bodies.

### "The routing header puts destination first, source second"

True for all message types. An earlier revision of this doc claimed CONNECT (`0x2E`) and ANNOUNCE (`0x2F`) reversed the ordering (sender in slot 2, recipient in slot 4); the two-node validation capture's 854 CONNECT/ANNOUNCE frames — covering both panel→supervisor requests and the matching supervisor→panel responses — all follow the destination-first convention identical to DATA/HEARTBEAT. Supervisor responses are the cleanest evidence: IP src = supervisor and slot 4 = supervisor, so slot 4 holds the source even when the supervisor is the one transmitting. The IdentifyBlock body's first TLV (the sender's self-name) consistently agrees with slot 4. Parsers can safely assume `slot 2 = destination, slot 4 = source` for every message type. See *Routing header → Name ordering* for the full evidence.

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

## Field-testing findings (active scanner build-out)

These notes come from active probing against a live PME1252 panel (NODE6) during scanner development. The corpus pcaps were sufficient to document the wire format passively; field testing surfaced the things that matter when *you* are the one constructing frames rather than parsing someone else's.

### The bouncer's silent-drop failure mode

When the bouncer rejects a frame, the failure is not always a TCP RST. Two distinct rejection paths observed:

1. **Immediate TCP RST** — fires when the BLN check fails or the frame is structurally malformed in obvious ways (length field mismatch, etc.). Happens within the same RTT as the SYN-ACK.
2. **Silent drop after TCP-layer ACK** — fires when the frame parses well enough to be accepted by the transport layer but the session manager rejects it. The panel sends a TCP ACK confirming receipt of the bytes, then never produces a response. Connection idles until the scanner times out.

The silent-drop path is easy to misdiagnose as a network problem. It's actually a session-state rejection. Verified causes for silent drops on legacy (PME1252) panels:

- **First frame on a fresh TCP connection is `0x33` DATA-LEGACY without a prior `0x2E` CONNECT in the session** — bouncer accepts the bytes at TCP layer but the session manager has no session for this peer, drops silently. (DCC actually does send `0x33` as a fresh-connection first frame in some captures, which contradicts this — see "0x33 as fresh-connection first frame" in *What's still unknown*.)
- **IdentifyBlock body shorter than expected** — the body trailer must be the full 16 bytes; truncated trailers (e.g., 8 bytes) are silently dropped.
- **Wrong slot 4 form for the msg_type** — slot 4 must be the bare supervisor name (e.g., `DCC-SVR`) in CONNECT frames and the listen-port form (e.g., `DCC-SVR|5034`) in DATA frames. Reversing this caused silent drop in testing.
- **Slot 2 doesn't case-fold-match a known panel name** — the bouncer requires slot 2 to be a name it recognizes (case-insensitive match). Sending arbitrary placeholders like `panel1` or `node1` to a panel that's actually named `NODE6` causes silent drop. The case-correction leak (Surface 1) only fires when the case-folded name does match an existing panel — it's a normalization step, not arbitrary-name acceptance.

### Bouncer enforcement scope (verified empirically)

End-to-end testing against a live PME1252 panel established that the bouncer enforces exactly two checks:

1. **BLN must match exactly** (case-sensitive). Wrong BLN → TCP RST.
2. **Slot 2 must case-fold-match a known panel name.** Wrong panel name → silent drop.

Slot 4 (the source identity), the IdentifyBlock self-name TLV, and the IdentifyBlock site/BLN body fields are **NOT enforced** beyond consistency with each other. A scanner can identify itself as any string (e.g., `p2-scanner`) and the panel will accept the connection and respond with full identity blocks. **A read-only scanner does not need to impersonate the supervisor** — it just needs to know the BLN and a panel name to establish a session.

Verified by direct comparison of two probes against the same panel (NODE6 at the reference site):
- `slot 4 = "DCC-SVR"` (impersonating supervisor) → 86-byte response, then full SystemInfo dump
- `slot 4 = "p2-scanner"` (arbitrary scanner name) → 86-byte response with identical structure

Both probes received the same 86-byte CONNECT response (opcode `0x0100`, embedded `NODE6`/`SITE`/`SITEBLN` identity strings). The panel made no distinction.

### Panel CONNECT response opcode varies by firmware

The panel's CONNECT response opcode is **not always `0x4640`**. Observed against live panels:

- **PME1300 modern firmware** — responds with `0x2E` body containing `0x4640` IdentifyBlock (matches DCC↔NODE5 captures in the corpus).
- **PME1252 V2.8.10 (Oct 2013 build)** — responds with `0x2E` body opcode `0x0100` (legacy SystemInfo response format), with identity strings still embedded but in a different layout than `0x4640`.

A scanner that strict-matches on opcode `0x4640` for CONNECT responses will fail to recognize the legacy panel's response shape. Robust dispatch: any response inside a `0x2E`/`0x2F` frame on a fresh TCP connection should be treated as a CONNECT-ACK regardless of inner opcode, with identity-string extraction by ASCII pattern rather than fixed offsets.

### Frame length field calculation (corrected)

The 4-byte length field at offset 0 of every frame counts **the entire frame including the length field itself**. Verified by direct measurement: a 93-byte frame on the wire carries length value `0x5D = 93`. A scanner that computes `length = 8 + payload_size` (excluding the length-field's own 4 bytes) sends frames whose stated length is 4 short of actual, which the bouncer immediately rejects with TCP RST. Correct calculation: `length = 12 + payload_bytes` (header is 4+4+4 = 12 bytes; payload is routing slots + body).

### Sequence number field (offset 8–11)

Real Desigo CC frames use a session-monotonic sequence number that increments per-frame. Across one captured session, observed values ranged from `0x00018fec` to `0x00019008` over ~10 frames in 30 seconds (so ~2-3 increment per frame, occasionally retransmitted with the same value). A scanner that sends `0x00000000` for seq is flagged behavior — real DCC is never observed with seq=0. The bouncer may or may not validate this strictly, but a scanner sending non-zero "plausible" values blends in better. Recommend starting at a random 24-bit value and incrementing per frame.

### Connection vantage matters for cold-discovery

A scanner running on the supervisor host itself sees DCC↔panel traffic natively (no SPAN required) — this is a *privileged* vantage equivalent to "owning the supervisor." A scanner running on an arbitrary host on the same VLAN sees only broadcast traffic (Surface 7) and its own active probes. Most cold-discovery surfaces (5, 6) require the supervisor-host or SPAN vantage. Tools that claim to work "without SPAN" need to be tested from a non-supervisor host to verify the claim.

**Field-test result, reference site:** A 90-second passive listen with `scapy.sniff` from a non-supervisor host (a regular workstation IP) on the HVAC VLAN observed 0 Surface 5 frames, 0 Surface 6 frames, and 14 Surface 7 broadcasts. Surface 7 (BACnet Who-Has) works from any segment-local host as expected. Surfaces 5 and 6 (P2 unicast TCP/5033 traffic) were not visible. The site's network is properly switched — DCC↔panel unicast traffic does not reach segment hosts.

An earlier corpus capture from the same VLAN that DID contain DCC↔panel frames was, on confirmation with the site operator, captured on the Desigo CC server itself, not on a separate workstation. That capture is consistent with privileged-vantage observation; it does not indicate that an unprivileged host can see Surfaces 5/6.

The supervisor-host or SPAN-port requirement for Surfaces 5 and 6 is binding on properly-segmented networks. Tools that need Surface 5/6 visibility should be deployed on the supervisor itself, on a SPAN port, or on a flooding/unmanaged switch.

### Panel persistent reconnect side effect — `msg_type = 0x2E` registers a runtime peer

**This finding's framing has been substantially revised after observing that production read-only scanners that emulate Desigo CC (using `msg_type = 0x33` with inner `0x4640` as the initial frame) do not trigger this behavior across many panels at the reference site, while a verification probe tool (using `msg_type = 0x2E` as the initial frame) did trigger it.** The corrected interpretation: this is documented protocol behavior that depends on the initial CONNECT envelope's `msg_type`, not a generic "any CONNECT triggers it" vulnerability.

#### Initial-frame `msg_type` distinguishes role

The protocol uses two different envelope types for the initial frame on a fresh TCP session, and the panel treats them differently:

- **Initial frame `msg_type = 0x33` (DCC-style: `0x33` envelope with inner `0x4640` IdentifyBlock)** — supervisor-to-panel pattern. Panels respond to reads/CONNECTs but do not register the source as a peer. This is what real Desigo CC sends at the reference site, and what well-behaved read-only scanners send. The doc's *Connection-handshake modes* table calls this "the alternative `0x33` + inner `0x4640` initiation path" of the Mode A flow. **Verified safe across many panels at the reference site over an extended period of production scanning.**

- **Initial frame `msg_type = 0x2E` (panel-style: `0x2E` CONNECT carrying `0x4640` IdentifyBlock directly)** — panel-to-supervisor pattern. This is the message a real panel sends to its real supervisor when the panel comes online. The doc's *Connection-handshake modes* table calls this the textbook "Mode A: Standard handshake" form. The panel that receives a `0x2E` CONNECT from a non-panel-named source past the bouncer treats it as a peer announcing itself, records the source IP as a runtime peer, and persistently calls back to that source on a 16-second cadence. **This is by-design announce-then-supervise protocol behavior, not a parser bug.**

The bouncer's check is purely on BLN + slot 2 routing; it does NOT validate that the initial-frame `msg_type` matches the sender's actual role. A scanner that sends `msg_type = 0x2E` from an arbitrary IP can establish itself as a "panel" the receiving panel will faithfully poll forever, and a scanner that sends `msg_type = 0x33` from an arbitrary IP can read points as a "supervisor" without leaving any peer-table residue. The initial-frame msg_type encodes which role is being claimed.

#### Reference site state — what created it

A PME1252 V2.8.10 panel (NODE6) at the reference site entered this registered-peer state because a verification probe tool deliberately used `msg_type = 0x2E` CONNECTs to characterize the panel's response to panel-style frames. The probe at 20:04:07 UTC on 2026-04-30 had:

- `msg_type = 0x2E`
- `slot 1 (BLN) = SITEBLN` (passes bouncer)
- `slot 2 (target) = "node6"` (case-folds to real panel name, passes bouncer)
- `slot 4 (source identity) = "scanner-verify"` (arbitrary scanner identity)
- Embedded `0x4640` IdentifyBlock with `flags = 01 01 00`, 16-byte trailer

The panel correctly interpreted this as a peer named `scanner-verify` announcing itself, registered the source IP, and began the standard panel-supervisor heartbeat (one CONNECT every ~16 seconds). The state persisted for ~18 hours of continuous SYN attempts (verified across multiple captures) and was cleared by power-cycling NODE6, after which a follow-up capture showed zero outbound SYN attempts to the scanner IP and normal Desigo↔NODE6 traffic resuming immediately. **The registration is in volatile memory** — power cycle wipes it; no flash/NVRAM persistence.

The earlier probe-impersonate at 20:03:40 (also `msg_type = 0x2E`, also bouncer-passing, but with `slot 4 = DCC-SVR` and `flags = 01 01 01`) likely *also* registered something, but the registration that actually drove subsequent callbacks is keyed on `scanner-verify`. Whether multiple registrations exist simultaneously isn't characterized — the panel's outbound CONNECTs only address `scanner-verify`, suggesting either probe-self overwrote the entry or the probe-impersonate registration is not actively driving callbacks.

#### Frame the panel sends to a registered peer

When a registered peer accepts the panel's TCP connection, the panel sends an 88-byte `0x2E` CONNECT frame:

```
Length: 88 bytes (0x00000058)
msg_type: 0x2E (CONNECT)
sequence: monotonically incrementing per emitted frame
direction: 0x00 (request)

Routing slots:
  slot 1 (BLN):              SITEBLN
  slot 2 (target):           scanner-verify          ← REGISTERED PEER NAME
  slot 3 (BLN echo):         SITEBLN
  slot 4 (source identity):  NODE6               (panel's own name)

Body (42 bytes):
  opcode:    0x4640 (IdentifyBlock)
  TLVs:      ["NODE6", "SITE", "SITEBLN"]
  trailer (16 bytes):
    separator   = 00
    flags       = 01 01 01     ← role flag = 0x01 (panel→runtime-registered peer)
    reserved    = 00 00 00 00 00
    timestamp   = current Unix epoch
    session_id  = 00 00
    null        = 00
```

This is the panel's "I'm here, who are you?" announcement directed at its registered peer. Real panels send the same frame to their real supervisors during normal operation; the only difference is the role flag (`01 01 00` to configured supervisors, `01 01 01` to runtime-registered peers).

#### Panel behavior with a held-open connection

A second listener test (extended-listen variant) held each accepted connection open for 30 seconds without sending any P2 response. The panel:

- Sent the CONNECT frame within ~50ms of TCP handshake completion
- Re-sent the CONNECT frame every ~14-15 seconds while the connection stayed up, with each retransmission carrying a fresh timestamp and incrementing sequence number
- Did not send keepalives or any other frame type
- Did not time out the connection from its side
- ACKed the listener's eventual FIN and immediately sent RST (no graceful close from panel side)

Application-layer retransmit cadence (~14-15s) is slightly tighter than TCP-level connection-attempt cadence (~16s) — consistent with the application timer not waiting through TCP backoff after a successful connection. The panel will evidently retransmit its CONNECT indefinitely until the connection drops, the supervisor responds with `0x0100`, or the panel reboots.

#### What's NOT happening

- **No operational data leaks to a passive listener.** The panel sends only the CONNECT identity announcement; it does not push COV updates, alarm reports, or any other operational data without first receiving a `0x0100` SystemInfo response from the listener. The "what does the panel push to a runtime-registered peer that responds properly?" question (Option C in earlier analysis) remains untested.
- **No supervisor session is hijacked.** Real DCC's session continues normally throughout. The runtime-registered peer is tracked in addition to the configured supervisor, not in place of it.
- **No `0x4634` routing-table entry is created.** The runtime-registered peer is recorded in some internal panel state but does NOT appear in the panel's published `0x4634` topology pushes. Other systems (other panels, BACnet routers) have no visibility into the registered peer.

#### Cleanup

- **Power cycle is the verified cleanup.** A power cycle of NODE6 cleared the registration completely — confirmed by post-reboot capture showing zero outbound SYN attempts to the previously-registered scanner IP and normal Desigo↔panel traffic resuming. The registration is in volatile memory only. No P2 opcode for removing a peer entry has been identified; whether such an opcode exists is unknown.
- **Accept-and-close does NOT clear the state.** Verified by Option A test: the panel resumes its 16-second cadence after a closed connection.
- **Changing the scanner's IP is a useful workaround for the noise from the registered peer's perspective**, but the panel will continue firing SYN attempts at the old IP indefinitely until reboot. If a different host later inherits the old IP, that host will start receiving the panel's SYN attempts and may not understand why.

#### Implications for protocol-aware scanners

**Use the `0x33` + inner `0x4640` initiation path** (with `0x34` fallback for modern dialects). This is what real Desigo CC sends and what well-behaved read-only scanners should send. It causes the panel to respond to reads without registering the scanner as a runtime peer.

**Avoid sending `msg_type = 0x2E` as the initial frame on a fresh TCP session unless you specifically want to be tracked as a peer.** A `0x2E` initial frame from a non-panel source is interpreted as a panel announcing itself — the panel will register your IP and call back persistently. There's no documented way to "deregister" without panel reboot.

A production read-only scanner used at the reference site sends `msg_type = 0x33` with inner `0x4640` IdentifyBlock as its initial frame and has scanned panels at the reference site over extended periods without triggering this state. This is empirical confirmation that the protocol's role discrimination works correctly when scanners use the appropriate envelope.

#### Why this matters for the protocol's security model

The corrected framing is narrower than earlier doc versions claimed. The protocol's authentication model is "BLN+slot 2 = network-segment trust"; once past the bouncer, a sender's claimed role (via the initial-frame msg_type) is taken at face value. This means:

- An attacker on the HVAC VLAN with the BLN can read points from any panel by emulating DCC (initial frame `msg_type = 0x33` + inner `0x4640`). This is the practical concern for unauthorized monitoring.
- An attacker can also register themselves as a runtime peer (initial frame `msg_type = 0x2E`), which causes the panel to call back persistently. Without responding as a real supervisor, all the attacker gets is panel-identity disclosure (name, BLN, site) — already obtainable via Surface 7 BACnet broadcasts. Whether further data flows if the attacker responds with `0x0100` is untested but plausible.
- Neither requires defeating any authentication. The security model is "VLAN access = trust," same as virtually every other building automation protocol of this era.

For practical site security, the takeaway is: protect the HVAC VLAN. The protocol's read surface is open to anyone who can route to it. The runtime-peer registration is not a separately exploitable vulnerability beyond the read surface — it's just the supervisor-tracking mechanism showing through to anyone who can claim to be a panel.

### 0x4634 routing-table push — sender-restricted

Active probe testing established that **panels reject inbound `0x4634` frames with TCP RST**, even from session-holders with valid BLN and panel name. Specifically: a session was established to NODE6 successfully (CONNECT got 86-byte response), but sending `0x4634` as the opcode of a subsequent `0x33` DATA frame triggered an immediate TCP RST from the panel (3 millisecond response time).

This is distinct from:
- **Silent drop** (slot 2 not recognized — the routing layer drops with no response)
- **Error response** (opcode recognized but request rejected — panel sends `0x05 0x00 0x03` error frame)

The panel apparently classifies `0x4634` as a sender-role-restricted opcode: only the supervisor is allowed to send it (as part of normal topology pushes). Anyone else attempting it gets the connection killed.

**Implication:** `0x4634` is not viable as an active cold-discovery query primitive. It's strictly a passive observation surface (Surface 5), only available to a vantage that sees the supervisor's outbound traffic.

### BACnet vs P2 naming — two distinct namespaces

A subtle but important finding. Siemens Apogee panels live on two protocol planes simultaneously (BACnet/IP on UDP/47808 and P2 on TCP/5033), and they have different names on each. Verified by direct comparison at the reference site:

| Panel | BACnet object-name | BACnet description | P2 canonical name |
|-------|---------------------|---------------------|--------------------|
| BACnet-capable PXCC | `SITE_PXCC101000` | (same as object-name) | not present in P2 inventory |
| BACnet-capable PXCC | `SITE_PXCC102000` | `EXHAUST FANS` | not present in P2 inventory |
| Legacy P2-only panel | (not in BACnet — PME1252 V2.8.10) | n/a | `NODE6` |
| BACnet-capable PXCM | `SITE_PXCM103000` | `AHU-1` | not present in P2 inventory |
| BACnet-capable PXCC | `SITE_PXCC104000` | `10TH FLOOR DXRS` | not present in P2 inventory |

The BACnet name is descriptive and includes the instance number; the P2 name is short and canonical (`NODE<n>`). They're **not** simple transformations of each other.

The BACnet `description` property (property ID 28) was field-tested as a possible bridge between namespaces. The result: descriptions contain **mechanical/equipment tags** (e.g., `AHU-1`, `EXHAUST FANS`, `10TH FLOOR DXRS`) — useful for HVAC asset management but not for P2 routing. The description does not expose the panel's P2 canonical name.

**Most important finding from the cross-protocol test at the reference site: the BACnet inventory and the P2 panel inventory are completely disjoint.** Of 8 confirmed P2 panels (8 PME1252 + 1 PME1300), 0 appeared in BACnet I-Am responses. Of the BACnet-discoverable Siemens devices found, none responded to P2 CONNECT on TCP/5033. The two planes have distinct device populations even though both carry the same site-code prefix in their naming conventions.

**Implication for cold-discovery:** The BACnet ReadProperty primitive (Method C in the runbook) reliably gives you (a) the site code, (b) the BACnet device inventory, and (c) the panels' mechanical/equipment context. It does **not** give you the P2 panel name needed for slot 2 of a P2 CONNECT.

To go from BACnet name to P2 name, three approaches remain plausible:

1. **Siemens proprietary BACnet properties** (vendor-id 7) that may expose P2 identity directly — not yet tested.
2. **Cross-correlate via passive observation** — observe both BACnet and P2 traffic from the same source IP and match by timing/structure (requires Surface 5/6 vantage).
3. **Probe the panel's P2 plane with candidate names** seeded from convention (e.g., known patterns like `NODE<n>` for panels in the `1xx000` BACnet instance range, where `n` may correlate to the instance number).

For panels that don't speak BACnet at all (PME1252 V2.8.10 generation, like the reference site's `NODE6`), the BACnet path is unavailable and discovery must use Surface 5/6 passive observation (with appropriate vantage) or active P2 probing.

### Example: BACnet inventory extracted via cold-discovery

Field testing at the reference site produced this verified inventory using only the BACnet primitives — Method C + description ReadProperty — from a non-supervisor host on the HVAC VLAN. IPs are sanitized; the layout is what a real cold-discovery run produces:

| Role | BACnet instance | Object name | Equipment context |
|------|-----------------|-------------|-------------------|
| Primary supervisor | 9997 | `DCC-SVR` | Primary Desigo CC server |
| Secondary supervisor | 9998 | `Desigo CC 9998` | Secondary Desigo CC workstation |
| Compact PXC | 101000 | `SITE_PXCC101000` | (no equipment description) |
| Compact PXC | 102000 | `SITE_PXCC102000` | Exhaust fans controller |
| BACnet/MSTP router | 103100 | `SITE_HV1_BACROUTER` | BACnet/IP→MS/TP router for an air handler |
| Modular PXC | 103000 | `SITE_PXCM103000` | Air handler controller |
| Compact PXC | 104000 | `SITE_PXCC104000` | Floor-N DXRS controller |
| Modular PXC | 106000 | `SITE_PXCM106000` | Floor DXRS controller |
| Modular PXC | 112000 | `SITE_PXCM112000` | Multi-floor DXRS controller |

This gives a scanner enough to map building IPs to building systems using BACnet alone — useful for technician tooling. It does **not** give the P2 panel names needed to establish P2 sessions on the P2 plane.

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
| **BACnet Method C cold-discovery** | **Who-Is + ReadProperty** | **✓ Verified at the reference site: returns BACnet inventory + equipment tags + site code prefix** |
| **Bouncer slot-2 strictness** | **8 non-name variants** | **✓ Verified at the reference site: 8/8 silent drops, no leak** |
| **Active 0x4634 query** | **Inside 0x33 DATA frame** | **✗ Verified rejected: panel TCP-RST within 3ms** |
| **Surface 7 BACnet broadcast (any vantage)** | **scapy passive listen UDP/47808** | **✓ Verified at the reference site: 14 broadcasts in 90s from non-supervisor host** |
| **Surfaces 5/6 (non-supervisor vantage)** | **scapy passive listen TCP/5033** | **✗ Verified NOT visible: 0/0 frames from non-supervisor host on properly-segmented network** |
| **Initial-frame `msg_type = 0x2E` registers source as runtime peer** | **Inbound `msg_type = 0x2E` as initial frame on a fresh TCP session, with valid BLN + slot 2 case-folding to a real panel name, registers source IP as a runtime peer; panel calls back every ~16s with `flags = 01 01 01`; persists across sessions until reboot** | **△ Verified by listener test against NODE6 (PME1252 V2.8.10); production scanners using `msg_type = 0x33` + inner `0x4640` initial frame do NOT trigger this; this is documented protocol behavior, not a vulnerability per se** |

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

## Point catalogs — what the protocol does and doesn't give you

This document specifies the wire protocol — how to frame messages, address panels, send a read request, parse a response. It does not provide a **point catalog**: the metadata needed to turn raw protocol primitives into named, typed, useful point reads.

A working scanner needs both. The protocol tells you *how* to read a point; the catalog tells you *which* points exist, *what* they're named, and *what data type* to expect. Without the catalog, you can issue P2 reads but you don't know what to ask for or how to interpret what comes back beyond raw bytes and inferred shape.

### Two distinct catalog problems

It's worth separating two things that often get conflated:

**1. Vendor catalog — TEC application definitions.** Siemens TEC controllers run pre-built "applications" (numbered, like `2032`, `4031`, `6017`) loaded at the factory or by the integrator. Each application has a fixed slot layout: slot 1 = `CTLR ADDRESS`, slot 4 = `RM TEMP`, slot 41 = `DO 1`, etc. This layout is **portable across sites** — application 4031 has the same point layout in any building. The reading workflow is:

1. Read the device's `APPLICATION` property → returns the application number (e.g., `4031`)
2. Look up the application number in the vendor catalog → get the slot-by-slot point layout
3. Issue the actual point read using slot number or point name from the catalog

The vendor catalog is large but bounded — Siemens has shipped on the order of 800 TEC applications across the product line. A complete catalog covers most TECs the scanner will ever encounter.

**2. Site catalog — per-installation configuration.** This is the data that varies building-to-building: BLN network name, scanner identity, panel-name-to-IP mapping, any custom application numbers used by the integrator, custom point names for user-defined panel applications. This is necessarily site-specific.

Most published BAS scanners ship the vendor catalog as a static data file alongside the code (since it's portable) and consume the site catalog as user-provided config (since it's not).

### What's in each catalog

**Vendor catalog** (per-application, per-slot):
- **Slot number** (1-99) — the addressing handle on the wire
- **Point name** — e.g., `RM TEMP`, `OCC HTG STPT`, `DAMPER POS`
- **Point type** — `analog_ro` / `analog_rw` / `digital_ro` / `digital_rw` — needed to dispatch the right value-extraction path
- **Ptype byte** — the data-type code (the `XX` byte described in *Response parsing*)
- **State labels** — for digital points, the `on_label` / `off_label` strings (`"NIGHT"` / `"DAY"`, `"OPEN"` / `"CLOSED"`)
- **Units** — for analog points, when known
- **Read-write flag** — whether the point accepts writes

**Site catalog** (per-installation):
- **BLN name** — required for the bouncer
- **Site code** — typically a 3-letter prefix
- **Scanner identity** — slot 4 / IdentifyBlock self-name (any string; the bouncer doesn't validate it)
- **Panel name → IP mapping** — `NODE1 → 10.0.0.10`, etc.
- **Panel-local points** — names of PPCL variables or virtual points the integrator defined, which won't be in the vendor catalog
- **Application overrides** — if the integrator built a custom application, its slot layout

### Where catalogs come from

For the **vendor catalog**, three practical sources:

1. **Walk the panel's enumerate output and aggregate.** Use the `0x0985` / `0x0986` / `0x0981` family documented earlier in this spec to programmatically traverse every TEC on accessible panels, then group results by `APPLICATION` value. With enough sites' worth of data, you converge on a complete catalog. This is the most thorough approach but takes time and access to many sites.

2. **Vendor controller datasheets.** Siemens publishes installation guides for each TEC family (TEC-3110, TEC-2210, etc.) listing application numbers and their point layouts. Useful as a starting point.

3. **Copy from existing catalogs.** Scanner projects that have done the work above can publish their catalog. A practical example: this repository ships [`tecpoints.json`](tecpoints.json), a 797-application vendor catalog used by the bundled scanner. The format is straightforward — see the README for layout. Whether to ship vendor data this way is project-dependent (licensing, completeness, maintenance), but a working catalog is essential for any practical scanner.

For the **site catalog**, two sources:

1. **Cold discovery + user input** — the runbook in this document discovers the BLN name and panel inventory automatically; the human supplies anything that isn't on the wire (preferred panel names, scanner identity).

2. **Export from Insight or Desigo CC.** The supervisor already has the full site catalog. If the operator can export the point list (CSV, XML, or via the supervisor's API), it's faster than discovery. The format will be vendor-specific and may need normalization.

### Conventions worth knowing

Some naming patterns are widespread enough to be useful:

- **Suffix conventions in PPCL variables:** `.DP` (data point alias), `.ENB` (enable flag), `.OCC` (occupancy state), `.NGT` (night/unoccupied state), `.STPT` (setpoint), `.MIN` / `.MAX` (limit values). These are PPCL-internal names, often readable but not always meaningful at the system level.
- **TEC subpoint names follow factory defaults** unless the integrator overrode them: `RM TEMP` (room temperature), `OCC HTG STPT` (occupied heating setpoint), `DAMPER POS` (damper position percentage), `SF SPD` (supply fan speed), etc. Spaces in names are normal — the protocol's TLV encoding handles them transparently.
- **BLN-virtual points** (system-wide — readable from any panel, typically from `$paneldefault`) are usually time-related (`SYSTIME`, `SYSDATE`) or weather-related on sites with weather integration. They behave differently from panel-local points; see *Reading a BLN virtual point*.

### What this document deliberately does NOT include

- A complete vendor TEC application catalog (would bloat a protocol spec; lives in a data file)
- Site-specific data from any reference installation
- Engineering-units conventions for specific equipment types

These are vendor data and per-installation configuration, respectively — outside the scope of a protocol specification.

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

### Step 2 — Send the CONNECT handshake (93 bytes)

```
HEADER (12 bytes)
  00 00 00 5D                  total length = 93
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
  
  Trailer (16 bytes — see "Connection handshake → role flag" and "session identifier" sections):
  00                           1 byte: trailer separator
  01 01 00                     3 bytes: flags. Third byte should be 0x00 —
                               this is what real DCC and panels both send.
                               Values other than 0x00 are not observed in
                               any real frame.
  00 00 00 00 00               5 bytes: reserved padding (always zero)
  TT TT TT TT                  4 bytes: Unix epoch timestamp, big-endian
                               (struct.pack(">I", int(time.time())))
  00 00                        2 bytes: session ID. 00 00 matches what
                               real panels send; real DCC uses a session-
                               stable non-zero value.
  00                           1 byte: trailing null
                               
  IMPORTANT: Match this exact byte split: sep(1)+flags(3)+rsv(5)+ts(4)+
  sid(2)+null(1) = 16. Other splits that total 16 bytes (e.g.,
  rsv(4)+ts(4)+sid(2)+null(2)) yield the right total length but place
  fields at wrong offsets and may pass routing while failing deeper
  validation in unpredictable ways.
```

The PXC validates this and replies with a routing-flipped success acknowledgement carrying the panel's identity. You don't need to parse the response in detail — just confirm `msg_type=0x33`, `seq=1`, direction byte = `0x01`. If you get direction byte `0x05` instead, the bouncer rejected you (see "The bouncer" section).

### Step 3 — Send a read request (65 bytes)

```
HEADER (12 bytes)
  00 00 00 41                  total length = 65
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
    # IdentifyBlock body: opcode + self-name TLV + site TLV + BLN TLV + 16-byte trailer
    # The 16-byte trailer breaks down as:
    #   00                  1 byte: separator
    #   01 01 00            3 bytes: flags (third byte = 0x00 for non-impersonating)
    #   00 00 00 00 00      5 bytes: reserved padding
    #   TT TT TT TT         4 bytes: Unix epoch timestamp (big-endian)
    #   00 00               2 bytes: session ID (00 00 acceptable for scanner)
    #   00                  1 byte: trailing null
    trailer = (b"\x00"                                  # separator
               + b"\x01\x01\x00"                        # flags (role=0x00)
               + b"\x00\x00\x00\x00\x00"                # reserved
               + struct.pack(">I", int(time.time()))   # timestamp
               + b"\x00\x00"                            # session ID
               + b"\x00")                               # trailing null
    identity = (b"\x46\x40"             # opcode 0x4640
                + lp_string(src)
                + lp_string(site)
                + lp_string(bln)
                + trailer)
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
---

## Appendix: Cold bootstrap runbook — discovering everything from zero

The MVS appendix above assumes you already know the site's BLN, the panel name, and a panel IP. This appendix covers the prior step: walking onto an HVAC segment with no prior site knowledge and ending up with a verified `(BLN, panel_name, IP)` tuple for every PXC, plus the supervisor name needed for scanner identity.

There are five verified discovery methods, ranked by preference. Run **Phase 1** always (L2/L3 inventory). Then in **Phase 2**, pick the highest-preference method available given your network vantage; the lower-preference methods exist as fallbacks. **Phase 3** is per-panel enrichment that always runs last.

The placeholder names used throughout (matching the MVS appendix):
- Site code: `SITE` (placeholder for the prefix you discover, e.g. `SITE`)
- BLN: `MYBLN` (placeholder for the form you discover, e.g. `<SITE>EBLN`)
- Supervisor name: `DCC-SVR` (placeholder for the form you discover)
- Panel names: `panel1`, `panel2`, …
- Scanner identity (any reasonable string): `scanner|5034`

### Phase 1 — Layer-2/3 inventory (always first, ~10 s)

Identify which hosts on the segment are PXCs vs. supervisors vs. third-party BACnet equipment. Three primitives, in parallel:

**ARP scan with vendor filter.** ARP-request the entire `/24`. Filter responses by Siemens OUI `00:a0:03` — every PXC and Automation Station NIC carries it. Cross-reference against the segment's known supervisor IP(s) to remove the supervisor itself. Result: candidate panel IPs.

**TCP/5033 SYN-scan.** Against every Siemens-OUI host, send a TCP SYN to port 5033. SYN-ACK responses identify panels that accept P2 connections. RST/timeout means either the host doesn't speak P2 (e.g., a sensor) or the bouncer's segment-level filter is blocking your IP — in the latter case, Phase 2 Method E and Phase 3 fail identically and you'll know.

**Optional — third-party fingerprint.** SYN-scan TCP/1628 (Trane Tracer SC), TCP/47808 (BACnet/IP routers that listen TCP), and TCP/80/443. Useful for cross-correlation but not required.

```python
import scapy.all as scapy

# ARP sweep
ans, _ = scapy.arping(f"{cidr}", verbose=0)
siemens_hosts = [(r[1].psrc, r[1].hwsrc) for r in ans
                 if r[1].hwsrc.lower().startswith("00:a0:03")]

# TCP/5033 reachability
panels = []
for ip, mac in siemens_hosts:
    pkt = scapy.IP(dst=ip)/scapy.TCP(dport=5033, flags="S")
    resp = scapy.sr1(pkt, timeout=1, verbose=0)
    if resp and resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags & 0x12:
        panels.append((ip, mac))
        scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=5033, flags="R",
                   seq=resp[scapy.TCP].ack), verbose=0)
```

### Phase 2 — Identity discovery: choose your method based on vantage

The goal of this phase is to recover the names a scanner needs to establish P2 sessions: the **BLN** and **at least one panel's canonical name**. Useful but not strictly required: the supervisor name (for impersonation testing or for "looking like Desigo" in network logs).

The five methods, ranked by preference:

| | Method | Vantage required | Time | What you get |
|---|---|---|---|---|
| A | Passive 0x4634 routing-table push | On supervisor↔PXC path | ≤60 s | **Full topology in one frame** |
| B | Passive panel-initiated CONNECT | On supervisor↔PXC path | ≤16 s | BLN, supervisor name, one panel name per emission |
| C | Active BACnet ReadProperty | None (any host on VLAN) | ~2 s | Site code (BLN derived) — but BACnet inventory may be disjoint from P2 inventory |
| D | Passive BACnet Who-Has listen | None (any host on VLAN) | 30–60 s | Site code |
| E | Active P2 panel-name probe | None (any host on VLAN), needs BLN | ~1 s/panel | Per-panel canonical names IF a candidate guess matches |

#### Method A — PREFERRED: passive observation of `0x4634` routing-table push

The supervisor and every PXC emit a `0x4634` routing-table push every **60 seconds** in both directions on TCP/5033. Each frame carries the entire site's BLN-routable name list as TLV name+cost pairs in the body, with the BLN itself in routing slot 1 and the source name in slot 4. One frame = full topology.

Verified body content from a representative corpus capture (sanitized names):

```
$paneldefault       cost=12
101000              cost=1467
NODE1 ... NODE11    cost=2500-2700      ← every panel name
SITE-BMS            cost=5411           ← BMS registration name
DCC-SVR             cost=2477           ← supervisor name (5033 form)
DCC-SVR|5034        cost=2789           ← supervisor name (5034 form)
```

Routing slots of the same frame: `[MYBLN, panel-target-of-this-push, MYBLN, DCC-SVR|5034]`.

To capture this passively, your scanner needs to see TCP/5033 traffic between the supervisor and any panel. Vantage options that satisfy this:

- Run the scanner on the supervisor host itself
- Run on any host whose switchport is configured as a SPAN/mirror destination for the supervisor's switchport
- Run on the gateway/router if supervisor and PXCs are on different subnets and traffic is routed
- Run inline (less common, requires bridging)

```python
import socket, struct, time

def collect_4634(iface_pcap_path, timeout_s=90):
    """Walk a pcap (or live capture) and return parsed 0x4634 bodies."""
    import dpkt
    topology = {}
    with open(iface_pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP): continue
            tcp = eth.data.data
            if not isinstance(tcp, dpkt.tcp.TCP): continue
            if 5033 not in (tcp.sport, tcp.dport): continue
            if not tcp.data or len(tcp.data) < 30: continue
            data = bytes(tcp.data)
            # Skip routing slots, find opcode 0x4634
            slots, p = parse_routing(data[12:])
            if p < 0: continue
            body = data[12+p:]
            if len(body) < 4 or body[0] != 0x46 or body[1] != 0x34:
                continue
            # Parse TLV: 0x01 LL_hi LL_lo <name> <4-byte cost>
            i = 2
            while i + 7 < len(body):
                if body[i] != 0x01: i += 1; continue
                ll = (body[i+1] << 8) | body[i+2]
                if not (1 <= ll <= 50): i += 1; continue
                name = body[i+3:i+3+ll]
                if not name.isascii() or not name.replace(b'-',b'').replace(b'|',b'').replace(b'$',b'').isalnum():
                    i += 1; continue
                cost = struct.unpack(">I", body[i+3+ll:i+3+ll+4])[0]
                topology[name.decode()] = cost
                i += 3 + ll + 4
            return {'bln': slots[0], 'supervisor': slots[3], 'topology': topology}
    return None
```

If you have path visibility, **stop here**. Method A gives you everything in one frame. Skip to Phase 3.

#### Method B — PREFERRED (alternate): passive observation of panel-initiated CONNECT

Same vantage as Method A. Each PXC opens a fresh TCP/5033 connection to the supervisor every **10–16 seconds**, sending an unsolicited CONNECT (`msg_type` 0x2E legacy or 0x2F modern) with full IdentifyBlock. Per the corpus, every panel announces 90+ times in a typical 25-minute capture window.

Wire layout (verified, 88-byte legacy form):

```
00 00 00 58 00 00 00 2E <seq:4>           ← 12-byte P2 header (msg_type 0x2E)
00 "MYBLN" 00 "DCC-SVR" 00 "MYBLN" 00 "panel1" 00   ← routing slots
46 40                                              ← IdentifyBlock opcode
01 00 06 "panel1"                                  ← LP-string: self-name
01 00 04 "SITE"                                    ← LP-string: site code
01 00 07 "MYBLN"                                   ← LP-string: BLN
01 01 00 00 00 00 00 00 <8 bytes status/seq tail>
```

Result per frame: `(BLN, supervisor_name, panel_name, site_code)` in plaintext. Listen for ~16 s and you get one panel; listen for ~2 minutes and you typically get all of them.

This method is interchangeable with Method A from a "what you learn" perspective; the difference is granularity. A is one frame with everything, B is many frames each carrying one panel's identity. Use whichever fires first in your capture.

#### Method C — Active BACnet ReadProperty (no path visibility required)

If you can't see supervisor↔PXC traffic, the cleanest active probe is BACnet `ReadProperty` against any Siemens BACnet device discovered in Phase 1 (or via a `Who-Is` broadcast). Read `object-name` (property 77) on the Device object — for higher-level PXCs (Automation Stations with instances `1xx000`), the returned string is typically site-prefixed, e.g. `SITE.Apogee.AS01` or similar. One round-trip per device.

Wire format of the request (replace `<inst:4>` with target's device-instance, e.g. `02 00 92 28` for instance 103000):

```
81 0A 00 11 01 04 02 75 04 0C 0C <inst:4> 19 4D
│           │     │  │  │  │     └─ context-tag 1, len 1, prop-id 0x4D = 77 (objectName)
│           │     │  │  │  └─ context-tag 0, len 4, object-id (Device class << 22 | inst)
│           │     │  │  └─ service: 0x0C = readProperty
│           │     │  └─ invoke-id (any value)
│           │     └─ APDU header: max-segs/max-resp byte
│           └─ APDU type 0x00 = Confirmed-Request
└─ BVLC: 0x81 0x0A = Original-Unicast-NPDU (4 bytes), NPDU 01 04 (expecting reply)
```

Send to `<device_ip>:47808` UDP. Parse the Complex-ACK response for the BACnet character-string in the property-value section. Apply regex `^([A-Z]{2,6})[._]` to extract the site prefix. From the site code, derive BLN candidates (Method E uses these).

You can also try `Read­Property­Multiple` to fetch `device-name` (70), `description` (28), and `location` (58) in a single round-trip — the strings often complement each other.

#### Method D — Passive BACnet Who-Has broadcast listen

If active probing is undesirable (e.g., you want to be invisible) or BACnet ReadProperty is filtered, the Apogee Automation Stations periodically issue BACnet `Who-Has` broadcasts to `x.x.x.255:47808` carrying object names they're searching for. Bind UDP/47808, listen for BVLC `0x0B` packets with APDU `10 07`, decode the context-tag-3 objectName from each. Site-prefixed names appear within seconds in the corpus.

Verified across three BACnet-bearing captures:

| Capture | Span | Who-Has broadcasts | Site-prefixed | Time-to-first-prefix |
|---------|-----:|-------------------:|--------------:|---------------------:|
| `capture-all.pcapng` | 396 s | 378 | 12 | <10 s |
| `capture-hvac.pcap` | 82 s | 48 | 5 | <10 s |
| `capture-hvac2.pcapng` | 204 s | 119 | 12 | <10 s |

Wire format and decoder are documented under Surface 4a of this spec. Apply regex `^([A-Z]{2,6})[._]` to extract the site prefix. Same outcome as Method C — yields the site code, from which BLN candidates are derived.

#### Method E — Active P2 panel-name probe

This is the harvest step that runs *after* you have the BLN (from any of A–D). Field-testing finding: the scanner identity in slot 4 is **not validated** by the bouncer, so the scanner can use any string. The supervisor name is not strictly required for read-only scanning.

**Important caveat from field testing.** The bouncer's slot-2 check is strict — it routes only on names that case-fold-match a name in the panel's known peer list. Generic candidates like `panel1`, `pxc1`, `controller1` get **silent-dropped** if they don't case-fold to a real panel name at this site. Method E only succeeds when the candidate list happens to include a case-variant of a real panel name. The case-correction leak (Surface 1) is a *normalization* primitive (lowercase → canonical case), not an arbitrary-name acceptance.

In practice:
- **If the site uses a documented Siemens convention** (`NODE1`, `NODE2`, ..., `NODEn`), the lowercase guess `node1...nodeN` will hit immediately for any real panel.
- **If the site uses a non-default convention** (e.g., `AS1`, `STATION1`, `<BUILDING>_PXC1`), Method E requires that you include those candidates in the guess list. Without inside knowledge or pattern observation, the search space is unbounded.
- **For the typical reference site convention** (`NODE<n>` with `n` as a small integer): a Phase 1 scan of N panels usually maps cleanly to `NODE1..NODEN` via this method.

For each panel from Phase 1:
1. Open TCP/5033 to the panel
2. Send a CONNECT (`msg_type` 0x33 legacy or 0x34 modern — try 0x34 first, fall back) with:
   - Routing slots: `[MYBLN, panel-guess, MYBLN, scanner-identity]`
   - `scanner-identity` can be any string (`p2-scanner|5034`, etc.)
   - `panel-guess` in lowercase to trigger the case-correction leak if the case-folded name matches
   - IdentifyBlock body with byte-accurate 16-byte trailer (see *Connection handshake*)
3. Read the panel's response. If `panel-guess` case-folded to a real panel name, slot 4 of the reply contains the panel's canonical name. If not, the panel silent-drops.

If Method A or B was used, you already have all panel names from the topology dump and can skip Method E entirely. Method E exists for the C/D path where you only have the BLN — and even then, it only works if your candidate names happen to include real panel-name variants.

**Caveat — initial frame `msg_type = 0x2E` registers the source as a runtime peer:** sending an initial frame with `msg_type = 0x2E` to a panel with valid BLN + bouncer-passing slot 2 causes the panel to register the source IP as a runtime peer and call back persistently (~16-second cadence, `flags = 01 01 01`) until panel reboot. **This is documented protocol behavior** — `0x2E` CONNECT is the panel-online-announcement envelope. Read-only scanners should use **`msg_type = 0x33` with inner `0x4640` IdentifyBlock as their initial frame** (the form the doc's *Connection-handshake modes* table calls "the alternative `0x33` + inner `0x4640` initiation path"), which is what real Desigo CC sends and does not register the source. A production read-only scanner at the reference site uses this form exclusively and has scanned panels there over extended periods without triggering registration. See *Field-testing findings → Panel persistent reconnect side effect* for full details.

```python
def harvest_panel_name(panel_ip, bln, scanner_identity=b"p2-scanner|5034", msg_type=0x34):
    # Guess list should reflect the site's actual naming convention.
    # For the default Siemens convention, NODE<n> is canonical:
    candidates = [f"node{n}" for n in range(1, 32)]
    for guess in candidates:
        try:
            s = socket.create_connection((panel_ip, 5033), timeout=2)
            s.sendall(build_connect_frame(msg_type, bln, guess, scanner_identity))
            resp = s.recv(4096)
            s.close()
            if resp and len(resp) >= 20:
                slots = parse_routing_slots(resp)
                if len(slots) >= 4 and slots[3]:
                    return slots[3]   # canonical name in slot 4
        except (socket.timeout, ConnectionResetError):
            continue
    return None  # exhausted candidate list - this site uses non-default naming
```

If your candidate BLN was wrong, the bouncer's TCP RST or silent FIN tells you to try the next form (`<SITE>EBLN`, `<SITE>BLN`, `<SITE>_BLN`, `<SITE>BACBLN`, `<SITE>`). Each candidate test is <50 ms, so the full list resolves in well under a second.

### Phase 3 — Per-panel enrichment (always runs last, ~1 s/panel)

For each `(IP, BLN, panel_name)` tuple now in hand, send opcode `0x010C` (system-info / firmware fingerprint) per the MVS appendix. Returns family string, version, build date, and serial. Useful for asset tracking, change-detection across audits, and PME1252-vs-PME1300 dialect confirmation that drives subsequent reads.

### End-to-end output schema

After Phases 1–3 the scanner emits, per panel:

```json
{
  "ip": "10.0.0.X",
  "mac": "00:a0:03:XX:XX:XX",
  "vendor": "Siemens",
  "tcp_5033_open": true,
  "bacnet_device_instance": null,
  "p2_bln": "MYBLN",
  "p2_dialect": "modern",
  "panel_name": "NODE3",
  "firmware_family": "PME1300",
  "firmware_version": "...",
  "discovered_via": "method-A"
}
```

…plus a separate site record:

```json
{
  "site_code": "SITE",
  "p2_bln": "MYBLN",
  "supervisor_name": "DCC-SVR",
  "supervisor_5034_name": "DCC-SVR|5034",
  "supervisor_ip": "10.0.0.X",
  "bms_name": "SITE-BMS",
  "panel_count": 11,
  "discovery_method": "A",
  "discovery_runtime_seconds": 87
}
```

### Failure modes and mitigations

| Symptom | Likely cause | Mitigation |
|---------|--------------|-----------|
| Methods A/B silent within 90 s | No path visibility | Switch to Method C (active BACnet) or D (passive Who-Has) |
| Methods C/D yield no site-prefixed strings | Quiet BACnet plane, non-default naming | Query device-name + description + location in one RPM; check for site context across the union |
| Method E candidate-BLN attempts all RST | Site uses non-Siemens-default BLN | Extend candidate list with hostname-style strings observed in I-Am `device-name`; ask the operator after 10 misses |
| Method E case-correction never fires | Site uses non-default panel naming (not `NODE<n>`) | Extend the candidate list with patterns observed in the site (`AS<n>`, `STATION<n>`, building-prefixed names). Without inside knowledge or Method A/B/D output, the search space is unbounded. |
| Phase 1 SYN-scan blocked at switch ACL | Defensive segmentation | Methods A–D still work — site code alone is useful intelligence; report panel count from BACnet enumeration |
| All phases silent | Wrong VLAN | Check switchport assignment and VLAN tagging |

### What this runbook explicitly does NOT do

- **Does not write to any panel.** All three phases are read-only — SYN scans, BACnet reads, P2 CONNECT and IdentifyBlock observation. No PPCL changes, no point writes, no priority overrides.
- **Does not bypass the bouncer.** The BLN and slot-2 panel-name checks are the bouncer's discriminators; Phase 2 Method E satisfies them by trial against legitimate naming conventions, not by exploiting a flaw.
- **Does not require credentials.** P2 has no per-user authentication — the BLN check is the entire access control, and that name is, as documented across this protocol spec, recoverable from observable traffic. This runbook is a fair characterization of the system's discovery surface, not a novel attack.
- **Does not exploit unpatched vulnerabilities.** Every leak surface used is documented behavior of the protocol as designed, observable on any commissioned site running default Siemens configurations.

The runbook is intended as discovery tooling for facility owners and the HVAC technicians who service their buildings — the same population that uses BACnet browsers, Modbus discovery tools, and vendor-supplied utilities like Siemens Insight. If you're running this against a network you don't have authority over, you're committing unauthorized access regardless of the technique.
