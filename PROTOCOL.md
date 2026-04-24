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

UDP 5033 exists as well, used only for multicast discovery beacons — not for point reads.

A small number of PXCs in the reference capture used non-ephemeral source ports (e.g. NODE3 used TCP source port 3513 for its outbound 5034 connection). This appears to be a per-panel configuration choice, not a separate service. Treat any `PXC_IP:* → DCC_IP:5034` flow as P2 regardless of the PXC-side source port.

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

The panel silently drops the message. No TCP RST, no error response, no log entry visible from outside — just timeout. This is why the original scanner appeared to "succeed" at connecting to NODE11 (TCP accept worked) but then every subsequent read returned None (operational reads were being ignored). Visible in Wireshark as a stream of PSH/ACK packets from the scanner to the PXC with zero response payloads from the PXC.

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
5. Send heartbeats periodically to keep the session alive (~30 seconds typical interval)

If step 2's identity check fails, the PXC responds in one of two ways described in "The bouncer" below.

**Note on the handshake carrier:** The original protocol assumed heartbeat-carries-identity was the only path, but the reference pcap shows explicit CONNECT (type `0x2E`) and ANNOUNCE (type `0x2F`) messages used by Desigo CC for the initial handshake. See "Connection handshake" below for full wire format. Both paths are accepted by the PXC.

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

---

## Operation opcodes (inside type `0x33` and `0x34` payloads)

After the routing header, the payload contains a big-endian 16-bit opcode followed by opcode-specific data. The full opcode map observed in the reference pcap:

### Point reads and writes

| Opcode | Direction | Operation | Notes |
|--------|-----------|-----------|-------|
| `0x0220` | 5033 | ReadShort | Desigo CC's preferred read, compact request |
| `0x0271` | 5033 | ReadExtended | Legacy-client dialect; returns full value block |
| `0x0273` | 5033 | WriteNoValue | Same wire format as 0x0271, trailer `00 00` instead of `00 FF`. Gets ACK-only response. Semantics unclear — possibly a probe/trigger/reset or parameter-clear |
| `0x0274` | both | ValuePush / COVNotification | See below — behavior depends on direction |
| `0x0240` | 5034 only | WriteWithQuality | PXC→DCC push of a BLN-sourced virtual point value, with a quality/sentinel header. Device name is literally `"NONE"` for panel-global points. ACK-only response |
| `0x0241` | 5033 | Unknown | Adjacent to 0x0240 but no value payload on the wire; body carries a `SYST\0#` prefix and device/point TLVs. Hypothesized: a property-operation (flag-set, reset, or trigger) against a subpoint. Only 4 samples, semantics unconfirmed |
| `0x5003` | 5033 | Unknown | Small request, `SYST` prefix + one point name (seen: `ZONE.AC04.ZN`). Possibly a zone-level or schedule-level read. 6 samples, semantics unconfirmed |

### Point enumeration (09xx family)

All 09xx enumeration opcodes share a cursor-based pagination model. The three main ones (`0x0981` walk points, `0x0985` read PPCL, `0x0986` enumerate FLN) are distinct in request shape — the "same request format with a different opcode byte" assumption is WRONG and will fail with `0x05 0x00 0x03` (not found).

| Opcode | Operation | Notes |
|--------|-----------|-------|
| `0x0981` | EnumeratePoints | Walks **every point on the panel** — more complete than `0x0986`. Returns panel-internal points (PPCL variables, schedule points, global analogs) in addition to FLN-device points. Live-tested against NODE3 returning 91 points on a ~25-device panel. |
| `0x0985` | EnumeratePrograms | Walks PPCL programs and returns their source text in chunks. Live-tested against NODE3 returning all 5 programs totaling 103 lines of source, including the 57-line `PPCL_SCU3`. |
| `0x0986` | EnumerateFLN | Lists TEC devices on the FLN bus. The simplest and oldest enumerate; works on every firmware. |
| `0x0982` | EnumerateTrended | Like `0x0981` but entries carry embedded timestamps. Likely trend or schedule points; exact semantic not fully mapped. |
| `0x0988` | EnumerateMulti | Takes a multi-string filter (device AND subpoint AND variant). Useful for targeted enumeration like "every `DAY.NGT` point across all `AC_x` zones." |
| `0x0983`, `0x0984`, `0x0987`, `0x0989`, `0x098C–F` | EnumerateVariants | Additional 09xx variants with different selectors; mostly return `0x00AC` "not supported" on V2.8.10 firmware. |
| `0x099F` | GetPortConfig | Returns panel port configuration indexed by port number. Request is 5 bytes: `09 9F 00 04 XX`. Response contains serial params like `;bd=9600;pa=0;mk=0` and port label. |

#### 0x0986 EnumerateFLN — request format

The simplest of the three. Two cursor TLVs stating "start from here" — on the first call both are `*`, on subsequent calls you pass the previous response's device name.

```
09 86                   opcode
00 00 00  00 01  <cursor1>   [3-byte pad][u16 BE len][value]  typically "*" or device name
00 00 00  00 01  <cursor2>   same format
```

The full 14-byte first-call body with wildcards: `09 86 00 00 00 00 01 2A 00 00 00 00 01 2A`.

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
00 00 00 00 00 00 NN        7-byte metadata — 6 zeros + data-type code (01/02/04)
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

- **Binary points have no units TLV** but do have values. `BLR2ALM`, `BLR2ENB`, `BLR2VLV` all return `3F 80 00 00` (= 1.0 for ON) or `00 00 00 00` (= 0.0 for OFF) with no trailing units string. Don't require a units TLV to extract a value.
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

Live examples:
- `MTRW / DAY.NGT / SiteWaterMeter` on NODE3
- `P11.BLR2_3_PGM / BLRBEN` on NODE11

The two ASCII parts together form the panel's internal index key. The first part is what clients typically display; the second part is a disambiguator (possibly a sub-field like a schedule slot or program label).

**Important cursor behavior:** when walking via 0x0981 and the current cursor matches a compound entry's first name, the panel returns the same record repeatedly — a single-name cursor can't advance past a compound key. The walker must detect this condition and try mutating the cursor to force advance.

**Cursor-mutation order matters.** A naïve byte-increment (`DIVV1` → `DIVV2`) is too aggressive — it skips adjacent entries with the same prefix (`DIVV10.STPT`, `DIVV10.TEMP`, `DIVV1T`). The correct order, from least- to most-disruptive:

1. Append `\x01` — smallest string strictly > cursor, returns the very next adjacent entry
2. Append `' '` (0x20), `'0'` (0x30), `'A'` (0x41), `'a'` (0x61), `'~'` (0x7E) — covers longer-prefix entries not caught by `\x01`
3. Byte-increment last character — skips all same-prefix entries, only use as last resort

Observed impact: on NODE3, skipping the `\x01` append and jumping straight to byte-increment loses approximately 200 points (everything between `DIVV1` and `DIVV2`, between `PW401` and `PW402`, etc.).

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

Byte-verified continuation with cursor `"SCU3_PPCL"` line 10: `09 85 00 00 01 00 01 2A 00 00 01 00 09 53 43 55 33 5F 50 50 43 4C 00 0A` (24 bytes).

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

**Typical run:** enumerating all 5 programs on NODE3 (total 103 source lines) takes ~104 round trips because each response carries ~1-10 lines. PPCL source lines themselves can be up to ~400 characters long (single-line `SET(...)` or `LOOP(...)` statements with many arguments).

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

### Session and identity

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

## Response status codes

As noted above, the first byte of an S2C payload is the status code:

- `0x01` — success
- `0x05` — error, followed immediately after the routing header by a 16-bit error code

Observed error codes:

| Error code | Occurrences | Typical triggering opcode |
|------------|-------------|---------------------------|
| `0x0003` | ~230 | Object not found / point doesn't exist |
| `0x00AC` | ~6 | Operation not supported / unknown opcode on this firmware |

The `0x05` / `0x0003` pair is the dominant error in the pcap — it fires on ~46% of `0x0220` reads, consistent with scanners probing for BLN-sourced virtual points that don't exist on the target panel. A naive parser that doesn't check the status byte will attempt to parse an error response's `00 03` prefix as the start of a point value block and hallucinate a value; the first-byte check is cheap and mandatory.

---

## Reading a point

Both `0x0220` and `0x0271` address points **by string name**, not by numeric ID. The wire request contains the device name and the point name as adjacent TLV strings:

```
[opcode][sub-opcode bytes][device TLV][point TLV]
```

Example — reading `K412/ROOM TEMP` via 0x0271:
```
02 71 00 00 01 00 04 "K412" 01 00 0B "APPLICATION" 00 FF
```

The subpoint slot number (1–99 shown in Desigo CC's UI) is **not transmitted on the wire.** Clients resolve slot → name via the vendor's point-definition metadata and send the name.

The two-byte trailer at the end of the request appears to select which property is being read:
- `00 FF` — typical for 0x0271 (wildcard property / default)
- `00 00` — seen on 0x0273 (different semantic — see below)

### The four read-ish opcodes are NOT four flavors of the same read

A Desigo CC session to a single panel typically uses all four of `0x0220`, `0x0271`, `0x0273`, `0x0274` mixed together:

- **`0x0271`** — canonical read; returns full value block
- **`0x0220`** — compact read, preferred for high-volume polling; errors with `0x05 00 03` if point doesn't exist
- **`0x0273`** — same wire shape as `0x0271` but ACK-only response. Semantics unclear from the pcap; plausibly a write-permission probe, cache invalidation, or parameter reset
- **`0x0274`** — **a bidirectional value-push opcode** whose semantic depends on which port it crossed:
  - **On TCP 5033 (supervisor → PXC)**: supervisor pushes a value for a BLN-sourced virtual point into the PXC's local model. Common for points like `OASTMP1.BN` (outdoor-air temp mirror from a weather-station panel) that the PXC needs but doesn't own.
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
| R3 | `0x0220` | `00 00 00 00 00 00 XX` | XX = data-type code (0x03 = analog) |
| R4 | any | (R2/R3 pattern but float starts `0xBF`) | Negative values |

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

- **Name** — a short ASCII string, unique on the FLN (e.g. `K412`, `PW401`, `DIVV3`)
- **Application number** — identifies which Siemens TEC library app the device runs (e.g. `2023` = VAV cooling/reheat, `2500` = VAV cooling-only, `6525` = fume hood)
- **Description** — optional free-form text from commissioning (e.g. `"CONFERENCE RM A"`, `"ROOM 412"`)

The application number determines which subpoint slots (1–99) are defined and which point names they map to. A slot number is only meaningful in the context of an app:

- App 2023 slot 5 = `HEAT.COOL`
- App 2500 slot 5 = *(undefined — not used by this app)*

Slot ranges aren't fully packed — apps typically use 50-90 of the 99 available slots, with gaps for slot numbers Siemens reserved but didn't wire up for that particular application.

**Fully-qualified point address:** `NODE / DEVICE / POINT`
- NODE = PXC controller name (e.g. `node3`, `NODE3`)
- DEVICE = TEC name on the FLN (e.g. `K412`)
- POINT = subpoint name (e.g. `ROOM TEMP`)

This is also the hierarchy Desigo CC and Insight use in their tree views.

**Point-name suffix conventions (observed):**
- `.BN` — BLN-sourced virtual point. The value doesn't originate on this panel; it's pushed in from elsewhere on the BLN (typically by the DCC server via `0x0274` writes). Example: `OASTMP1.BN` = mirror of outdoor air temp from another panel.
- `.BAC` — BACnet-bridged point. This panel exposes the point via BACnet or received it from BACnet.
- `.DP`, `.ENB`, `.OCC`, `.NGT` — internal PPCL variables, typically booleans or small enums.
- `.SPM`, `.CSTM` — set-point / custom programmed values.

These are conventions, not syntax rules. The PXC doesn't validate them.

---

## BLN routing table (0x4634)

The `0x4634` opcode is how a scanner tells the PXC what panels it knows about. The request body is a fixed header followed by a list of entries; each entry is a TLV name followed by a u32 BE cost/metric value.

Example body from the reference pcap (abbreviated):

```
46 34 00 00 00 00 0C 07 00 0E          header
01 00 0D "$paneldefault" 00 00 00 0C    default entry, cost=12
01 00 06 "101000" 00 00 05 BB           site code entry
01 00 05 "NODE1" 00 00 0A 90            NODE1, cost=2704
01 00 06 "NODE11" 00 00 0A 72           NODE11
01 00 05 "NODE2" 00 00 09 DB
01 00 05 "NODE3" 00 00 0A 62
01 00 05 "NODE4" 00 00 0A A5
01 00 05 "NODE5" 00 00 0A AF
01 00 05 "NODE6" 00 00 0A 69
01 00 05 "NODE8" 00 00 09 D4
01 00 05 "NODE9" 00 00 09 FD
01 00 0F "SITE-BMS" 00 00 15 23
01 00 0A "DCC-SVR" 00 00 09 AD
01 00 0F "DCC-SVR|5034" 00 00 0A E5
00 00 00 00                              terminator
```

The costs cluster around 2500–2800 for PXCs and jump higher for non-PXC supervisory nodes. The actual cost function isn't pinned down, but across 155 routing-table observations from multiple source panels, a clear pattern emerges:

**Cost is a per-observer metric, not a global topology constant.** The same peer is reported with different costs depending on which panel is publishing the routing table:

| Peer | as seen by DCC | as seen by NODE6 | as seen by NODE4 |
|------|----------------|------------------|------------------|
| `NODE1` | 2704 | 3145 | 3145 |
| `NODE3` | 2658 | 3122 | 3122 |
| `NODE6` | 2665 | 3077 | 3192 |
| `NODE8` | 2516 | 2920 | 2920 |

The DCC server consistently reports lower costs than peer panels do for the same targets. Panels at similar network positions (NODE4 and NODE6) report identical costs for most peers. This is consistent with a latency- or quality-based metric measured from the observer's own vantage, not a static link-cost. Plausibly an EWMA of round-trip time or an integer ping-count-style sample.

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

Some older PXC firmware revisions don't implement `0x0986` cleanly and return partial or empty responses. The fallback is brute-force probing against a dictionary of common device-name patterns (`K401`, `K402`, ..., `VAV001`, `VAV002`, ...) — slow but works. Live NODE3 (PME1252 V2.8.10) handles `0x0986` correctly.

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
01 00 0A "OASTMP1.BN"         point name TLV
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

## Cold-site discovery (the cartesian attack)

A scanner with no prior knowledge of a site can still identify a PXC by exploiting the bouncer's distinct failure signatures:

1. **Port-scan** a subnet for TCP/5033 listeners
2. **BLN attack** — try candidate BLN names (`P2NET`, site-prefix guesses, common patterns) against a known PXC IP. A TCP RST means "wrong BLN"; a silent accept means "BLN correct, scanner or node wrong." The first silent-accept gives you the BLN.
3. **Scanner attack** — with the BLN locked, try candidate scanner names. Silent drop continues until you get a heartbeat response, then the scanner name is valid.
4. **Node attack** — with BLN and scanner locked, try node names (`node1`, `node2`, ..., `NODE1`, ..., named variants). The first one that gets a valid read response is the PXC's actual node name.

This is the "cartesian attack" — up to `|BLN| × |Scanner| × |Node|` probes in the worst case, but well-ordered candidate lists usually hit within a few dozen probes.

The whole workflow fits inside `cold_discover_site()` in the scanner code with pre-built candidate dictionaries for each field.

**New shortcut:** once you have a valid session, send one `0x4634` probe or observe one from a real supervisor — it reveals the complete BLN topology (every panel name, every scanner name, plus costs). One successful `0x4634` observation is worth hundreds of brute-force node attacks.

---

## What's still unknown

- **Property state sentinel** (`3FFFFFFF` vs `00000000`) — still not cracked; observation across all pcaps suggests it's a generic "wildcard / no filter" sentinel rather than a quality-flag register
- **Opcode `0x0273`** — semantics still unclear; ACK-only response, same wire shape as a read. Likely a command/probe/reset, not a read or a write
- **Opcodes `0x0241`, `0x5003`** — low-frequency, appear alongside reads but don't follow standard read/write wire shapes. Meaningful samples would require triggering them deliberately from Desigo
- **0x4106 parameter bytes** — the trailing `00 01 7F FF` is stable across observations but I've only seen one variant. If Desigo has a "clear SOME tracebits" or "clear on condition" mode, those parameters would surface different values here
- **Subscription / unsubscription opcodes** — not observed. The 5034 push channel operates without a visible handshake in captures. A capture of a PXC coming online from reset would resolve this
- **Subscribe-from-graphic path** — if Desigo uses a different mechanism to request ad-hoc subscriptions when a floor plan is opened (vs the always-on 5034 pushes), that exchange wasn't in any capture window
- **Full data-type code table** — the byte inside the response metadata block before the f32 value. Observed: `0x02` (seen on `MTRW / SITE_WATER` — 2-byte integer?), `0x03` (analog, dominant), `0x06` (analog32?). Other codes likely for binary/enumerated/string
- **0x4634 cost function** — now known to be a per-observer metric (not a global link cost), with DCC reporting consistently lower values than PXCs. Exact computation (latency EWMA? hop-weighted RTT? integer ping sample?) still not pinned down.
- **0x0982 timestamp format** — BCD-ish timestamps in responses (e.g. `79 09 07 02 0C 16 FF 2A`) look like `year-1900 / month / day / hour / minute / second / fraction / tz` but the exact encoding isn't pinned
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

No. The three mainstream enumerate opcodes each have a different request shape:

- **`0x0986`** (FLN devices): two cursor TLVs, no filter.
- **`0x0981`** (all points): two filter TLVs (always `*`) + cursor TLV + trailing empty TLV — six TLV fields total.
- **`0x0985`** (PPCL programs): ONE filter TLV + ONE cursor TLV + a u16 BE line-number trailer (not another TLV).

Using the wrong shape returns `0x05 0x00 0x03` "not found" from the PXC, even though the opcode is supported. If you get "not found" on an opcode you know exists on that firmware, the request body framing is the first thing to check.

### "TLV fields start with `01 00`"

Subtle off-by-one trap. The TLV format is `[tag: 1 byte = 0x01][length: u16 BE][value: LL bytes]` — three bytes of header. An easy bug when writing Python `struct.pack` is to treat the header as `[\x01\x00][u16 length][value]`, which silently adds an extra zero byte of header and shifts every downstream length by one. This will parse fine in isolation because TLVs are length-delimited, but it corrupts fixed-position trailers. Symptom: requests look right in a packet dump, but the PXC returns the first matching entry and refuses to advance the cursor on continuation calls.

### "The `has_more` flag in 0x0985 responses tells you when a program ends"

It doesn't, reliably. The one byte at offset -5 in a `0x0985` response body looks like a has-more flag, but its observed values don't correlate with program boundaries. Use the `0x05 0x00 0x03` error response — PXC returns it when you ask for a line past the end of the last program — as the authoritative termination signal.

### "Every PXC accepts type `0x33` DATA for operational requests"

No. Modern-firmware panels (PME1300 platform) accept only type `0x34` HEARTBEAT for operational requests, and silently drop `0x33` frames. Legacy panels (PME1252 and earlier) accept only `0x33` and silently drop `0x34` operational frames. See "Firmware dialects" above. Symptom of picking the wrong type is connection-accepts-but-reads-never-complete, with zero error messages anywhere. Always detect the dialect at handshake time.

---

## Empirical validation status

What's been tested end-to-end against live PXCs on the reference site — both PME1252 V2.8.10 legacy-dialect panels and a PME1300 V2.8.18 modern-dialect panel:

| Capability | Method | Status |
|------------|--------|--------|
| Session handshake (legacy) | `0x33` + inner `0x4640` | ✓ Routinely working |
| Session handshake (modern) | `0x34` + inner `0x4640` | ✓ Working against the modern-dialect panel once implemented |
| Dialect auto-detection | probe 0x33 with short timeout, fall back to 0x34 | ✓ Implemented; per-host cache avoids repeat probes |
| Point read by name | `0x0220` / `0x0271` | ✓ Routinely working on both dialects |
| FLN enumeration | `0x0986` | ✓ Returns 17 devices on NODE2, 21 on NODE3 |
| All-point enumeration | `0x0981` | ✓ Returns 91 points on NODE3 including panel-internal |
| PPCL source dump | `0x0985` | ✓ Returns all 5 programs, 103 total source lines |
| Compact sysinfo | `0x010C` | ✓ Returns model/firmware/build date |
| Legacy sysinfo | `0x0100` | ✓ Returns same fields in different layout |
| pcap decoding | Offline | ✓ Parses all captures cleanly |

What's wire-format-documented but NOT live-tested:

| Capability | Reason not tested |
|------------|-------------------|
| 5034 passive listener | Scanner machine isn't the configured supervisor IP; PXCs don't push to it |
| 0x4106 tracebit clear | Intentionally excluded from the read-only scanner |
| 0x0274 COV receive | Requires 5034 listener above |
| 0x0240 virtual-point push | Observed passively in captures; scanner doesn't write |
| Cold-site discovery on modern dialect | Cold-probe path still uses legacy-dialect-only probes; modern panels may fingerprint differently |
| 0x0988 multi-string filter | Low priority — 0x0981 covers enumeration needs |

Every wire format documented above has been either live-tested OR observed in a real Desigo CC capture and byte-verified against that capture. No speculation-only entries remain in the opcode tables.
