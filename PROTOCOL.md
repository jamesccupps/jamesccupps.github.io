# Apogee P2 Protocol — Open Specification

**Version**: 1.3
**Status**: Draft / Working Specification

## Abstract

This document specifies the **Siemens Apogee P2 protocol** — the building-automation network protocol used between supervisor workstations (Insight, Desigo CC) and field controllers (PXC Modular, PXC Compact, Power MEC, MEC, MBC, and compatible third-party equipment) in the Siemens Apogee Automation System.

It covers the wire frame format, transport ports, opcode catalog, point addressing, point class taxonomy, control-language reference, BACnet integration, and security considerations needed for implementation.

The specification is suitable for implementers of:

- Diagnostic and monitoring tools (passive observers)
- Decoder dissectors (Wireshark plugins, IDS signatures, log analyzers)
- Read-only scanners and inventory tools
- Gateway / bridge software (e.g. P2 → BACnet/IP bridges)
- Defensive monitoring systems
- Custom client applications (read, write, command, schedule, alarm acknowledgment)

This specification does **not** describe authentication, encryption, or message-integrity mechanisms because the P2 protocol on the wire provides none. Implementers should not rely on the protocol itself for security; see §21.

**Naming notes**:

- The formal long-form is **Protocol 2**, per the vendor's Wiring Guidelines glossary. Vendor literature also references a sister protocol "P3" alongside P2 in cable-type lists ("P2/P3 RS-485") and in the Siemens-published error text for `0x00AC` ("P2 or P3 command is not supported by the server field panel"). P3 is not described by this specification; treat it as an unmapped sister identifier.
- The `.P2` file extension refers to an offline panel-database export produced by Desigo CC's "P2 Export utility" and is **unrelated to this wire protocol**. A `.P2` file contains a panel's engineered configuration (points, alarms, PPCL programs, schedules) for migration tooling; it does not contain wire-level traffic.
- **Hardware vs firmware identifiers** are easily confused on Apogee equipment. This specification distinguishes them as follows:
  - **Orderable part number** (catalog SKU): e.g. `PXC100-PE96.A` — the model number a user purchases. `PXC100` is the PXC Modular base; `PE` denotes P2 firmware loadout, `BE` denotes BACnet; the trailing `##` is the licensed node count (`24`/`48`/`96`); `.A` is the hardware revision letter.
  - **Hardware-platform identifier** (in revstring): e.g. `PXME` — internal platform code returned by the panel. `PXME` = PXC Modular Ethernet; `PXCE` = PXC Compact Ethernet (PXC-16/24/36); `PXMR` / `PXCR` = RS-485-only variants. Returned as part of the Hardware Revision string in Desigo CC (e.g. `PXME V2.8.18 APOGEE`).
  - **Firmware-build identifier** (in revstring): e.g. `PME1300` or `BME1290` — internal firmware build tag. `PME####` = P2 firmware family (2.x branch); `BME####` = BACnet firmware family (3.x branch). Returned as the Firmware Revision in Desigo CC and as the panel-model TLV in `0x010C` SystemInfo responses, despite the "model" label being a misnomer.
  - **Firmware version string**: e.g. `V2.8.18 APOGEE` or `V3.5.2 BACnet` — the human-readable revision. Note that `V2.x APOGEE` and `V3.x BACnet` are parallel branches of the same firmware codebase running on the same hardware.

  A panel typically reports all three: the revstring `PME1300 0049 - PXME V2.8.18 APOGEE 4.3g` means firmware build `PME1300`, hardware platform `PXME` (PXC Modular Ethernet), firmware version `V2.8.18` on the P2 branch. The underlying orderable hardware is `PXC100-PE##.A`.

---

## Table of Contents

1. Terminology and Conventions
2. Network Architecture
3. Transport Layer
4. Wire Frame Format
5. Session-Layer Protocol
6. AP2 Wire Opcode Catalog
7. CPI Sub-Opcode Namespace
8. AP2Cmd Object Structure
9. Connection Establishment and Handshake
10. Error Responses and Error Codes
11. Firmware Dialect Detection
12. Common Operation Body Formats
13. Discovery and Replication (EPing)
14. Response Parsing — Point Reads
15. Comm Status — Stale-Cache Behavior
16. Point Addressing
17. Point Classes
18. Subpoint Semantics
19. PPCL (Process Control Language)
20. BACnet Integration
21. Security Considerations
22. Cold-Site Discovery
23. Identity-Leak Surfaces
24. Implementation Guide
25. Appendix A: Default Timer Values
26. Appendix B: BACnet Integration Reference
27. Appendix C: Glossary
28. Appendix D: Complete Opcode Reference Table
29. Appendix E: Pinned Wire Body Catalog
30. Appendix F: Firmware Build Registry

---

## 1. Terminology and Conventions

### 1.1 Key Terms

| Term | Meaning |
|---|---|
| **ALN** | Automation Level Network — the supervisor-to-controller network layer. Used interchangeably with BLN in some contexts. |
| **AP2** | The wire-level protocol described herein. Sometimes called "P2 Ethernet" when carried over TCP/IP. |
| **AP2Cmd** | A unit of work in the protocol; an opcode plus its parameters. Encoded as a wire frame. |
| **BACnet** | ASHRAE Standard 135 building-automation protocol; supported alongside P2 in modern equipment. |
| **BACnet/SC** | BACnet Secure Connect — TLS-based BACnet transport. |
| **BBMD** | BACnet Broadcast Management Device. |
| **BLN** | Building Level Network — the logical network grouping a set of field panels under one or more supervisors. |
| **CPI** | Common Protocol Interface — the supervisor-side dispatch namespace. Each CPI code maps to (typically) one AP2 wire opcode. |
| **CPT** | BACnet ConfirmedPrivateTransfer (service choice 18). Used to encapsulate AP2 messages inside BACnet/IP packets. |
| **EPing** | The periodic heartbeat/discovery probe used between field panels on the same BLN. Wire opcode `0x4640`. |
| **Field Panel** | A controller that hosts physical I/O and/or downstream FLN devices. Sometimes called "ALN node" or just "panel." |
| **FLN** | Field Level Network — the downstream network connecting a field panel to its terminal-equipment controllers. |
| **MS/TP** | BACnet Master-Slave/Token-Passing — the RS-485 BACnet sub-protocol. |
| **PPCL** | Process Control Language — the proprietary control-strategy programming language. |
| **Supervisor** | A workstation that hosts the supervisory database and provides the operator interface. Also called "the workstation." |
| **TEC** | Terminal Equipment Controller — a downstream FLN device for terminal-unit control (VAV box, fan coil, etc.). |
| **UC** | Unitary Controller — a downstream FLN device for unit-level control with flexible programming. |

### 1.2 Notation

- **Network byte order** = big-endian. All multi-byte numeric fields on the wire are big-endian unless explicitly stated.
- **`0xHH`** denotes a hexadecimal byte; **`0xHHHH`** a 16-bit value; **`0xHHHHHHHH`** a 32-bit value.
- **`[offset]`** denotes a byte offset into a structure or frame.
- **NUL-terminated** strings end with `0x00`.
- **`u8`/`u16`/`u32`** = unsigned integer; **`f32`** = IEEE 754 single-precision float.

### 1.3 Requirement Keywords

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this document are to be interpreted as in RFC 2119.

### 1.4 Scope and Audience

This specification defines the Apogee Protocol 2 (AP2) wire format used between supervisor workstations and field panels in the Siemens Apogee Automation System. It is intended for implementers of:

- Diagnostic and monitoring tools, including Wireshark dissectors and intrusion-detection signatures
- BACnet bridges and gateway software
- Diagnostic and inventory scanners
- Custom supervisor or panel-side client software

The specification covers the protocol as it operates over IP transports (TCP/5033, TCP/5034, and TCP/3001 via serial-to-Ethernet bridges) and over BACnet/IP encapsulation. P2 over its original RS-485 trunk is mentioned where the IP encoding inherits behavior from it, but byte-level RS-485 framing is out of scope.

P2 provides no transport security and no message authentication (see §21). This specification does not endorse use of P2 on networks reachable by untrusted parties.

Two interpretive conventions apply throughout:

- **The wire bytes are authoritative.** Opcode labels such as "ValuePush" or "RegisterCOV" describe operations by their observable behavior. A parser MUST dispatch on the bytes (opcode, sub-opcode, body shape), not on the textual label.
- **Hedged statements flag uncertainty.** Where this specification describes an operation as "probable" or "inferred", implementers SHOULD verify the behavior against the firmware they target before relying on it.

---

## 2. Network Architecture

### 2.1 Three-Tier Topology

```
                    ┌──────────────────────────┐
                    │     Supervisor Tier      │
                    │       (workstation)      │
                    └──────────┬───────────────┘
                               │
                               │ TCP/5033, TCP/5034 (P2)
                               │ UDP/10001 multicast + broadcast (presence beacon)
                               │ UDP/47808 (BACnet)
                               │
                    ┌──────────┴───────────────┐
                    │    Field Panel Tier      │
                    │  (PXC / MBC / MEC / etc) │
                    └──────────┬───────────────┘
                               │
                               │ P1 RS-485 / MS-TP RS-485 / BACnet/IP
                               │
                    ┌──────────┴───────────────┐
                    │    FLN Device Tier       │
                    │   (TEC / UC / VFD ...)   │
                    └──────────────────────────┘
```

- **Supervisor (workstation)**: Hosts the central database, operator interface, alarming, scheduling, reporting. Multiple supervisors may exist on a Management Level Network (MLN).
- **Field Panel**: A direct-digital-control (DDC) device with on-board I/O. Connects upstream to supervisor(s) and downstream to FLN devices.
- **FLN Device**: A terminal-level controller (TEC, UC, VFD, etc.) attached to a field panel's downstream bus.

### 2.2 BLN Transport Variants

The Building Level Network (BLN) — the supervisor↔panel layer — supports multiple transport mechanisms:

| BLN Type | Physical Layer | Notes |
|---|---|---|
| **P2 (RS-485)** | RS-485 via Trunk Interface card | The original (pre-Ethernet) serial BLN. Sometimes labeled "PII" in vendor literature, referring to the second-generation Apogee panels that introduced this trunk. Up to 4 trunks per supervisor. |
| **IP (Ethernet)** | TCP/IP over Ethernet | Primary transport for modern installations |
| **Remote** | Modem over PSTN | Dial-up BLN; one supervisor can host up to 8 modems × 300 remote BLNs |
| **AEM-bridged** | TCP/IP via Lantronix-based serial-to-Ethernet bridge | Bridges legacy RS-485 BLNs onto an IP network |
| **BACnet** | BACnet/IP UDP/47808 | When supervisor is configured as a BACnet client |
| **MS/TP** | BACnet RS-485 | When supervisor or field panel is configured for MS/TP |

This specification focuses on the **IP (Ethernet) and AEM-bridged variants**, which carry the same AP2 frames over different transports.

### 2.3 FLN Variants

| FLN Type | Physical | Application range |
|---|---|---|
| **P1 FLN** | RS-485 (proprietary serial) | Apogee TEC/UC application numbers in the catalog ranges |
| **MS/TP FLN** | RS-485 (BACnet MS/TP) | BACnet-native MS/TP devices |
| **MS/TP Routed FLN** | BACnet MS/TP behind a BACnet router | Indirect access via a BACnet/IP↔MS/TP router |
| **BACnet/IP FLN** | TCP/IP | Modern BACnet/IP-native FLN devices (e.g. DXR2.E controllers) |

Per panel limits (BACnet firmware revision 3.4 or later — corresponding to the modern PXC Compact / Modular hardware generation):
- Up to **3 FLNs** per legacy panel (numbered 1, 2, 3)
- Up to **96 FLN devices** per modern BACnet field panel (across all FLNs combined)
- Up to **32 FLN devices** per legacy FLN
- Up to **127 master addresses** + 127 slave addresses on a single MS/TP segment (BACnet spec: 0-254 total)

### 2.4 Site, BLN, and Node Naming

Three identifiers form a node's fully-qualified address:

- **Site name**: groups panels that share intra-site discovery cadence (default 10s EPing); panels in different sites use the inter-site cadence (default 60s).
- **BLN name**: unique per BLN within a site. Used as the addressing prefix in every wire frame.
- **Node name**: unique per node within a BLN. Used as the DNS hostname when DNS is available.

Naming rules:
- Maximum 30 characters
- Letters, numbers, periods, dashes only (Ethernet BLN names cannot contain periods)
- Unique on the Ethernet network

DNS-based discovery is preferred; a Node Name Table fallback is replicated across all panels on a BLN when DNS is not available.

### 2.5 Supervisor Identifier

The supervisor identifies itself in every frame as:

```
<HOSTNAME>|<LISTENING_PORT>
```

Where `LISTENING_PORT` is the TCP port on which the supervisor accepts inbound connections from panels (see §3.2).

### 2.6 Supervisor Stack Architecture (Informative)

The supervisor implements P2 as multiple parallel protocol adaptors, each responsible for a different family of operations. Implementers of dissectors, interoperability tooling, or intrusion-detection signatures may encounter traffic patterns that only make sense in light of this internal split:

| Adaptor role | Behavior on the wire |
|---|---|
| **Modern P2 / BACnet bridge** | Handles HVAC point operations and BACnet-bridge translation. Emits the bulk of supervisor-originated AP2 frames. |
| **IP transport** | IP-transport-specific variants of operational opcodes, plus a set of IP-only operations (alarm acknowledgment, COV registration/cancellation, BACnet network ops). The dominant source of `0x4640` transport keepalives. |
| **Legacy serial** | Legacy ALS3 protocol and ECP (Electronic Card Protocol — security/access control) over RS-485. **Does not produce AP2 frames on TCP.** |
| **Fire-alarm integration** | Fire-alarm panel integration (Siemens XLS series) via XNET / FSI sub-protocol. **Does not produce AP2 frames on TCP.** |

Only the first two adaptors produce traffic on TCP/5033 and TCP/5034. The latter two are listed so that an observer who sees references to ALS3 / ECP / FSI / XNET classes in vendor documentation does not assume they are P2-related.

The same operation may appear in both the modern P2 and IP-transport adaptors with slightly different wire shapes; the IP-transport variant is what travels on TCP. This is one structural reason why some opcodes appear polymorphic on the wire (see §6.6).

---

## 3. Transport Layer

### 3.1 IP-Layer Requirements

- **IPv4** is the only supported addressing family.
- Each device requires exactly **one IP address**.
- When multicast optimization is enabled, an additional **shared multicast group address** is required per BLN.
- DHCP or fixed IP addressing both supported; reserved DHCP is recommended over pure DHCP for production.
- DNS support is recommended; a `hosts`-style local name file is the fallback.
- **MTU**: standard 1500-byte Ethernet MTU. TCP MSS advertised as 1460.

### 3.2 Port Assignments

The protocol uses multiple TCP/UDP ports. Implementers MUST handle both directions on TCP/5033 and TCP/5034 to fully capture a session.

#### 3.2.1 Native P2 Ports

| Port | Protocol | Role | Direction |
|---|---|---|---|
| **TCP/5033** | TCP | Field panel listener | Supervisor → Panel; panel↔panel peer |
| **TCP/5034** | TCP | Supervisor listener | Panel → Supervisor |
| **UDP/10001** | UDP multicast + directed broadcast | Presence beacon | Panel → multicast group + broadcast |

The default TCP/5033 port is **configurable** at the panel; both endpoints must agree on the chosen port. The factory default is 5033.

Both supervisors and panels typically maintain **two simultaneous TCP connections** to each peer: one outbound (to the peer's listener), one inbound (accepted on the local listener). This bidirectional pattern is normal and expected.

#### 3.2.2 Multicast Presence Beacon (UDP/10001)

Field panels emit a periodic presence beacon out-of-band from the TCP traffic. The beacon allows passive discovery without sending probes.

| Property | Value |
|---|---|
| Source IP | Network gateway IPs (typically the panel's L3 gateway) |
| Destination port | UDP `10001` |
| Destination addresses | **Both** multicast group `233.89.188.1` **and** directed broadcast `255.255.255.255` |
| Payload | 4 bytes: `01 00 00 00` (invariant) |
| Cadence | ~10.5 seconds between emission pairs |

The beacon is **dual-emitted**: each beacon is sent twice in immediate succession (typically <1 ms apart) — once to the multicast group, once to the directed broadcast. The redundancy ensures presence detection works regardless of whether intermediate switches have IGMP snooping enabled.

**Note on documentation variants**: some legacy literature references "UDP port 8" for the multicast beacon. The value used by deployed panels is UDP/10001. Implementers MUST use UDP/10001. The multicast group address (`233.89.188.1`) and UDP port are configurable per site; a defensive scanner SHOULD accept both as parameters.

#### 3.2.3 Soft Controller Ports

Software-implemented field panels ("Soft Controllers") listen on configurable ports starting at **5400** (factory default). Constraints:

- Recommended range: **5100–32767**
- Two Soft Controllers on the same supervisor MUST NOT have ports that differ by exactly 100 (e.g. {5400, 5500} is invalid; {5400, 5401, 5501} is valid).
- This constraint suggests an internal `port mod 100` indexing in the supervisor.

#### 3.2.4 Serial-to-Ethernet Bridge Ports

Some installations use a Lantronix-based bridge to expose a remote serial BLN over IP:

| Port | Role | Default speed |
|---|---|---|
| **TCP/3001** | Bridge channel 1 — P2 BLN encapsulated over TCP | 38400 bps |
| **TCP/3002** | Bridge channel 2 — HMI/terminal passthrough | 9600 bps |
| TCP/23 | Bridge admin via Telnet | — |
| TCP/80 | Bridge web management | — |
| TCP/69 | TFTP for firmware download | — |
| UDP/161/162 | SNMP | — |
| TCP/30718 (`0x77FE`) | Bridge discovery service | — |

Implementers SHOULD treat TCP/3001 as functionally equivalent to TCP/5033 at the AP2 frame level — the AP2 frame structure is identical; only the transport differs.

#### 3.2.5 BACnet Integration

When BACnet is used:

| Port | Protocol | Role |
|---|---|---|
| **UDP/47808** (`0xBAC0`) | UDP | BACnet/IP |
| TCP/47808 | TCP | BACnet/SC (Secure Connect, TLS) — newer panels |

A BACnet MAC address on Ethernet is **6 bytes**: 4-byte IPv4 + 2-byte UDP port. Example: `192.168.1.50` on port 47808 → `C0 A8 01 32 BA C0`.

BBMD entries MUST use subnet mask `255.255.255.255` (i.e., `/32`).

#### 3.2.6 Supervisor-Side Service Ports

For a complete enumeration of supervisor-listening ports (relevant to IDS/scanner implementations):

| Port | Protocol | Service |
|---|---|---|
| TCP/7 | TCP | Server-to-client ICMP-equivalent comm check (Insight) |
| TCP/100 | TCP | Field-panel diagnostic service |
| TCP/135 | TCP | Microsoft RPC endpoint mapper |
| 161 / 162 | UDP | SNMP (poll / trap) |
| TCP/502 | TCP/UDP | Modbus (when Modbus driver loaded) |
| 5093 | UDP | License authentication (Rainbow / SafeNet) |
| 5099 | TCP + UDP | License authentication (database server) |
| TCP/5441 | TCP | Panel-traffic sniffer service ("Sniffer") |
| TCP/5442 | TCP | Asynchronous panel-event channel ("IPSNIFF" / Insight Async) |
| TCP/6779, TCP/6780 | TCP | Object-database service (newer supervisors) |
| TCP/6775, TCP/6778 | TCP | Object-database service (legacy supervisors) |
| TCP/12001 – TCP/12005 | TCP | Dialogic voice-board ports (RENO option) |
| TCP/30400 | TCP/UDP | Utility Cost Manager (when UCM option is installed) |

Field-panel-side ancillary ports:

| Port | Protocol | Service |
|---|---|---|
| TCP/21 | TCP | FTP — configuration file transfer (used by Field Panel GO; LSM-FPGO license-gated) |
| TCP/23 | TCP | Telnet HMI (disabled by default) |
| TCP/50 | TCP | Second Telnet for integration drivers (disabled by default) |
| TCP/69 | TCP | Program-list retrieval service (Siemens-proprietary; not standard TFTP) |
| TCP/80 | TCP | Field Panel Web Server (HTTP UI; CVE-2022-45937 — see §21.3) |
| TCP/999 | TCP | AEM200 configuration (when an AEM200 bridge is in use) |
| UDP/5033 | UDP | SNMP listener (when `LSM-SNMP` license is enabled on PXC Modular only) — distinct from the multicast beacon on UDP/10001 |

The TCP/69 panel-side service is **not standard TFTP** despite sharing the well-known TFTP port number. It is a Siemens-proprietary program-list retrieval service that runs over TCP. The Lantronix bridge in §3.2.4 uses TCP/69 for a separate TFTP-compatible firmware-download service.

### 3.3 TCP Keepalive

The serial-to-Ethernet bridge defaults to **45-second TCP keepalive**. Native panel-to-supervisor connections rely on the application-layer EPing mechanism (§13.2) rather than TCP keepalive for liveness detection.

---

## 4. Wire Frame Format

This section defines the byte layout of a single AP2 message carried over TCP (port 5033, 5034, or 3001).

### 4.1 Frame Structure

```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       total_length                            |  (4 bytes, BE)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       session_msg_type                        |  (4 bytes, BE)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       sequence_number                         |  (4 bytes, BE)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  direction  |
  +-+-+-+-+-+-+-+
  |  slot 1: BLN name (NUL-terminated ASCII)                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  slot 2: destination node name (NUL-terminated ASCII)         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  slot 3: BLN name (NUL-terminated ASCII)                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  slot 4: source node / scanner name (NUL-terminated ASCII)    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    AP2 wire opcode (BE)       |   sub-opcode / flags (BE)     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       payload (variable)                      |
  ~                            ...                                ~
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The first 12 bytes form a fixed session header (length + msg_type + sequence). The remainder is the AP2 payload.

### 4.2 Field Definitions

| Field | Type | Description |
|---|---|---|
| `total_length` | u32 BE | Total message length on the wire, including these 4 bytes. A 76-byte frame encodes `0x0000004C` here. Used by the framer to demarcate messages within a TCP stream. |
| `session_msg_type` | u32 BE | Session-layer message class. See §5 for values. |
| `sequence_number` | u32 BE | Monotonically increasing per-side sequence number. Wrap-around at 2^32 is rare in practice (about 13.6 years at 10 req/s); implementers SHOULD tolerate wrap by treating the field as modular. See §8.4. |
| `direction` | u8 | `0x00` = request (or client→server initial message); `0x01` = success response; `0x05` = error response (followed by u16 BE error code). See §8.3 and §10. |
| `slot 1` (BLN name) | NUL-terminated ASCII | BLN name; appears twice in the frame (slots 1 and 3 are identical). Routing prefix. Required. |
| `slot 2` (destination) | NUL-terminated ASCII | **Destination node name** — the recipient of this frame. In responses the slots swap content: slot 2 then holds the destination of the response (the original source). Required. |
| `slot 3` (BLN name) | NUL-terminated ASCII | BLN name; identical to slot 1. Required. |
| `slot 4` (source) | NUL-terminated ASCII | **Source node name** — the sender of this frame. Supervisors and scanners typically use `<HOSTNAME>\|<PORT>` format (e.g. `DCC-SVR\|5034`); a panel uses its bare node name. Required. |
| `AP2 wire opcode` | u16 BE | The AP2 operation code. See §6 for the catalog. |
| `sub-opcode / flags` | u16 BE | A 2-byte field that follows the wire opcode for most operations. Its interpretation is **opcode-specific**: many operations use these bytes as a sub-opcode or flags value (commonly `0x0000`, sometimes a CPI-derived value such as `0x0001` for `0x0274` ValuePush); a few operations — notably `0x4640` IdentifyBlock — have no separate sub-opcode field and place TLV data directly after the wire opcode. See §6 per-opcode entries and §7 for the CPI namespace. |
| `payload` | variable | Operation-specific data. See per-opcode sections. |

Slot 2 holds the destination of the current frame and slot 4 holds the source. This ordering applies to all session message types (`0x33`, `0x34`, `0x2E`, `0x2F`) and to both requests and responses. See §4.6 for examples.

### 4.3 Byte-Order Note

All multi-byte integer fields in the wire frame are **big-endian (network byte order)**, including the AP2 wire opcode and any sub-opcode bytes that follow it. Implementations parsing captured traffic read these as big-endian; implementations generating frames byte-swap from native order before transmission.

### 4.4 Maximum Frame Size

The `total_length` field is 32 bits, so the theoretical maximum frame size is 4 GB. Practical limits:

- TCP MSS is 1460 bytes; frames larger than about 1400 bytes fragment across TCP segments.
- The framer MUST handle messages that span multiple TCP segments by buffering until `total_length` bytes have arrived.
- Typical frame size is 60-150 bytes; the largest commonly seen frames (a few kilobytes) occur during PPCL program upload.
- Receivers SHOULD reject frames with `total_length > 65536` as framing corruption and close the connection.

### 4.5 Example: ValuePush (Supervisor → Panel BLN-Virtual Write)

A supervisor pushes a BLN-sourced virtual-point value into a panel's model: point `OASTMP1.BN` is set to `48.706` (an outdoor-air-temperature value mirrored from another panel that reads it physically).

```
00 00 00 4C                            total_length = 76 bytes
00 00 00 33                            session_msg_type = 0x33 (legacy dialect)
00 0C 7B C6                            sequence_number = 0x000C7BC6
00                                     direction = request
53 49 54 45 42 4C 4E 00                "SITEBLN\0"          (slot 1: BLN name)
4E 4F 44 45 36 00                      "NODE6\0"            (slot 2: destination panel)
53 49 54 45 42 4C 4E 00                "SITEBLN\0"          (slot 3: BLN name repeated)
44 43 43 2D 53 56 52 7C 35 30 33 34 00 "DCC-SVR|5034\0"     (slot 4: source = supervisor)
02 74                                  AP2 wire opcode = 0x0274 (ValuePush)
00 01                                  CPI sub-opcode = 0x0001
00 00                                  field marker
01 00 0A                               TLV header: tag=0x01, length=10 (u16 BE)
4F 41 53 54 4D 50 31 2E 42 4E          point name "OASTMP1.BN" (10 bytes)
01 00 00 00                            value-block marker (TLV tag + zero-length empty TLV)
42 42 D3 D0                            f32 BE = 0x4242D3D0 = 48.706
00                                     trailer
```

Slot 2 holds the destination (panel `NODE6`); slot 4 holds the source (supervisor `DCC-SVR|5034`). The device field is implicit — BLN-virtual points carry no device TLV in this direction. The inverse direction (panel → supervisor COV) is documented in §12.5 and carries an explicit device TLV.

### 4.6 Routing Header — Name Slot Ordering

The four NUL-terminated strings in the wire frame are referred to as **slots 1 through 4** in the order they appear on the wire. **The slot assignments are constant regardless of message type or direction**:

| Slot | Content | Notes |
|---|---|---|
| **Slot 1** | BLN name | The BLN name (same as slot 3); used as a routing prefix |
| **Slot 2** | **Destination node name** | The recipient of this frame |
| **Slot 3** | BLN name (repeated) | Same as slot 1 |
| **Slot 4** | **Source node name** | The sender of this frame |

The destination-then-source ordering applies to all session message types (`0x33`, `0x34`, `0x2E`, `0x2F`) and to both requests and responses. In a response frame the slots swap content (destination of the response = source of the request, source of the response = destination of the request), but slot 2 still holds the destination of *this particular frame*.

**Concrete examples**:

```
Request (supervisor → panel):
00 "SITEBLN" "NODE6" "SITEBLN" "DCC-SVR|5034"
   ^slot1   ^slot2  ^slot3    ^slot4
            =DEST            =SRC

Response (panel → supervisor, slots swap):
01 "SITEBLN" "DCC-SVR|5034" "SITEBLN" "NODE6"
   ^slot1   ^slot2          ^slot3    ^slot4
            =DEST                     =SRC
```

### 4.7 Scanner Identity Conventions

Slot 4 (source) is a self-identifier string. Conventional formats by supervisor type:

| Supervisor type | Slot 4 format |
|---|---|
| Desigo CC | `<SITE>DCC-SVR\|5034` (DATA frames) or bare `DCC-SVR` (CONNECT/ANNOUNCE) |
| Insight | `<SITE>WCIS-SVR` |
| Engineering tools (field-tech laptops) | varies, often includes tool name |
| Custom clients / scanners | `<custom_name>\|<listening_port>` (e.g. `P2SCAN\|5034`) |

The `|<port>` suffix is **part of the identity string**, not a parser delimiter. It tells the peer the port the sender is listening on for response or push traffic. Both forms with and without the suffix must be recognized by a parser.

The panel does **not** validate the slot 4 source identifier — any reasonable string is accepted (see §9.10 Bouncer). The supervisor may log it for audit, but it is not a security check.

---

## 5. Session-Layer Protocol

### 5.1 Session Message Types

The 4-byte `session_msg_type` field at frame offset 4 indicates the role of the message:

| Value | Name | Direction | Purpose |
|---|---|---|---|
| `0x00000033` | **DATA** | Bidirectional | Operational traffic on legacy-dialect panels (firmware build `PME1252` and earlier) — point reads, writes, enumerations, COV pushes. Most-common type (>85% of observed frames). |
| `0x00000034` | **HEARTBEAT** | Bidirectional | Operational traffic on modern-dialect panels (firmware build `PME1300` and later) — same role as `0x33` but used by newer firmware. The name "HEARTBEAT" is historical; in practice these frames carry the full opcode set, not just keepalives. See §11 for dialect detection. |
| `0x0000002E` | **CONNECT** | Bidirectional | Session-establishment handshake initiator (Mode A) and Mode-C carrier for some workflows. Body carries a `0x4640` IdentifyBlock or, in Mode-C-headless flows, an operational opcode directly. See §9.11. |
| `0x0000002F` | **ANNOUNCE** | Bidirectional | Reverse-direction handshake initiator (Mode B, typically panel → supervisor). Structurally identical to CONNECT. See §9.12. |

A receiver MUST be prepared to handle all four types. Legacy-dialect panels speak `0x33` for operational traffic; modern-dialect panels speak `0x34`. CONNECT (`0x2E`) and ANNOUNCE (`0x2F`) frame session establishment regardless of dialect.

### 5.2 Sequence Numbers

Each side maintains a monotonically increasing sequence counter per connection. The sequence number is included in every frame and incremented per request.

The receiver echoes the sequence number in the response so that the requester can correlate. Async pushes (`session_msg_type = 0x34`) use the server's own sequence counter, independent of any client request.

**Pipelining lag — pair with tolerance, not strict equality.** In normal operation the panel's response sequence equals the request sequence in the great majority of pairs. A small fraction of pairs (around 10% in busy sessions) show panel-side pipelining lag: the response sequence runs **1 to 17 behind** the request sequence (never ahead). This is normal in busy sessions and is not a desync. Parsers MUST pair requests and responses with a sliding-window tolerance of at least 20 frames rather than requiring strict sequence equality. A parser that requires exact echo will appear to lose roughly 10% of responses.

### 5.3 Direction Byte

The single-byte `direction` field at offset 12 takes one of three values:

- `0x00` = request, initial message, or asynchronous push
- `0x01` = success response or acknowledgment
- `0x05` = error response (followed by 2-byte BE error code; see §10)

These are the only three values observed. The direction byte allows a stateless decoder to tell which way the frame travels without inspecting TCP-stream state.

### 5.4 Connection Establishment

A standard TCP three-way handshake establishes the connection. The first application-layer frame after handshake completion is typically a session-initialization message carrying a `0x4640` IdentifyBlock:

- Against **legacy-dialect** panels, the first frame uses `session_msg_type = 0x33` (DATA) or `0x2E` (CONNECT).
- Against **modern-dialect** panels, the first frame uses `session_msg_type = 0x34` (HEARTBEAT) or `0x2F` (ANNOUNCE).

A client that does not know the dialect in advance SHOULD use the detection algorithm in §11.2.

### 5.5 Connection Teardown

Either side may close the TCP connection (FIN). No application-layer goodbye message is required. The framer SHOULD treat a clean FIN as a normal termination and a connection reset as a fault to be logged.

---

## 6. AP2 Wire Opcode Catalog

The AP2 wire opcode (2 BE bytes at frame offset just after the addressing strings) identifies the operation. **416 distinct wire opcodes** are defined. A small number are polymorphic: more than one logical operation shares the same wire opcode and is distinguished by body shape (see §6.6). This section lists the most-common opcodes grouped by function. Appendix D gives the complete enumeration.

### 6.1 Opcode Categories (high-byte clustering)

The opcode space partitions into functional regions by high byte:

| Range | Function | Examples |
|---|---|---|
| `0x00xx`-`0x01xx` | Point definition, modification, COV registration, system info | `0x0050` StatusQuery, `0x0100` SystemInfo (legacy), `0x010C` SystemInfo (compact) |
| `0x02xx` | Point I/O ops, reads, writes | `0x0220` ReadShort, `0x0240` WriteWithQuality, `0x0271` ReadExtended, `0x0273` WriteNoValue, `0x0274` ValuePush, `0x02E2` ReadProcessData |
| `0x03xx` | Point definition, timer/trend, network ops | `0x0302`/`0x0303` point definition, `0x0313` modify, `0x0332`-`0x0357` timers, `0x0360`-`0x0367` trend, `0x0368` NodeRoutingQuery |
| `0x04xx` | PPCL / state-set catalog | `0x040A` MultiStateLabelCatalog, `0x0401`-`0x040E` PPCL / state-set ops |
| `0x05xx` | Alarming, BLN connection ops | `0x0500` AckAlarm (legacy), `0x0508` AlarmReport, `0x0509` AlarmAck (v2), `0x0540`-`0x054D` BLN connection ops |
| `0x06xx` | Modify / maintenance ops | `0x0606` lightweight probe, `0x0600`-`0x0615` maintenance |
| `0x09xx` | Enumeration, scheduler, network status | `0x0981` EnumeratePoints, `0x0985` EnumeratePrograms, `0x0986` EnumerateFLN, `0x098C`-`0x098F` schedules |
| `0x38xx` | Trend ops | `0x3807`, `0x3809`, `0x3817` (trend definitions); `0x3800`-`0x381A` cluster |
| `0x40xx` | BACnet integration | `0x4000`-`0x401F`, `0x400F` UploadReportDescriptor |
| `0x41xx` | PPCL programming | `0x4100` PpclLineUpdate, `0x4103` PpclClearTrace, `0x4106` DefinePpcl |
| `0x42xx` | Bulk property operations | `0x4200` PropertyQuery, `0x4221` BulkPropertyRead, `0x4222` BulkPropertyWrite |
| `0x46xx` | Discovery, replication | `0x4633` ReplNotify-init, `0x4634` RoutingTable, `0x4636` ReplChanges, `0x4640` IdentifyBlock / EPing |
| `0x48xx`-`0x4Bxx` | BLN management, node ops | `0x4824`–`0x4B03` cluster |
| `0x50xx` | Scheduler transport | `0x5001`–`0x5054` Schedule add/del/mod/read; `0x5020` EntryWrite, `0x5022` SlotInit |
| `0x53xx` | Status probes | `0x5354` (constant-body probe, always errors) |
| `0xF0xx` | Vendor-extended | `0xF038` BLN management (vendor-extended range) |

### 6.2 Most-Common Opcodes (by observed frequency)

| Wire opcode | Sub-opcode | Name | Purpose |
|---|---|---|---|
| `0x4640` | `0x1600` | **IdentifyBlock / EPing** | Connection-handshake identity (initial) AND mid-session identity refresh AND inter-panel discovery (10-sec intra-site heartbeat). Bears multiple roles. |
| `0x0274` | `0x0001` | **ValuePush** (bidirectional) | **TCP/5033 (supervisor → panel)**: virtual-point write into the panel's model. **TCP/5034 (panel → supervisor)**: genuine unsolicited COV emission. Same opcode, direction-dependent semantic. |
| `0x0240` | `0x0004` | **WriteWithQuality** | Supervisor writes a point value with a quality indicator. **Fails with error `0x0E15` against SYST scope** — use `0x4222` (BulkPropertyWrite) for SYST writes. |
| `0x4222` | `0x1114` | **BulkPropertyWrite** | Canonical opcode for SYST-scoped setpoint writes. The supervisor retries this after a `0x0240` returns `0x0E15`. |
| `0x4636` | `0x1604` | **ReplChanges** | Replication update push between panels |
| `0x4634` | — | **ReplNotify / RoutingTable** | BLN routing-table announce/push (port-agnostic — observed on both 5033 and 5034) |
| `0x0500` | — | **AckAlarm** (legacy) | Alarm acknowledgment (legacy form). CPI `0x0F01` maps to this wire opcode but is not written at `[+0x06]`. |
| `0x0509` | `0x0F01` | **AlarmAck** (v2) | Newer alarm acknowledgment variant; writes `0x0F01` at `[+0x06]`. Paired with `0x0508` AlarmReport. Polymorphic — see §6.6. |
| `0x0508` | — | **AlarmReport** | Panel reports an alarm transition to supervisor |
| `0x0220` | `0x00xx` | **RegisterCOV / read-short** | **Subscribe** to COV updates (modern dialect); also **point read** for modern firmware. Variants `0x0220`-`0x0223`. |
| `0x0271` | `0x0010` | **ReadExtended** | Point read (legacy-dialect firmware, build `PME1252` and earlier). Returns full value block. |
| `0x0272` | `0x0012` | **read variant** | Alternate read variant |
| `0x0273` | `0x0011` | **WriteNoValue / PointProbe / AlarmAckTrigger** | Point-existence probe (Desigo's dominant use case). Also pre-cursor for `0x0509` alarm ack. |
| `0x0244` | `0x00xx` | **CancelCOV** family | Unsubscribe from COV; sub-opcodes `0x0244`-`0x024D` are variants |
| `0x02E2` | `0x00xx` | **ReadProcessData** | Read process data from a point |
| `0x0294` | `0x0704` | **SYST read (small)** | SYST-scoped read, small (53-byte sep=`0x00`) and large (222-byte preallocated sep=`0x01`) forms |
| `0x0295` | `0x0702` | **SYST read (sibling)** | Plant-equipment status registers — sibling of `0x0294` |
| `0x0241` | `0x0030` | **PropertyEcho / DefaultPropertyResolve** | SYST-scoped, paired-response operation |
| `0x4200` | `0x1103` | **PropertyQuery** | Browse form (small ~30-40B) OR preallocated deep-read form (222B) |
| `0x4221` | `0x11xx` | **BulkPropertyRead** | Read multiple properties in one request. **273-byte preallocated request body** (distinct from `0x4220`'s 222-byte form). |
| `0x0050` | — | **StatusQuery** | Leaks supervisor name (bare form) without authentication; useful cold-discovery primitive |
| `0x0981` | `0x0961`/`0x0971`/`0x0981` | **EnumeratePoints** | Panel-wide point enumeration. Cursor-based (multi-roundtrip). Three variants for FLN/panel/subnet scope. |
| `0x0985` | — | **EnumeratePrograms** | Enumerate PPCL programs — response carries source text |
| `0x0986` | — | **EnumerateFLN** | Enumerate FLN devices attached to a panel |
| `0x0100` | `0x0118` | **SystemInfo (legacy) / Connect-response** | Firmware/identity query (legacy-dialect firmware). Also the CONNECT-response opcode on firmware build `PME1252` (V2.8.10) — those builds echo this in the `0x2E` body instead of `0x4640`. **High-frequency on legacy firmware**; implementers MAY observe traffic shapes beyond firmware/CONNECT-response that this specification does not document. |
| `0x010C` | — | **SystemInfo (compact)** | Firmware/model query (newer panels, 2-byte request) |
| `0x4106` | `0x0xxx` | **DefinePpcl** | Define/load a PPCL program |
| `0x4103` | `0x04xx` | **PpclClearTrace** | Clear PPCL trace bits |
| `0x4100` | — | **PpclLineUpdate** | Update a single PPCL line; carries SYST scope footer |
| `0x5020` / `0x5022` | — | **Schedule writes** | Schedule add/modify operations |

### 6.3 Opcode Variants

Adjacent opcodes often represent variants of the same operation. For example, the **RegisterCOV** family:

- `0x0220` = basic
- `0x0221` = with extended attributes
- `0x0222` = with quality
- `0x0223` = with on-change-only flag

Variant selection is encoded by the specific opcode value, not by a sub-opcode bit. Implementers MUST handle all variants explicitly.

### 6.4 Reserved and Vendor-Extended Ranges

| Range | Status |
|---|---|
| `0x0000`-`0x6FFF` | Standard AP2 operations |
| `0x7000`-`0xEFFF` | Reserved |
| `0xF000`-`0xFFFF` | Vendor-extended operations (sub-opcode high byte `0xE3` observed) |

### 6.5 Complete Opcode Reference

See Appendix D for the complete (opcode → sub-opcode → name) table. §6.6 documents wire opcodes that are polymorphic (multiple distinct operations sharing one opcode value).

### 6.6 Polymorphic Wire Opcodes

**Several AP2 wire opcodes are polymorphic** — the same opcode value is used by multiple distinct operations that share only the wire-opcode byte. The operations are distinguished by **body shape**, not by the opcode alone. A parser that pattern-matches on opcode alone will misroute these.

Polymorphism arises from two structural causes:

1. **Multiple operations share one wire opcode.** Several logical operations are encoded with the same opcode value; each operation produces a body shape characteristic of its semantics.
2. **Transport-layer and application-layer share an opcode.** `0x4640` is the canonical example: it functions as a 10-second transport-layer keepalive in normal operation, while a rare application-layer replication-change operation uses the same wire opcode.

The eight currently-known polymorphic wire opcodes:

| Wire opcode | Use A (dominant) | Use B (rare) | Disambiguator |
|---|---|---|---|
| `0x4640` | Transport-layer 10 s heartbeat / IdentifyBlock | Replication-change push (CPI `0x1604`) | Body carries `0x4640` TLV identity payload → heartbeat; body carries replication-change list → ReplChanges |
| `0x4100` | PPCL line write (carries program-name + line-content + SYST footer) | Equipment-schedule member-log report (CPI `0x0675`) | Body bytes after opcode: PPCL text → line write; EQS member-log structure → log report |
| `0x010C` | SysInfo / firmware fetch (2-byte request, ~269 B response) | Buffer-alarm-state read (CPI `0x0132`) | Request body length 2 bytes → SysInfo; longer body → alarm-state read |
| `0x0509` | AlarmAck (compact, class header + point name) | BACnet MS/TP controller-value report (CPI `0x1137`) | Routing: DCC → PXC short body → AlarmAck; longer body with MSTP-controller TLVs → MS/TP value report |
| `0x0291` | SYST property write (value-bearing body) | Trend delete (CPI `0x0701`) | Body carries `01 00 c8 [type] [f32]` value marker → property write; trend-id payload → trend delete |
| `0x0606` | Lightweight heartbeat / panel-name probe | Holiday-spec read (CPI `0x1342`) | 14-byte constant body → heartbeat; calendar-spec body → holiday read |
| `0x0961` | Legacy AnalogPointQuery / EnumeratePoints (FLN scope) | Access-group replace (CPI `0x0917`) | Body carries scope TLV + cursor → enumerate; access-group payload → access-group op |
| `0x0964` | TitleAnalogQuery (value + units + limits) | Trend-definition upload (CPI `0x0705`) | Body carries point-name TLV → TitleAnalogQuery; trend-definition payload → trend upload |

A parser that receives any of these opcodes MUST inspect the body to determine which use is in play. A dissector or IDS that labels frames by opcode alone will mislabel the polymorphic cases.

In normal BLN traffic, Use A is by far the dominant case. Most clients (scanners, dissectors) only need to handle Use A. Use B is documented for completeness because some workflows and newer firmware exercise it occasionally.

---

## 7. CPI Sub-Opcode Namespace

The **CPI function code** (Common Protocol Interface) is the supervisor's internal dispatch identifier for each AP2 operation. It is a 2-byte value held in the in-memory `AP2Cmd` structure at offset `+0x06`, immediately after the wire opcode at `+0x04`.

The relationship between CPI codes and wire bytes is **not one-to-one**:

- For many operations (e.g. `0x0274` ValuePush with CPI `0x0001`), the CPI code is emitted onto the wire as the 2 bytes immediately following the wire opcode. In these cases the CPI code is observable directly.
- For some operations, the wire bytes following the opcode are `0x0000` regardless of the in-memory CPI code (e.g. `0x0271` reads as observed in operation use `00 00` after the wire opcode even when the supervisor's internal CPI code differs).
- For `0x4640` IdentifyBlock, there is no separate CPI byte pair on the wire — TLV data starts immediately after the wire opcode.

A wire-level parser should treat the bytes immediately after the wire opcode as opcode-specific and consult the per-opcode definitions in §6 and §12. The CPI namespace clustering below is most useful for understanding which operations belong to which supervisor-side family.

### 7.1 CPI Namespace Map (high-byte clustering)

| CPI high byte | Namespace | Wire opcode family |
|---|---|---|
| `0x00xx` | COV / value primitives | `0x0240`, `0x0241`, `0x0271`-`0x0273` |
| `0x01xx` | Point definition / modification | `0x005B`, `0x0100`-`0x0140`, `0x0303`-`0x0327`, `0x5332`-`0x5355` |
| `0x02xx` | Identification / parameter | `0x0030`, `0x0044`, `0x0059`, `0x0302`, `0x410F`-`0x4110`, `0x4628`-`0x462E`, `0x4644`-`0x4645` |
| `0x03xx` | BLN / connection ops | `0x0540`-`0x054D` contiguous range |
| `0x04xx` | PPCL programs | `0x4107`, `0x4108`, `0x410E`, `0x412A`, `0x4137` |
| `0x06xx` | Schedule transport | `0x5001`-`0x5054` |
| `0x07xx` | Alarm / event extended | `0x0294`, `0x0295`, `0x02A1`, `0x4842` |
| `0x08xx` | Network / node status | `0x09BD`, `0x09BF` |
| `0x09xx` | Time-of-day / timer | `0x0332`-`0x0357` |
| `0x0Axx` | Trend ops | `0x3807`, `0x3809`, `0x3817` |
| `0x0Bxx` | PPCL / state-set catalog | `0x0401`-`0x040E` (PPCL programs, state-set labels) |
| `0x0Exx` | Trend extended | `0x0360`-`0x0367` |
| `0x0Fxx` | Alarm priority / ack | `0x0509`, `0x0567` |
| `0x10xx` | BACnet ops | `0x4000`, `0x400B`, `0x400C`, `0x4017` |
| `0x11xx` | Bulk property / modify | `0x4200`, `0x4967`, `0x0313` |
| `0x12xx` | Sensitivity / diagnostic | `0x4245` |
| `0x13xx` | Modify / maintenance | `0x0600`-`0x0615` |
| `0x15xx` | Network maintenance | `0x4300`, `0x4332` |
| `0x16xx` | **Replication / Discovery** | `0x4633` (CPI `0x1601`), `0x4635` (`0x1603`), `0x4636` (`0x1604`), `0x4640` (`0x1600`) |
| `0x20xx` | BLN management | `0x4824`-`0x4B03` cluster, `0xF038` |
| `0xE3xx` | Vendor-extended | `0x0031`, `0x0032`, `0x0033` |

### 7.2 Inherited Sub-Opcodes

Not every opcode explicitly emits a sub-opcode value at `[+0x06]`. Approximately one-third of opcodes emit an explicit value; the remainder carry an inherited class-default value, which is typically the high-byte cluster's base. When parsing, treat absence of an explicit sub-opcode write as "use the family default" rather than as an error.

### 7.3 Notable (opcode, sub-opcode) Pairs

| AP2 opcode | CPI sub-opcode | Role |
|---|---|---|
| `0x4640` | `0x1600` | Discovery EPing (intra-site heartbeat base) — transport-layer dominant use |
| `0x4640` | `0x1604` | Replication-change push — application-layer use, rare. See §6.6 for the polymorphism. |
| `0x4633` | `0x1601` | Replication notification — init |
| `0x4635` | `0x1603` | Replication notification — event |
| `0x4636` | `0x1604` | Replication changes (the actual update push) |
| `0x4106` | (PPCL family) | DefinePpcl |
| `0x4103` | (PPCL family) | PpclClearTrace |
| `0x0274` | `0x0001` | ValuePush (COV) |
| `0x0240` | `0x0004` | WriteWithQuality |
| `0x0509` | `0x0F01` | AlarmAck (v2; writes `0x0F01` at `[+0x06]`. `0x0500` AckAlarm legacy uses CPI `0x0F01` but does not emit it on the wire) |

---

## 8. AP2Cmd Object Structure

When implementing a P2 protocol stack, it is useful to model each operation as an AP2Cmd object. The canonical in-memory layout is:

```c
struct AP2Cmd {
    void*    vtable;            // [+0x00] virtual dispatch table pointer (if using C++)
    u16      wire_opcode;       // [+0x04] AP2 wire opcode (little-endian in memory, big-endian on wire)
    u16      cpi_sub_opcode;    // [+0x06] CPI sub-opcode / function code
    u8       reserved[8];       // [+0x08-0x0F] object state, link pointers
    void*    payload;           // [+0x10] pointer to payload buffer or inline data
    u8       state[0x44];       // [+0x14-0x57] operation-specific state
    u32      extended_a;        // [+0x58] extended payload field A (24 opcodes use this)
    u32      extended_b;        // [+0x5C] extended payload field B (22 opcodes use this)
    u8       trailing[0x14];    // [+0x60-0x73] reserved trailer
};
```

Total size: 0x74 (116) bytes. This layout is canonical for every opcode in the protocol.

### 8.1 Serialization

When serializing an AP2Cmd to the wire:

1. Open the connection (or use an existing one) and write the session header (12 bytes including length, msg_type, sequence).
2. Write the direction byte.
3. Write the four addressing strings as NUL-terminated ASCII.
4. Write `wire_opcode` as 2 big-endian bytes.
5. Write `cpi_sub_opcode` as 2 big-endian bytes.
6. Write the operation-specific payload.

### 8.2 Deserialization

When deserializing:

1. Read 4 bytes for `total_length` (u32 BE). The full frame is exactly `total_length` bytes on the wire; buffer until `total_length` bytes are available before continuing.
2. Read 4 bytes for `session_msg_type`.
3. Read 4 bytes for `sequence_number`.
4. Read 1 byte for `direction` (see §8.3 for direction values, including error responses).
5. Read four NUL-terminated strings (slots 1 through 4).
6. Read 2 bytes for `wire_opcode` (big-endian).
7. Read 2 bytes for `cpi_sub_opcode` (big-endian).
8. The remaining bytes (up to `total_length` from the start of the frame) are the operation-specific payload; consult the per-opcode definition.

### 8.3 Direction Byte Values

The single-byte `direction` field at offset 12 takes one of three values:

| Value | Name | Meaning |
|---|---|---|
| `0x00` | **REQUEST** | Client-to-server request (or initial message) |
| `0x01` | **SUCCESS** | Server-to-client success response |
| `0x05` | **ERROR** | Server-to-client error response. **The next 2 bytes (big-endian u16) are the error code.** |

An error response (`direction = 0x05`) has body layout:

```
0x05 <error_code_u16_BE>
```

The error response body is exactly 3 bytes; no trailing context follows the error code (see §10.3). The error code identifies the failure reason; see §10 for the catalog of common error codes.

### 8.4 Sequence Number Convention

The 4-byte `sequence_number` field is per-connection monotonically increasing. Implementers SHOULD:

- Initialize the sequence to a **random 24-bit value** at connection establishment (not zero — sequence values of 0 or 1 are recognizable scanner fingerprints and may be rejected by stricter firmware).
- Increment by 1 for each request sent.
- Echo the request's sequence in the response (servers do this automatically).
- Tolerate wrap-around after `2^32` requests; no special handling is required.

A panel may reject handshakes with sequence numbers that appear to come from a replay or a non-conformant client. Generate fresh sequences per connection attempt.

---

## 9. Connection Establishment and Handshake

The protocol requires a session-establishment handshake **before any operational request will be accepted**. A panel that receives a request without a prior handshake will silently drop it.

### 9.1 TCP Connection

The client opens a standard TCP connection to the panel's listening port (typically TCP/5033). Once the three-way handshake completes, the client MUST send an identity message before issuing any other operation.

### 9.2 Identity Message Frame

The identity message uses wire opcode `0x4640` (the same opcode used for in-session EPing) carried inside a session frame. The full byte layout, from frame start:

```
Field                              Size  Value/Description
-----                              ----  -----------------
total_length                       4     Total wire length of this frame, BE (includes these 4 bytes; see §4.2)
session_msg_type                   4     0x00000033 (legacy) or 0x00000034 (modern); see §11
sequence_number                    4     Random 24-bit initial value, BE
─── ROUTING BLOCK ───
direction                          1     0x00 (request)
slot 1: BLN name                   z     NUL-terminated: BLN name (case-sensitive match required by panel bouncer)
slot 2: destination node name      z     NUL-terminated: name of the target panel (case-insensitive match against panel's known peer list)
slot 3: BLN name (repeated)        z     NUL-terminated: identical to slot 1
slot 4: source / scanner name      z     NUL-terminated: client's self-identifier (e.g. "DCC-SVR|5034" or "P2SCAN|5034")
─── IDENTITY BLOCK ───
wire_opcode                        2     0x4640 (BE)
tlv1_tag                           1     0x01 (string TLV tag)
tlv1_length                        2     u16 BE — length of scanner_name string
scanner_name                       var   raw ASCII (no NUL terminator)
tlv2_tag                           1     0x01
tlv2_length                        2     u16 BE — length of site_name string
site_name                          var   raw ASCII
tlv3_tag                           1     0x01
tlv3_length                        2     u16 BE — length of BLN name (matches slot 1/3)
network_name                       var   raw ASCII
trailer_separator                  1     0x00
flag_bytes                         3     0x01 0x01 0x00 (third byte = role flag; 0x00 = "configured peer")
reserved                           5     0x00 0x00 0x00 0x00 0x00
timestamp                          4     Unix epoch seconds, BE u32 (panels may reject suspiciously old timestamps)
session_id                         2     0x00 0x00 (zero session-id is accepted; supervisors use non-zero session-stable values)
trailing_null                      1     0x00
```

The **trailer is exactly 16 bytes** (separator + 3 flag bytes + 5 reserved + 4 timestamp + 2 session-id + 1 null).

The IdentifyBlock body starts the first TLV immediately after the 2-byte wire opcode `46 40`. There is no separate sub-opcode field for `0x4640` (see §4.2). The 3 TLVs (scanner self-name, site code, BLN name) are followed by the 16-byte trailer.

A note on the inner length encoding: the TLV format is `[tag 0x01][u16 BE length][value]` — a 3-byte header before each string value. Names are nearly always under 256 characters, so the high byte of the length field is zero in practice (a 7-byte name "SITEBLN" encodes as `01 00 07 53 49 54 45 42 4C 4E`). Implementers MUST emit the length as a u16 BE, not as a single byte; a 1-byte length will produce frames that don't parse against any real Siemens stack.

### 9.3 Three Identifiers Required

To establish a session, a client MUST know three identifiers:

1. **BLN name** (network name) — the unique BLN name configured on the panel. Panels REJECT messages whose BLN name doesn't match their configuration. This is a soft authentication / addressing check.
2. **Site name** — the site identifier. Often shared across all BLNs at a physical location.
3. **Scanner name** — the client's self-identifier in `<HOSTNAME>|<PORT>` format. Some sites expect a specific format (e.g. `<SITE>DCC-SVR|5034`); if handshakes fail, try this variant.

The BLN name can be learned by:
- Reading site configuration documents
- Sniffing existing traffic on the network (BLN name appears in every frame)
- Inspecting traffic captured at the site
- The `0x0050` StatusQuery opcode (leaks the supervisor name without authentication)

### 9.4 Handshake Response

A successful handshake response has:

- `session_msg_type` = same as the request (0x33 or 0x34)
- `sequence_number` = same as the request (echoed)
- `direction` = `0x01` (SUCCESS)
- Body containing the panel's identity (BLN name, node name, etc.) and a confirmation echo of the client's identity

A panel that receives a handshake with a mismatched BLN name will typically close the connection without responding, or send an error response with code indicating the BLN-name mismatch.

### 9.5 Identity Refresh

The `0x4640` opcode is also used **mid-session** as a periodic identity refresh / EPing. The body format is identical to the initial handshake.

The cadence used by Desigo CC is **exactly 10.0 seconds** per established TCP connection, matching the default "Intra-site EPing Period" of 10 s (see §13.2.1). Clients SHOULD match this cadence to be indistinguishable from a real supervisor; the protocol also tolerates longer intervals on most firmware. A client that allows more than 60 s of idle time MAY have its connection closed by the panel.

### 9.6 Inner TLV Format

The IdentifyBlock body uses a simple Tag-Length-Value form for its strings:

```
tag          u8   always 0x01 (string tag)
length       u16  big-endian, length of value field
value        var  raw ASCII bytes (no NUL terminator)
```

This inner TLV format also appears in DATA message bodies for point names, device names, and response payloads. It is **distinct from** the outer routing-header strings, which are NUL-terminated with no length prefix.

The three TLV entries in the IdentifyBlock (in order):

1. **Self-name TLV** — sender's own node name; must match slot 4
2. **Site code TLV** — site identifier
3. **BLN name TLV** — BLN name; must match slots 1 and 3

### 9.7 The Role Flag

The third byte of the `01 01 XX` flag triplet in the 16-byte trailer is the **role flag**. It signals the sender's relationship to the recipient:

| Sender | Context | Third flag byte | Meaning |
|---|---|---|---|
| Supervisor (Desigo CC) | Outbound CONNECT to panel | `0x00` | Standard configured peer |
| Panel | Outbound CONNECT to **legitimately-configured supervisor** | `0x00` | Configured peer (commissioned via panel NVRAM) |
| Panel | Outbound CONNECT to **runtime-registered peer** | `0x01` | Peer registered at runtime (typically through an inbound CONNECT) rather than commissioned |

**For client implementations**: send `flags = 01 01 00` matching what Desigo CC and panels both send to legitimately-configured peers. The `0x01` value is a panel-side outbound signal and is not required from supervisor-emulating clients.

### 9.8 The Session Identifier

Bytes at trailer offsets 13-14 (2 bytes) are a session identifier with distinct conventions by sender:

| Sender | Value | Notes |
|---|---|---|
| Panel | `0x00 0x00` | Panels do not set this field; always zero |
| Supervisor (Desigo CC) | non-zero, session-stable | A single supervisor↔panel session uses one value throughout its lifetime; e.g. `0xFE 0x98` |

Since panels successfully establish sessions with `0x00 0x00`, the panel-side bouncer accepts this value. A scanner that uses `0x00 0x00` matches what real panels send.

The exact derivation of the supervisor's non-zero value is implementation-specific — it may be a hash of session parameters, a counter, or a random nonce per session. A scanner that wants to mimic Desigo CC could copy a value from observed traffic, but doing so risks colliding with an active session.

### 9.9 The Embedded Timestamp

Bytes at trailer offsets 9-12 (4 bytes) are a **big-endian 32-bit Unix epoch timestamp** in seconds. The preceding byte is always `0x00` (padding or a u40 high byte).

The panel validates (or at least logs) this timestamp. A scanner sending CONNECT with a wildly wrong timestamp may be rejected or flagged in panel logs. Always encode `int(time.time())` as big-endian into these bytes.

### 9.10 The Bouncer — Identity Validation

The panel validates incoming handshake fields with two distinct failure signatures:

| Field | If wrong | Why |
|---|---|---|
| **BLN name** | TCP RST | BLN is both security AND routing. Wrong BLN means the panel has no valid route for the packet. Case-sensitive. |
| **Slot 2 (destination panel name)** | Silent drop | TCP connection stays up; the frame is silently discarded by the routing layer. Slot 2 must case-fold-match a name in the panel's known peer list. |

**Other fields are NOT validated:**

- The **source identity in slot 4** can be any string — a scanner does not need to impersonate a real supervisor name.
- The **IdentifyBlock body fields** (self-name TLV, site code TLV, BLN TLV) are not validated beyond internal consistency with the routing slots.
- The **trailer bytes** (timestamp, session ID, role flag) are not validated as authentication, though the panel may log them.

This means a read-only scanner only needs to know two things to establish a session: the **BLN name** (exact case-sensitive match) and **at least one panel name** (case-insensitive). Everything else is decorative.

The distinct BLN-RST vs slot-2-silent behavior is what makes cold-site BLN discovery tractable: a scanner can enumerate BLN candidates in parallel by observing TCP RST vs silent drop, without sending actual reads. See §22 (Cold-Site Discovery) for the full algorithm.

### 9.11 The Three Connection Modes

In operation, three distinct connection patterns occur. **Implementations MUST recognize all three or they will mis-frame traffic.**

| Mode | First-frame type | Subsequent frames | Identity exchange? | Where seen |
|---|---|---|---|---|
| **Mode A: Standard handshake** | `0x2E` CONNECT | `0x33` / `0x34` operational frames | Yes — CONNECT carries IdentifyBlock | Steady-state Insight / Desigo sessions; all `5033`-side polling |
| **Mode B: Reverse handshake** | `0x2F` ANNOUNCE | `0x33` / `0x34` operational frames | Yes — symmetric to Mode A but panel-initiated | Panel → supervisor connections to TCP `5034` |
| **Mode C: Single-msg-type carrier** | `0x2E` or `0x2F` | **Every** subsequent frame is also `0x2E` (or `0x2F`) | Optional — see two sub-variants below | Schedule-edit and PPCL-edit sessions; specific Desigo workflows; alarm bursts |

**Mode C is easy to miss.** The defining property of a Mode C connection is that the message-type byte never transitions from `0x2E`/`0x2F` to `0x33`/`0x34` for the entire lifetime of the TCP connection. Operational opcodes (reads, writes, schedule ops, alarms) all ride inside `0x2E` (or `0x2F`) framing.

Within Mode C there are **two sub-variants**:

| Mode C sub-variant | First frame | Use case |
|---|---|---|
| **Mode C with handshake** | `0x2E`/`0x2F` carrying a normal `0x4640` IdentifyBlock | A regular session that uses CONNECT/ANNOUNCE framing for its operational frames instead of switching to `0x33`/`0x34` |
| **Mode C headless** | `0x2E`/`0x2F` going straight to an operational opcode (`0x0961`, `0x0969`, `0x0271`, `0x0508`, etc.) — no `0x4640` at all | Short bursty workflows: schedule queries, ad-hoc reads, alarm pushes. A fresh TCP connection is opened just to fire a few opcodes and tear it down. |

Mode C is **not** uniquely supervisor-initiated. Both directions exist: supervisor→panel (schedule ops) and panel→supervisor (reads, alarm reports).

A dispatcher that only handles `0x33`/`0x34` will silently drop every byte of a Mode-C-headless session. A correct dispatcher accepts opcode payloads inside `0x2E` and `0x2F` whenever the first two bytes after the routing header are not `0x46 0x40`. The marker selector is:

- First 2 bytes after routing header == `0x46 0x40` → IdentifyBlock (Mode A/B initial frame, Mode-C-with-handshake initial frame, or mid-session identity refresh)
- Otherwise → operational opcode (treat the 2 bytes as a wire opcode)

`0x4640` IdentifyBlock TLVs can also appear mid-session inside `0x2E`/`0x2F` frames as periodic identity refreshes — these are normal in any mode and not a mode-transition signal.

### 9.12 CONNECT (`0x2E`) and ANNOUNCE (`0x2F`) Format

These two message types carry **structurally identical payloads**. The only differences are the message-type code (`0x2E` vs `0x2F`) and minor byte-length variation for embedded node names.

The body layout is the same as the identity message documented in §9.2: routing header (direction + 4 NUL-terminated names) followed by the `0x4640` IdentifyBlock with TLVs and 16-byte trailer.

CONNECT is typically used in the supervisor → panel direction (Mode A). ANNOUNCE is typically panel → supervisor (Mode B). Both carry an identity exchange.

### 9.13 Bare-Opcode Session Keepalives

Within an established Mode A session, panels send 2-byte bare-opcode keepalive frames to the supervisor. These are panel → supervisor only, no body, no response expected. Common bare opcodes:

- `0x0951`, `0x0954`, `0x0955`, `0x0956`, `0x0959` — session keepalive pings

These are distinct from Mode C frames:

| Feature | Bare-opcode ping | Mode C frame |
|---|---|---|
| Frame body size | Exactly 2 bytes | 30–250 bytes |
| TCP state | Mid-session after a Mode A handshake | Immediately after TCP three-way handshake on new connection |
| Direction | Panel → supervisor only | Bidirectional |

### 9.14 Frame-Length Calculation

The `total_length` field at offset 0 is the **total length of the entire frame on the wire**, including the 4 bytes occupied by the length field itself. The 12-byte session header (length + msg_type + sequence) and the payload that follows are both counted:

```
total_length = 4 (length field) + 4 (msg_type) + 4 (sequence) + payload
             = 12 + payload
```

A receiver that has read the first 4 bytes needs to read `total_length − 4` additional bytes to complete the frame. Receivers SHOULD reject frames with `total_length > 65536` as framing corruption and close the connection.

---

## 10. Error Responses and Error Codes

### 10.1 Error Response Format

A panel signals an operation failure with `direction = 0x05`, followed by a 2-byte big-endian error code:

```
0x05 <error_code_BE_u16>
```

The error response body is **exactly 3 bytes** (direction + 2-byte code) with no trailing payload — see §10.3. Earlier vendor documentation described an optional context-bytes tail; current firmware does not emit one. Clients SHOULD rely on the error code as the canonical failure indication and SHOULD log the routing header (slot 4) to identify the responding panel.

### 10.2 Error Code Catalog

Error codes use the Siemens E-code naming convention (`E<decimal>` form). The table below covers both the codes commonly returned in normal operation and the broader vendor-documented catalog.

**Common codes:**

| Code (hex) | E-code | Name | Meaning / Typical trigger |
|---|---|---|---|
| `0x0002` | E2 | **object_unknown** | Returned by scope-restricted operations (e.g. `0x0244`) when the target is out of the requesting scope |
| `0x0003` | E3 | **not_found** | Object does not exist. The dominant error in normal operation; returned by point-existence probes and reads against unconfigured names. |
| `0x00AC` | E172 | **not_supported** | P2 or P3 command not implemented on this firmware revision |
| `0x0E11` | E3601 | **already_exists / device_failed** | `0x0204` (CreateObject) when named object already present. Supervisors typically treat as idempotent success. |
| `0x0E15` | E3605 | **physical-point-not-commandable** | `0x0240` (WriteWithQuality) written against SYST-tagged property. Retry with `0x4222` BulkPropertyWrite. |

**Vendor-documented (rare or firmware-specific; implementers SHOULD recognize them but may not encounter them in normal operation):**

| Code (hex) | E-code | Name | Meaning |
|---|---|---|---|
| `0x0001` | E1 | no_memory_available | Panel out of dynamic memory for the operation |
| `0x0004` | E4 | priority_too_low | Command priority insufficient to override current point state |
| `0x0005` | E5 | failed_no_change | Operation failed; point state did not change |
| `0x0007` | E7 | out_of_service | Point or device is in out-of-service state |
| `0x0008` | E8 | field_panel_general_error | Generic panel-side failure |
| `0x0009` | E9 | already_exists | Object already exists (sibling of E3601) |
| `0x000A` | E10 | trend_already_exists / value_unchanged | Trend definition exists or value unchanged |
| `0x000B` | E11 | value_out_of_range | Value parameter outside acceptable range |
| `0x000C` | E12 | not_hostcaller_node / line_not_traced | PPCL line not configured for tracing |
| `0x000D` | E13 | line_not_enabled / line_already_exists | PPCL line state mismatch |
| `0x0016` | E22 | has_unresolved_points | PPCL or zone has unresolved point references |
| `0x0028` | E40 | line_accessed_not_traced | PPCL tracebit condition |
| `0x0040` | E64 | TIU_busy | Trunk Interface Unit busy |
| `0x0065` | E101 | command_not_supported | Function-level not-supported (sibling of E172) |
| `0x0080` | E128 | point_in_HAND_mode | Point is in HAND override; cannot be commanded remotely |
| `0x0081` | E129 | invalid_password | Authentication failure |
| `0x0082` | E130 | user_accounts_database_full | Cannot create user account |
| `0x00AB` | E171 | coldstart_required | Operation requires panel coldstart |
| `0x00B7` | E183 | operation_aborted_warmstart | Operation aborted due to warmstart |
| `0x00B8` | E184 | too_many_framing_errors | Communication-layer framing errors exceeded threshold |
| `0x00F9` | E249 | invalid_point_address | Point address format invalid |
| `0x00FA` | E250 | failed_IO_device | I/O device failure |
| `0x00FE` | E254 | monitor_list_full | COV monitor list full |
| `0x0200` | E512 | FLT_transfer_in_progress | Firmware Loading Tool transfer active |
| `0x0202` | E514 | FLT_transfer_killed | Firmware transfer aborted |
| `0x0203` | E515 | TEC_not_added | TEC device addition failed |
| `0x0205` | E517 | connection_lost | Network connection lost |
| `0x0206` | E518 | warm_started | Panel just warm-started; operation cannot proceed |
| `0x0207` | E519 | protocol_error | Low-level protocol error |
| `0x0209` | E521 | timeout | Server panel did not respond |
| `0x0210` | E528 | invalid_FLN_number | FLN number outside range 0-3 |
| `0x0E10` | E3600 | invalid_drop_number | Drop number outside range 0-98 (99 is invalid) |
| `0x0E12` | E3602 | invalid_point_number | Point number invalid |
| `0x0E13` | E3603 | physical_point_failed | Underlying physical point failed |
| `0x0E14` | E3604 | physical_point_not_commandable | Sibling of E3605 |
| `0x0E16` | E3606 | value_out_of_range | Sibling of E11 |
| `0x0E17` | E3607 | application_invalid_for_device | App number not valid for device type |

### 10.3 Error Response Body Size

**Error response payload is exactly 3 bytes**: 1-byte direction `0x05` + 2-byte error code. No opcode is echoed and no trailing context bytes follow the error code.

Parser implication: when the direction byte is `0x05`, read exactly 2 more bytes for the error code and stop. Do not scan for a value block, and do not expect the request opcode to be echoed.

### 10.4 Status Byte Check Is Mandatory

A naive parser that doesn't check the status byte first will attempt to parse an error response's `0x00 0x03` (the bytes of error code 0x0003) as the start of a point value block and hallucinate a value. The first-byte check (direction = `0x00` / `0x01` / `0x05`) is cheap and mandatory.

### 10.5 Handling Errors

Implementers SHOULD:

1. Treat any `direction = 0x05` response as an authoritative failure for the operation that triggered it.
2. Log the error code, operation, and target object for diagnostics.
3. NOT retry the same operation unless the error code is known to be transient (most are not).
4. For `0x0E15` specifically, transparently retry the write as `0x4222` BulkPropertyWrite.

---

## 11. Firmware Dialect Detection

Two firmware dialects are deployed across modern controllers; they differ in the `session_msg_type` they use for operational traffic. Implementers MUST detect which dialect a panel speaks before exchanging operational frames.

### 11.1 The Two Dialects

| Dialect | Used by | Operational `session_msg_type` |
|---|---|---|
| **Legacy** | Firmware builds `PME1252` and earlier (firmware revisions up to ~V2.8.10) | `0x33` (DATA) |
| **Modern** | Firmware builds `PME1300` and later (firmware V2.8.15+) | `0x34` (HEARTBEAT) |

The dialect is determined by the firmware build, not the hardware platform — both legacy and modern firmware run on the same PXC Modular (`PXME`) and PXC Compact (`PXCE`) silicon. A field upgrade from a legacy to a modern firmware build flips the dialect on the same physical controller.

Representative firmware revisions in each dialect:
- Firmware `PME1252` on hardware `PXME V2.8.10 APOGEE` (build Oct 2013) → legacy dialect
- Firmware `PME1300` on hardware `PXME V2.8.18 APOGEE` (build Sep 2019) → modern dialect

Both dialects can coexist on the same BLN. A retrofit site may have mixed legacy and modern panels; the supervisor handles each panel using its appropriate dialect.

A panel speaking the modern dialect will **silently drop** a handshake sent with `session_msg_type = 0x33` — no RST, no error response, just no reply. A panel speaking the legacy dialect responds normally to `0x33` and ignores `0x34`.

### 11.2 Recommended Detection Algorithm

```
1. Open the TCP connection.
2. Send the handshake with session_msg_type = 0x33 and a short timeout (≤2s).
3. If a response arrives:
     - Lock in the panel's response msg_type for all subsequent messages.
     - Cache the result (keyed by host) for future connections.
4. If no response arrives within the short timeout:
     - Drain the receive buffer.
     - Send a fresh handshake (new sequence number) with session_msg_type = 0x34.
     - Wait for a response with the full read timeout.
     - If a response arrives, lock in 0x34 for this session.
5. If neither dialect responds, the panel is unreachable or rejecting the handshake (mismatched BLN name, suspicious timestamp, etc.).
```

The short first timeout is critical: a 30-second wait per modern panel would make discovery painfully slow. Two seconds is enough for legacy panels (which respond in well under a second).

### 11.3 Additional Dialect Indicators

The four message-type bytes pair with the dialects as follows:

| Observed signal | Implies |
|---|---|
| Panel responds with `session_msg_type = 0x33` (DATA) | Legacy dialect; use `0x33` for all subsequent operational messages |
| Panel responds with `session_msg_type = 0x34` (HEARTBEAT) | Modern dialect; use `0x34` for all subsequent operational messages |
| Frame uses `session_msg_type = 0x2E` (CONNECT) | Legacy-dialect session-management frame (typically supervisor → panel, Mode A) |
| Frame uses `session_msg_type = 0x2F` (ANNOUNCE) | Modern-dialect session-management frame (typically panel → supervisor, Mode B) |

The four message types pair into two dialect groups: legacy = {`0x2E`, `0x33`}, modern = {`0x2F`, `0x34`}. Both dialects can coexist on the same BLN — different panels speak different dialects depending on their firmware vintage.

### 11.4 Caching

A scanner SHOULD cache the discovered dialect per panel IP. Repeated connections to the same panel within one process can then skip the probe. A cached value should be invalidated and re-probed if the cached message type stops eliciting responses (e.g., after a firmware upgrade).

---

## 12. Common Operation Body Formats

This section documents the body format for the most common operations. The body begins immediately after the 2-byte sub-opcode field; offsets in this section are relative to the start of the body.

The operations are organized as follows:

- §12.1 — SYST scope footer (a structural convention used by multiple opcodes)
- §12.2-§12.5 — Point reads (the four read-ish opcodes and ValuePush)
- §12.6-§12.9 — Writes (the `0x0240` → `0x4222` retry workflow)
- §12.10-§12.11 — Identification (`0x4634` RoutingTable, `0x010C` SystemInfo)
- §12.12-§12.16 — Enumeration (point, FLN device, PPCL program)
- §12.17 — Schedule operations
- §12.18-§12.19 — Display catalogs (multi-state labels, object display labels)
- §12.20 — PPCL editor opcodes
- §12.21-§12.22 — Alarms (`0x0508` AlarmReport, `0x0509` AlarmAck, `0x0273` AlarmAckTrigger)
- §12.23 — The PXC→supervisor push channel (TCP/5034) traffic mix

### 12.1 SYST Scope Footer

Operations targeting SYST-scoped objects carry a **trailing scope footer** in the request body. The footer is a length-prefixed scope marker appended after the main body content:

```
Body content...
01 00 04 "SYST" 23 3F FF FF FF        12-byte SYST scope footer
```

Byte breakdown (12 bytes total): 1-byte TLV tag `0x01` + 2-byte u16 BE length `0x0004` + 4-byte ASCII `"SYST"` + 1-byte separator `0x23` + 4-byte sentinel `0x3F FF FF FF`.

The presence of a SYST footer changes the operation's semantics — the panel routes the request through its system-scope handler rather than its FLN-scope handler. Operations with mandatory SYST footers include `0x4100` (PpclLineUpdate), `0x4103` (PpclClearTrace), `0x0263` (object delete), `0x0291` / `0x02A8` (SYST property ops).

Strip the footer and the panel rejects the request.

### 12.2 Detailed Point Read Wire Format

Both `0x0220` (modern) and `0x0271` (legacy) address points **by string name**, not by numeric ID. The wire request contains the device name and point name as adjacent TLV strings:

```
[opcode] [sub-opcode bytes] [device TLV] [point TLV] [trailer]
```

**Example request** (reading `TEC1:APPLICATION` via `0x0271`):

```
02 71 00 00 01 00 04 "TEC1" 01 00 0B "APPLICATION" 00 FF
└─┬─┘ └─┬─┘ └────┬─────┘ └──────┬─────────┘ └─┬─┘
opcode subop  device TLV     point TLV    trailer
```

**Two-byte trailer values** select the operation variant:

| Trailer | Used by | Semantic |
|---|---|---|
| `00 FF` | `0x0271` typical | Wildcard property / default value read |
| `00 00` | `0x0273` | No-value request (ACK-only, see below) |
| (omitted) | `0x0272` | "Look up the property descriptor without fetching its current value" |

The subpoint slot number (1-99 in Desigo CC's UI) is **not transmitted on the wire**. Clients resolve slot → name via the vendor's point-definition metadata and send the name.

### 12.3 BLN Virtual Point Reads (System-Wide Points)

When reading a BLN-sourced virtual point (panel-internal globals, schedules, alarm conditions — points that don't live on a specific TEC device), the request format changes:

**`0x0271` legacy form** (empty device TLV):

```
02 71 00 00 01 00 00 01 00 0D "OAT.MIRROR.BN" 00 FF
            └──┬──┘
         empty device TLV (length 0)
```

**`0x0220` modern form** (uses literal `"SYST"` as device name tag):

```
02 20 01 00 04 "SYST" 00 3F FF FF FF 00 00 01 00 0D "POINT.NAME" 01 00 00 00 00 01 00 00 01 00 00
            └────┬────┘                              └──────┬─────┘
            SYST tag                                 point name TLV
```

Both variants address the same underlying virtual point. Desigo CC emits both during the same operator action when probing a panel of unknown firmware vintage.

### 12.4 Four Read-ish Opcodes Are Distinct

A supervisor session typically uses all four reads mixed together. They are NOT four flavors of the same read:

| Opcode | Use case |
|---|---|
| `0x0220` | Compact read, preferred for high-volume polling; errors with `0x05 00 03` if point doesn't exist |
| `0x0271` | Canonical legacy read; returns full value block |
| `0x0272` | Property descriptor lookup (no value fetched); typically returns `0x0003 not_found` against current firmware |
| `0x0273` | Same wire shape as `0x0271` but trailer `00 00`. ACK-only response. Used as a point-existence probe AND as an AlarmAckTrigger pre-cursor for `0x0509` |

### 12.5 ValuePush `0x0274` — Bidirectional Semantic

The `0x0274` opcode has two distinct semantics, selected by which TCP port the frame travels on. This catches many parsers off guard because the opcode and sub-opcode are identical in both directions; only the body shape and the destination port differ.

**Supervisor → Panel on TCP/5033** (push-write of a BLN virtual into the panel's model):

```
[routing header]
02 74 00 01 00 00              opcode + header
01 00 0D "POINT.NAME"          point TLV
01 00 00 00 42 90 00 00        marker + empty TLV + f32 BE value (72.0 °F)
00                             trailer
```

The device field is implicit (BLN-sourced). Used by the supervisor to mirror values from other panels (e.g. outdoor air temperature read by one panel and pushed to other panels).

**Panel → Supervisor on TCP/5034** (genuine unsolicited COV notification):

```
[routing header: BLN / dest=supervisor / BLN / src=panel]
02 74 00 01 00 00              opcode + header
01 00 0A "VAV-12"              device TLV
01 00 09 "ROOM TEMP"           point TLV
42 90 00 00                    f32 BE value (72.0 °F)
00 00 00 00 00 00 00 00 00 00 00 00 00   trailer padding
```

Two TLVs (device + point) plus the f32 value. This is the genuine unsolicited COV that operators see when a panel reports a value change exceeding its COV threshold.

Implementers MUST branch on the listening port (or equivalent: direction of the TCP connection) to parse `0x0274` correctly.

### 12.5.1 The Four `(dst_port, msg_type)` Quadrants for `0x0274`

In real BLN traffic, `0x0274` frames split across four quadrants of `(destination TCP port, session_msg_type)`. The dominant signal for direction is `dst_port`; the `msg_type` byte tracks panel firmware dialect (§11):

| `(dst_port, msg_type)` | Relative frequency | Meaning |
|---|---|---|
| `(5034, 0x33)` | Dominant | PXC → DCC COV push, legacy dialect |
| `(5033, 0x33)` | Common | DCC → PXC virtual-write, legacy dialect |
| `(5033, 0x34)` | Less common | DCC → PXC virtual-write, modern dialect |
| `(5034, 0x34)` | Rare | PXC → DCC COV push, modern dialect |

A dissector or IDS classifying `0x0274` traffic SHOULD use the full `(dst_port, msg_type)` tuple rather than relying on opcode alone. The `msg_type` distribution also serves as a per-panel dialect probe: a panel that emits `0x0274` only with `msg_type = 0x34` is on modern firmware regardless of any handshake observation.

### 12.6 WriteWithQuality `0x0240` Wire Format

Two distinct wire shapes depending on which scope the write targets:

**Supervisor → Panel on TCP/5033, SYST scope** (returns error `0x0E15` — see §12.9):

```
[routing header]
02 40                          opcode
01 00 04 "SYST"                tag = "SYST"
23                             separator (0x23 marks SYST-scope write)
... addressing fields ...
... value bytes (f32 BE for analog, enum byte for digital) ...
00                             quality byte (0x00 = good, non-zero = degraded)
```

**Panel → Supervisor on TCP/5034, NONE scope** (BLN-sourced virtual report, accepted):

```
[routing header]
02 40                          opcode
01 00 04 "NONE"                device TLV (always "NONE" for panel-global virtuals)
00                             separator (0x00 marks NONE-scope)
3F FF FF FF                    wildcard / quality-default sentinel
00 00                          reserved
01 00 0A "AHU.OAT.BN"          point name TLV
01 00 00 00 00 01 00 00 01 00 00   marker pattern
42 6C 40 4C                    f32 BE value (59.0625 °F)
00                             trailer
```

The separator byte (`0x00` NONE vs `0x23` SYST) distinguishes the two shapes.

### 12.7 BulkPropertyWrite `0x4222` (The SYST Write Path)

The canonical opcode for SYST-scoped setpoint writes. Used when `0x0240` against a SYST-scoped point returns error `0x0E15`. The supervisor transparently retries the same write as `0x4222`, which succeeds.

Request body is a fixed preallocated structure (~273 bytes total request size including the routing header). Body layout carries:

- Target object addressing (device + point TLVs)
- The value to write
- Priority information
- Quality flags
- Padding/reserved bytes

Implementers building a setpoint-write feature SHOULD:

1. First attempt `0x0240` with separator `0x00` (NONE scope) or `0x23` (SYST scope) as appropriate.
2. On error `0x0E15`, retry as `0x4222` automatically.
3. Treat both `0x0240` and `0x4222` writes as semantically equivalent from the operator's point of view.

### 12.8 PropertyQuery `0x4200` — Two Forms

`0x4200` has two distinct request shapes:

| Form | Size | Use case |
|---|---|---|
| Small browse form | ~30-40 bytes | Quick property browse — list properties of a point or device |
| Preallocated deep-read form | 222 bytes | Full property descriptor retrieval — comparable to BulkPropertyRead |

The form selector is the body length and the marker bytes immediately after the opcode. Implementers should accept both shapes.

### 12.9 The `0x0240` → `0x4222` Retry Workflow

This is the canonical operator-changes-a-setpoint workflow:

```
1. Operator changes setpoint in supervisor UI.
2. Supervisor sends 0x0240 WriteWithQuality with SYST scope (separator 0x23).
3. Panel responds with error: direction 0x05, code 0x0E15.
4. Supervisor automatically retries the same logical operation as 0x4222 BulkPropertyWrite.
5. Panel acknowledges the 0x4222 write with direction 0x01 success.
6. The setpoint is now updated.
```

A scanner implementing setpoint writes MUST follow this exact retry pattern. A scanner that tries only `0x0240` will fail on every SYST setpoint write with `0x0E15` and have no obvious indication of why.

### 12.10 Routing Table `0x4634`

The `0x4634` opcode carries the BLN routing table — a list of every BLN peer the sender knows about. **Observed on both TCP/5033 and TCP/5034** (port-agnostic; either side may push it).

**Body format**:

```
46 34 00 00 00 00 0C 07 00 0E              header (10 bytes)
01 00 0D "$paneldefault" 00 00 00 0C        TLV name + u32 BE cost
01 00 06 "SITE" 00 00 05 BB
01 00 05 "NODE1" 00 00 0A 90
01 00 05 "NODE2" 00 00 0A 72
01 00 05 "NODE3" 00 00 09 DB
... one entry per known peer ...
01 00 0A "DCC-SVR" 00 00 09 AD
01 00 0F "DCC-SVR|5034" 00 00 0A E5
00 00 00 00                                  terminator (4 zero bytes)
```

Each entry is a TLV name (tag=0x01, u16 BE length, raw bytes) followed by a u32 BE cost/metric value.

**Cost is per-observer**, not a global topology constant. The same peer is reported with different costs depending on which panel publishes the routing table. Supervisor-published routing tables typically have lower cost values than panel-published tables for the same peer. Plausibly an EWMA of round-trip time or similar latency-derived metric.

**Special entries** that appear in every routing table:

- `$paneldefault` (cost always 12) — internal fallback / default-route placeholder. **This entry MUST appear as the first TLV in every `0x4634` body** without exception. A `0x4634` body whose first TLV is not `$paneldefault` is malformed; parsers SHOULD reject the frame rather than attempt to continue.
- A numeric-named entry (e.g. `101000`, cost ~1467) — possibly a legacy MS/TP gateway registration or site-code identifier
- The supervisor's BLN-registered name (e.g. `SITE-BMS`, cost ~5400)

Observing a single `0x4634` frame from a real supervisor reveals the complete BLN topology — every peer name, every cost metric, in one message. No brute-force enumeration is required to learn what nodes exist on the BLN.

### 12.11 System Info `0x010C` Wire Format

The smallest request in the protocol. Body is literally two bytes:

```
01 0C
```

Response (~269 bytes typical) decomposes as:

```
TLV: firmware-build tag    "PME1252 " or "PME1300 " (note trailing space).
                           Returned in a TLV that Siemens labels as panel
                           model, but the value is the firmware build
                           identifier (PME#### = P2 firmware family,
                           build ####), not a hardware model number.
TLV: hardware revision     "PXME V2.8.10 APOGEE" / "PXME V2.8.18 APOGEE"
                           (platform code + firmware version + branch).
                           PXME = PXC Modular Ethernet; PXCE = PXC Compact.
TLV: build date            "Oct 28 2013 12:31:01" / "Sep 26 2019 12:41:20"
16 bytes: feature bytes    (bit layout unmapped; byte ~0x68 encodes node number)
IdentifyBlock              standard TLV identity (node + site + BLN + flags)
~80 bytes: panel state     (bit fields — panel health, point counts)
20+ bytes: timing fields   (two 6-byte structures; may be schedule or trend metadata)
3-byte trailer             "00 03 00"
```

**`0x010C` can be carried inside either a `0x33` DATA or a `0x34` HEARTBEAT frame** depending on the panel's firmware dialect (§11). The opcode itself and response format are identical across both dialects.

`0x010C` is the simplest panel-aliveness probe and the most informative response — implementers should use it as the first read after handshake to identify the target panel.

### 12.12 EnumeratePoints `0x0981` Request Format

Cursor-based panel-wide point enumeration. Three sub-variants by scope:

- `0x0961` — FLN scope (per-device walk)
- `0x0971` — subnet scope (FLN-bus walk)
- `0x0981` — panel-wide (every point on the panel including panel-internal PPCL variables)

Request body:

```
09 81 00 00 01 00 04 "SYST" 01 00 00 00 00 00 00
└─┬─┘ └─┬─┘ └─────┬─────┘ └─┬─┘ └────────┬────────┘
opcode subop  scope TLV   cursor TLV   terminator
```

Start at cursor `0x0000` for the first request; the response carries a continuation cursor for subsequent requests. Iterate until cursor returns to `0x0000` or to a defined end-of-data sentinel (`0xFFFF` in some firmware).

### 12.12.1 Cursor Advancement and Compound-Name Entries

When a panel returns a compound-name entry (§12.13 SHAPE C — two name TLVs at the top), a single-name cursor cannot advance past it: the panel returns the same compound record indefinitely. The walker must mutate the cursor to force advancement.

**Cursor-mutation order — least- to most-disruptive.** A naïve byte-increment (`VAR1` → `VAR2`) is too aggressive — it skips adjacent entries with the same prefix (`VAR10.STPT`, `VAR10.TEMP`, `VAR1T`). The correct ordered strategy:

1. **Append `\x01`** — the smallest string strictly greater than the current cursor. Returns the very next adjacent entry. This is the safe first try and handles most compound-name stalls.
2. **Append a single character in ascending order**: `' '` (0x20), `'0'` (0x30), `'A'` (0x41), `'a'` (0x61), `'~'` (0x7E). Covers longer-prefix entries that `\x01` doesn't catch.
3. **Byte-increment the last character of the cursor.** Skips all same-prefix entries. Use only as last resort when the above strategies fail.

A walker advances by trying each strategy in order, accepting the response from the first strategy that returns a different entry than the stalled cursor's response.

### 12.12.2 TLV Framing Trap in Cursor Requests

The inner TLV format in `0x0981` (and `0x0985`, `0x0986`) cursor requests is `[tag: 1 byte = 0x01][length: u16 BE][value]` — **3 bytes of header** before each string value. An easy bug when writing the framer is to treat the header as `[\x01\x00][u16 length][value]`, which silently adds an extra zero byte of header and shifts every downstream length by one. This will parse fine in isolation because TLVs are length-delimited, but it corrupts fixed-position trailers.

**Symptom**: the panel returns the first matching entry and refuses to advance the cursor on continuation calls. The malformed framing causes the panel to interpret the cursor as a different value than the client intended.

### 12.13 EnumeratePoints `0x0981` — Three Response Shapes

The `0x0981` response carries a list of point entries. **Three distinct response shapes** appear across firmware revisions:

**SHAPE A** — used by older firmware. Each entry has:

```
01 00 LL <point_name>           name TLV
3F FF FF F? 00 00 00 XX          quality sentinel + data type code
<value_bytes>                   value (f32 for analog, byte for digital)
[optional units TLV]            01 00 LL <units string>
```

**SHAPE B** — used by newer firmware. Compact form:

```
01 00 LL <point_name>           name TLV
00 00 00 00 00 00 XX             metadata (XX = data type code)
<value_bytes>
```

**SHAPE C: Compound-name entries** — multi-part hierarchical names:

```
01 00 LL <name_part_1>
01 00 LL <name_part_2>
... more name parts ...
<value bytes>
```

Used for points with hierarchical addressing like `TEC1:VAV-12:ROOM TEMP`.

Implementers SHOULD detect the shape by inspecting the bytes after the first name TLV:

- `3F FF FF F?` prefix → SHAPE A
- `00 00 00 00 00 00 XX` pattern → SHAPE B
- Second `01 00 ...` immediately → SHAPE C

### 12.13.1 The Units-TLV Trap

A tempting shortcut when parsing SHAPE A or SHAPE B responses is "the trailing string TLV is the engineering-units label." This is **wrong** in two ways:

- **Binary points have no units TLV but do have values.** Examples like `PUMP1.RUN`, `PUMP1.ENB`, `PUMP1.ALM` return `3F 80 00 00` (= 1.0 for ON) or `00 00 00 00` (= 0.0 for OFF) with no trailing units string. A parser that requires a units TLV to extract a value will silently miss every binary point.
- **Descriptions can be short.** "VAV INLET" is 9 characters, "BLR 2 ALM" is 9 characters — well within the typical length range for units strings like "DEG F" or "IN H20". A naive length-based "short trailing TLV = units" heuristic will eat descriptions.

The reliable disambiguator is a whitelist of unit patterns: classify a trailing TLV as units only when its content matches alphanumerics + `%` + known space-bearing patterns like `DEG F`, `DEG C`, `IN H20`, `IN.WC`, `CFM`, `PSI`, `kW`, `kWH`, `RPM`. A trailing TLV that doesn't match the whitelist is a description string, not a units string.

### 12.14 Bare-Opcode `0x0220` as Alternative Walker

Some implementations use `0x0220` issued repeatedly with sequential slot numbers as an alternative to cursor-based `0x0981`. This works for known-application TEC devices: read slot 1 → APPLICATION, slot 2 → metadata, slots 3+ → application-specific subpoints. The walker stops when reads return `0x05 0x0003 not_found` for consecutive slot numbers.

This approach is slower than `0x0981` but avoids cursor-state management.

### 12.15 EnumerateFLN `0x0986` Request Format

Lists FLN devices attached to a panel:

```
09 86 00 00 01 00 04 "SYST" 01 00 00 00 00 00 00
```

(Same shape as `0x0981` with the opcode changed.)

Response carries entries each containing: device name, description string, application number (sometimes 0 — fall back to a per-device APPLICATION read), and status flags.

Some older firmware revisions return partial or empty responses to `0x0986`. The fallback for those panels is brute-force dictionary probing against common device-name patterns (`TEC1`, `TEC2`, ..., `VAV001`, ...).

### 12.16 EnumeratePrograms `0x0985` Request and Response

Lists PPCL programs loaded on the panel and returns their source text.

**Request body**:

```
09 85 00 00 01 00 04 "SYST" 01 00 0A "<prog_name>" 00 <cursor> 00 00 00
```

The program name field can be empty in the first request to retrieve the first program; subsequent requests use the cursor to page through.

**Response body** includes:

- Program metadata (name, line count, status)
- Source text as a series of line TLVs
- `has_more` flag in the trailer (1 byte): `0x01` = more programs / lines, `0x00` = last entry

### 12.17 Schedule Operations (09xx and 5xxx families)

Schedule operations cluster in two opcode ranges:

**`09xx` family** (request/response model):

- `0x0961` / `0x0964`–`0x0976` / `0x0979` / `0x098B`–`0x098F` — schedule entry queries

**`0x098D` wire format** (schedule entry read):

```
09 8D <body with target schedule reference and entry index>
Response: list of schedule entries with day-of-week, time-of-day, value
```

**`0x0976` wire format** (DeviceAllSubpointsRead):

A panel-wide bulk read of all subpoints of a device, returning a long response with one TLV per subpoint.

**`5xxx` family** (property-write model):

- `0x5022` — schedule slot init
- `0x5020` — schedule entry write

These write new schedule entries and modify existing ones.

### 12.18 Multi-State Label Catalog `0x040A`

Returns the state-text labels for a multi-state point (e.g., `{ON, OFF, AUTO}` for an LOOAL point).

**Request**:

```
04 0A <target_point_address>
```

**Response**: a list of TLV strings, one per state, in state-index order. The state byte value (0, 1, 2, …) maps to the string at the corresponding index.

### 12.19 Object Display Labels `0x5038`

Returns the user-facing display labels and descriptors for a point or device.

**Request — first call** (with cursor=0): retrieves the first batch.
**Response**: a list of (label, descriptor) pairs.

### 12.20 PPCL Editor Opcodes (`0x4100` / `0x4103` / `0x4104` / `0x4106`)

PPCL programs are modified via this opcode family:

| Opcode | Operation |
|---|---|
| `0x4100` | PpclLineUpdate — update a single line in a program (carries SYST scope footer) |
| `0x4103` | PpclClearTrace — clear trace bits (carries SYST scope footer) |
| `0x4104` | PpclEnable — enable/disable a line |
| `0x4106` | DefinePpcl — load a complete PPCL program |

All PPCL editor opcodes carry a **trailing SYST scope footer** after the main body content (see §12.1).

### 12.21 Alarm Reporting `0x0508` (AlarmReport) and `0x0509` (AlarmAck)

Panel → supervisor alarm notification + supervisor → panel acknowledgment.

**`0x0508` AlarmReport wire format** (panel → supervisor):

```
[routing header: BLN / dest=supervisor / BLN / src=panel]
05 08                          opcode
01 00 LL <device_name>         device TLV
01 00 LL <point_name>          point TLV
<BACnet date+time 8 bytes>     timestamp
<alarm state byte>             alarm state (entered/cleared/etc.)
<alarm priority byte>          priority level (1-6, enhanced alarming)
[optional 4-char alarm class label]   e.g. "URGT", "MAIN", "TROB"
<trailing block>               additional details (varies)
```

**`0x0509` AlarmAck wire format** (supervisor → panel):

```
[routing header]
05 09                          opcode
01 00 LL <device_name>         device TLV
01 00 LL <point_name>          point TLV
<acknowledgment marker bytes>
<operator identity TLV>        the user acknowledging
<BACnet date+time 8 bytes>     ack timestamp
```

**BACnet date+time format (8 bytes)**:

```
Byte 0: year offset from 1900 (e.g., 0x7C = 124 = 2024)
Byte 1: month (1-12)
Byte 2: day of month (1-31)
Byte 3: day of week (1=Monday, 7=Sunday)
Byte 4: hour (0-23)
Byte 5: minute (0-59)
Byte 6: second (0-59)
Byte 7: hundredths of a second (0-99)
```

**Two BACnet-style date encodings exist in the protocol.** The 8-byte form above is used for alarm timestamps (`0x0508`, `0x0509`). A separate **4-byte BACnet date** encoding is used inside weekly schedule entries (`0x098D`):

```
Byte 0: year offset from 1900
Byte 1: month (1-12; 0xFF = any/unspecified)
Byte 2: day of month (1-31; 0xFF = any)
Byte 3: day of week (1=Monday, 7=Sunday; 0xFF = any)
```

The 4-byte form omits time-of-day because schedule entries carry the time-of-day in a separate field (typically a 4-byte minutes-since-midnight value). Implementers MUST select the encoding based on the carrying opcode, not assume one date format is universal.

**Cross-port duplication**: alarm reports are typically emitted on **both** TCP/5033 and TCP/5034. Parsers should de-duplicate by sequence number, or by `(device, point, timestamp)` tuple if a parser handles both ports.

### 12.22 The `0x0273` AlarmAckTrigger Pre-Cursor

`0x0273` (WriteNoValue) is sent immediately before `0x0509` AlarmAck for the same point in operator-initiated alarm acknowledgments. Its role is unclear from the wire — possibly an operator-action trigger or a state-clear precondition. Implementers of an alarm-acknowledgment feature SHOULD include the `0x0273` precursor for compatibility with strict panels.

### 12.23 The PXC → Supervisor Push Channel (TCP/5034) Traffic Mix

Every panel maintains an outbound TCP connection to the supervisor's port 5034. This channel is **panel → supervisor only**; the supervisor's only response is a 39-byte routing-header-only ACK for each pushed frame.

Observed traffic mix in a typical 10-minute window across 6 panels:

| Opcode | Purpose | Frequency | Typical size |
|---|---|---|---|
| `0x0240` | WriteWithQuality (BLN virtual-point value report) | ~55% | ~84 B |
| `0x0274` | COV notification (device-point value change) | ~45% | ~82 B |
| `0x4634` | BLN routing-table announcement | ~2% | ~256 B |

There is **no explicit subscribe/unsubscribe handshake** for COV notifications. As long as the panel's outbound TCP connection to supervisor:5034 is alive, the panel pushes COV/value changes. Subscription is implicit from the connection being open.

---

## 13. Discovery and Replication (EPing)

### 13.1 Two Discovery Mechanisms

Two distinct discovery mechanisms operate at different protocol layers:

1. **UDP/10001 multicast presence beacon** (§3.2.2) — a 4-byte `01 00 00 00` payload broadcast by network gateways every ~10.5 seconds to multicast group `233.89.188.1` and to directed broadcast `255.255.255.255`. This is the **layer-2/3 discovery** mechanism — a passive listener can detect a P2 site's existence without sending anything.

2. **EPing TCP-layer heartbeat** (§13.2 below) — the `0x4640` opcode exchanged over the established TCP session as a periodic identity refresh and liveness check between known peers. This is the **application-layer heartbeat** between panels and the supervisor.

These two mechanisms serve different purposes. The UDP/10001 beacon announces existence; the TCP EPing maintains an active session.

**Note on documented multicast defaults**: vendor configuration tools reference `234.5.6.7` as the multicast group address and UDP `8` as the multicast port. The values used by deployed panels are `233.89.188.1` on UDP `10001`; the "UDP port 8" value appears to be a transcription artifact in vendor literature. Implementers SHOULD accept both addresses (`234.5.6.7` and `233.89.188.1`) and both ports (`8` and `10001`) as configurable per site, and SHOULD default to `233.89.188.1` on UDP `10001`.

### 13.2 EPing Protocol (TCP Heartbeat)

The **EPing** (Ethernet ping) is the periodic application-layer heartbeat that establishes liveness between panels and the supervisor over the established TCP session. It carries wire opcode `0x4640` with CPI sub-opcode `0x1600`.

#### 13.2.1 Timing

Two cadences apply:

| Setting | Default | Range | Purpose |
|---|---|---|---|
| **Intra-site EPing Period** | 10 s | — | Heartbeat interval between panels in the same site |
| **Intra-site EPing Timeout** | 5 s | — | If no EPing reply for this long, peer is considered failed |
| **Inter-site EPing Period** | 60 s | 1-900 s | Heartbeat between panels in different sites |
| **Inter-site EPing Timeout** | 5 s | — | Inter-site failure timeout |

A panel marks a peer as failed after `EPing Timeout` elapses without a reply.

#### 13.2.2 Tombstone Lifetime

When a peer is marked failed, the panel keeps a "tombstone" record of the peer's identity for **86400 seconds (24 hours)** by default. During this period, the panel knows the peer existed and can fast-detect it returning. After the tombstone expires, the peer is forgotten.

### 13.3 Replication Protocol

Replication operations propagate global-data changes across the BLN. Two cadences:

| Setting | Default | Range |
|---|---|---|
| Intra-site Notification Period | 10 s | — |
| Intra-site Polling Period | 60 s | — |
| Intra-site Cycle Timeout | 15 s | — |
| Inter-site Notification Period | 10 s | 1-900 s |
| Inter-site Polling Period | 180 s | 1-900 s |
| Inter-site Cycle Timeout | 15 s | 1-900 s |
| Holdback Delay | 10 s | — |

Replication uses opcodes:

- `0x4633` (CPI `0x1601`) — replication notification init
- `0x4635` (CPI `0x1603`) — replication notification event
- `0x4636` (CPI `0x1604`) — replication changes push

### 13.4 Topology Limits

| Limit | Value |
|---|---|
| Panels per Ethernet BLN | 100 |
| Ethernet BLNs per supervisor | 64 (combined Ethernet + bridge BLNs) |
| Total Ethernet field panels per supervisor | 1,000 |
| Per-supervisor remote (dial-up) BLNs | 300 |
| Per-supervisor modems | 8 |

---

## 14. Response Parsing — Point Reads

This section specifies how to parse the response body of a point-read operation (`0x0220` or `0x0271`). Implementers MUST check the direction byte first (§10.4) and only enter the parsing logic below for direction = `0x01` (success).

### 14.1 Value Block Structure

Successful point-read responses carry a trailing **value block** with this structural signature:

```
[last byte of point name] [01 00 00] [7-byte metadata] [IEEE-754 float (4 bytes)]
                                                       ^ float offset = marker + 10
```

The IEEE 754 single-precision float **always sits at offset +10** from the `01 00 00` marker.

### 14.2 Response Variants

Four response variants are observed. Labels R1-R4 are used here to distinguish them from the SHAPE A/B labels used for `0x0981` enumerate responses (§12.13).

| Variant | Opcode | 7 metadata bytes | Condition |
|---|---|---|---|
| **R1** | `0x0271` | `3F FF FF X? 00 00 00` | Quality-flags partial (see §14.3) |
| **R2** | `0x0271` | `00 00 00 00 00 00 00` | Quality-flags explicit, all clear |
| **R3** | `0x0220` | `00 00 00 00 00 00 XX` | XX = data-type code (see §14.4) |
| **R4** | any | (R2/R3 pattern but float starts `0xBF`) | Negative values |

### 14.3 The `3F FF FF` Prefix Trap

When matching R1 responses, lock only the **3-byte prefix `3F FF FF`** — not the full 4-byte `3F FF FF FF`. The fourth byte varies on the wire:

- `3F FF FF FF` — about 25% of responses
- `3F FF FF F7` — about 75% of responses
- `3F FF FF F0` — occasional

The low-nibble variation is not stable across reads of the *same point* in the same session, so it isn't quality-flag information the user can interpret reliably; treat it as opaque.

A predicate that requires the literal `3F FF FF FF` will reject the F7 majority and produce false-offline classifications for most online devices. Use a 3-byte prefix match.

### 14.4 Data-Type Codes (the `XX` byte in R3 / SHAPE B metadata)

The 7th metadata byte in R3 / SHAPE B responses encodes the point's data type:

| Code | Inferred role | Value distribution |
|---|---|---|
| `0x00` | Digital / binary / enum | Mostly 0.0 / 1.0; small integers also seen |
| `0x01` | Rare — semantics not defined by this specification | — |
| `0x02` | Small integer (likely `int16`) | Integer values in setpoint contexts |
| `0x03` | Analog (the dominant type) | Floats 0.01 to ~2500, integer-valued majority |
| `0x06` | "Analog32" / extended numeric | Mixed |

Codes `0x04` and `0x05` are reserved by the dispatcher but are not used in normal operation. Treat them as reserved values until firmware surfaces them.

### 14.5 Scan-Loop Bounds for the Value Block

A scanner implementing marker-based scan must bound the loop so the float at offset +10 is fully addressable. The correct bound is `i + 13 < len(payload)` (the marker occupies 3 bytes, plus 7 metadata bytes, plus 4 float bytes = 14 bytes from `i` through `i+13`).

**Off-by-one trap**: `range(1, len(payload) - 14)` is one too small and silently misses cases where the float sits at the very end of the payload with no trailing data. Use `range(1, len(payload) - 13)`.

### 14.6 The False-Positive Trap

A naive parser that scans for `01 00 00` byte patterns will false-positive on the response's **trailing configuration block** — the panel appends min/max/resolution metadata with a near-identical structure.

The reliable disambiguator is the byte *immediately before* the real value block's `01 00 00` marker: it must be a printable ASCII character — the last byte of the TLV-encoded point name.

The trailing config block's preceding byte is part of the float value itself (non-ASCII bytes).

Accepted preceding bytes for the real value block: A-Z, a-z, 0-9, space, period, underscore, hyphen.

### 14.7 Value Decoding

For analog points (data-type codes `0x03`, `0x06`): the 4 value bytes decode as IEEE 754 single-precision big-endian (`f32 BE`).

For digital / multi-state (data-type code `0x00`): the first byte of the value field is the state index (0, 1, 2, ...). Map to user-facing labels via the `0x040A` Multi-State Label Catalog (§12.18) or via the default enumerations (§17.4).

For small integers (data-type code `0x02`): the 4 value bytes decode as `int16` in the low half plus padding, OR `int32` BE depending on context. Implementers should compare against the point's known type from the application catalog.

### 14.8 Engineering-Unit Scaling

The raw decoded value is in raw units. To convert to display value, apply per-point linear scaling:

```
display_value = raw_value * slope + intercept
```

The `slope` and `intercept` are properties of the point definition stored in the supervisor's per-application point database (e.g. for VAV Cooling Only app 2020, slot 4 ROOM TEMP has slope=0.25 and intercept=48.0). These are not transmitted on the wire — clients must hold a per-application slot table to render values correctly.

---

## 15. Comm Status — Stale-Cache Behavior

This section covers how the panel reports stale-cached data for downstream devices that have gone offline. The behavior is operationally significant: a scanner that ignores the comm-status byte will report cached values for devices that have been dead for weeks.

### 15.1 The Stale-Cache Mechanism

**Panels cache the most recent value read from each TEC device.** When a TEC goes offline (unplugged, comm-faulted, power lost), the panel **continues returning the last cached value** to read requests — indefinitely — instead of erroring.

Without accounting for this, a scanner will confidently report `72°F` for a VAV controller that's been dead for two weeks.

### 15.2 The Live-vs-Stale Indicator

The **second byte of the metadata block** after the `01 00 00` marker is the comm-status flag:

| Value | Meaning |
|---|---|
| `0x00` | Device is online; value is live |
| `0x01` | Device is comm-faulted; value is stale cached data |

The **third byte** is an error code; `0x06` is the typical comm-error code. Other codes surface for different failure modes.

Supervisor UIs (Desigo CC, Insight) display comm-faulted points with a `#COM` flag. Scanners SHOULD do the same.

This `0x01` in the *value block metadata* is a TEC-level comm-fault flag for the underlying device. It is **distinct from** the `0x05` *response-level* status byte (§10), which indicates a panel-level operation failure (point doesn't exist, opcode unsupported). Both can appear in the same parser workflow — one indicates device health, the other indicates operation outcome.

### 15.3 Panel-Cached Metadata vs Live FLN Data

Not all properties on a device behave the same way under FLN comm-fault:

- **Live FLN-sourced points** (ROOM TEMP, RM STPT DIAL, AUX TEMP, anything read from the device's I/O at request time) carry the comm-status flag described above. When the TEC is faulted, these come back with `comm_status=0x01` and a stale cached value.
- **Panel-cached configuration metadata** (APPLICATION number, descriptor strings, slot-table info — anything the panel knows because it commissioned the device, not because the device just told it) **keeps reading successfully even when the TEC is fully faulted**. APPLICATION reads on a #COM device return the configured app number with varying `comm_status` (`0x00` or `0x01` depending on firmware) — it's unreliable as a liveness signal.

The trap here is that a scanner using APPLICATION-read-success as a proxy for "device exists / is registered" — and treating that as "device online" — will silently mark every #COM-faulted device online.

Recommended verification policy:

1. Read ROOM TEMP (or any other genuinely live-sourced point on the device).
2. If `comm_status=0x00` → online.
3. If `comm_status=0x01` → offline (#COM). Optionally read APPLICATION to surface the configured app number for display, but flag it as cached.
4. If ROOM TEMP doesn't exist on this device (some non-VAV apps), fall back to APPLICATION as a registration probe — but treat the result as "registered" not "online", and check `comm_status` on it too.

### 15.4 The `-62.5°F` Sensor Signature

A second, separate signal of sensor trouble is a repeated **`-62.5°F`** (or adjacent values like `-63.5°F`) across multiple unrelated points on the same device.

This isn't a protocol signal — the panel returns these values with `comm_status=0x00` (healthy), so the comm-fault byte won't catch it. The pattern is that the underlying sensor or wiring is broken, but the panel's input side is still reading valid analog-to-digital conversions of an open-circuit rail or shorted input.

Scanners SHOULD flag when multiple points on one device report the same implausible temperature — it indicates a hardware issue downstream of the panel.

---

## 16. Point Addressing

A point address identifies a specific data location within the system. Multiple formats exist depending on the firmware generation of the field panel.

### 16.1 Modern Format (P2 Firmware Revision 2.5 and Later)

This is the canonical address format on all firmware in current deployment (V2.8.x P2 panels and V3.x BACnet panels).

```
FLN.Drop.PointNumber
```

| Field | Range | Meaning |
|---|---|---|
| FLN Number | 0-253 | `0` = point resides in the field panel itself; `1+` = the FLN that hosts the point's device |
| Drop Number | 0-254 | FLN device's drop address (or PTM key for direct-I/O points) |
| Point Number | 0-65534 | 16-bit point identifier within the drop |

A panel-resident point has FLN=0; a TEC point has FLN=1..N and a Drop=0..31.

### 16.2 Legacy Format — FLN Devices (Pre-Ethernet Firmware, Insight Versions ≤ 12.41)

Used by pre-2003 panels and the original serial-only Apogee architecture. Modern P2-over-Ethernet panels do not emit this format; it is documented here for archival compatibility.

```
Trunk.PanelNumber.FLN.Drop.PointNumber
```

| Field | Range |
|---|---|
| Trunk Number | always 0 at the supervisor |
| Panel Number | 0-99 |
| FLN Number | 1, 2, or 3 (only 3 FLNs supported) |
| FLN Device Drop | 0-31 |
| Point Number | 0-99 |

Theoretical maximum: 3 × 32 × 100 = 9,600 FLN-device points per panel.

### 16.3 Legacy Format — Direct Panel I/O (Insight Versions ≤ 1.41)

Used only by the earliest Apogee panel generation. Not encountered on any P2-Ethernet-capable hardware.

```
Trunk.PanelNumber.FLN.Constant.PointNumber
```

| Field | Range |
|---|---|
| Trunk Number | always 0 |
| Panel Number | 0-99 |
| FLN Number | 0 only |
| Constant | always 0 |
| Point Number | 4-296 (offset from PTM address key) |

### 16.4 Name-Based Addressing

Points may also be referenced by logical name in operator-level commands and over the wire when an operation includes a name field:

```
<BLN>.<FloorOrZone>.<RoomOrUnit>.<DeviceType>:<SubpointName>
```

The `:` is the system delimiter. Wildcards `*` and `?` are supported (e.g., `<dev>:DO*` matches all subpoints starting with `DO`).

### 16.5 FLN Device Default-Output Subpoint

When a frame references an FLN device without a specific subpoint, the device's **default-output subpoint** is implied:

| Device class | Default subpoint |
|---|---|
| TEC | `DAY.NGT` (DAY/NIGHT mode) |
| DXR | `RM OP MODE` |
| (other classes) | per-class as defined |

---

## 17. Point Classes

This section defines the **thirteen logical point classes** that the protocol supports (twelve standard data-bearing classes plus the special `LCTLR` rollup class). Each class has well-defined wire-level command semantics.

### 17.1 Analog Classes

| Code | Name | Description | COV |
|---|---|---|---|
| **LAI** | Logical Analog Input | Sensor reading (temperature, pressure, etc.) | Yes |
| **LAO** | Logical Analog Output | Modulating output (damper position, etc.) | Yes |
| **LPACI** | Logical Pulse Accumulator Input | Counting input (energy, flow meter) | Yes |

Analog values are transmitted as IEEE 754 single-precision floats (`f32`) in big-endian byte order. Engineering-unit scaling is applied at the supervisor display layer using per-point slope and intercept (`value_displayed = raw * slope + intercept`).

### 17.2 Binary Classes

Binary points come in several semantic variants distinguished by storage type and override-release behavior:

| Code | Name | Persistence on release | Use case |
|---|---|---|---|
| **LDI** | Logical Digital Input | n/a (read-only) | Sensor contact closure |
| **LDO** | Logical Digital Output | reverts to default | Simple ON/OFF output |
| **L2SL** | Logical 2-State Latched | retains commanded state indefinitely | Output with latched memory (e.g. lighting circuits) |
| **L2SP** | Logical 2-State Pulsed | reverts to default after pulse duration | Pulsed-only output (e.g. momentary actuators) |
| **LFSSL** | Logical Fail-Safe Latched | retains state; reverts to safe default on comm failure | Latched output with fail-safe behavior |
| **LFSSP** | Logical Fail-Safe Pulsed | pulsed; reverts to safe default on comm failure | Pulsed output with fail-safe behavior |

The **Latched / Pulsed distinction** governs how state survives release:

- **Latched** classes (L2SL, LFSSL): the commanded state persists indefinitely until explicitly changed.
- **Pulsed** classes (L2SP, LFSSP): the commanded state is a momentary pulse; the point reverts to its default when released.

The **Fail-Safe variants** (LFSSL, LFSSP) add a configurable safe default that the panel applies when communication with the supervisor is lost.

### 17.3 Multi-State Classes

| Code | Name | States |
|---|---|---|
| **LENUM** | Logical Enumeration | Arbitrary multi-state (>2 states) |
| **LOOAL** | Logical On-Off-Auto Latched | 3-state {ON, OFF, AUTO}, latched |
| **LOOAP** | Logical On-Off-Auto Pulsed | 3-state {ON, OFF, AUTO}, pulsed |

LOOAL and LOOAP are **digital-only** classes and MUST NOT be substituted for analog points (their command semantics are not interchangeable). LENUM may carry any user-defined enumeration up to 65535 states.

### 17.4 Default Enumerations

The default enumeration table for binary and multi-state classes:

| Class | Default levels |
|---|---|
| LDI, LDO, L2SL, L2SP, LFSSL, LFSSP | {OFF=0, ON=1} |
| LOOAL, LOOAP | {OFF=0, ON=1, AUTO=2} |
| LENUM | user-defined |

### 17.5 Special Class

| Code | Name | Purpose |
|---|---|---|
| **LCTLR** | Logical Controller | Bundled rolled-up status indicator for an FLN device as a whole. Always exists at subpoint 0 of every FLN device. Surfaces a single online/offline/alarm state without enumerating subpoints. |

### 17.6 COV (Change-of-Value) Semantics

For classes that support COV (LAI, LAO, LPACI), the field panel compares the current value against the last reported value. When the absolute difference equals or exceeds the **COV limit** (set per-point in engineering units), the panel emits a `ValuePush` (opcode `0x0274`) to all subscribed supervisors.

- COV limit is per-point and configurable.
- The supervisor subscribes via `RegisterCOV` (opcode family `0x0220`-`0x0223`).
- The supervisor unsubscribes via `CancelCOV` (opcode family `0x0244`-`0x024D`).
- COV resubscription period (default 60 minutes) means the supervisor must re-subscribe periodically to maintain its subscription.
- COV poll rate (default 60 seconds) is a fallback poll the supervisor performs as a safety net.

---

## 18. Subpoint Semantics

FLN device subpoints have two override-persistence variants. The distinction governs how an override behaves when the point is released.

### 18.1 Unbundlable Subpoints

- **Storage**: EEPROM + RAM
- **Behavior on release**: stays at the commanded value indefinitely; only changes when the device's internal program commands it
- **Use case**: setpoints, sensor readings, calculation results

A point report shows the subpoint number in **braces** for unbundlable subpoints: `{NN}`.

### 18.2 Non-Unbundlable Subpoints

- **Storage**: EEPROM only
- **Behavior on release**: immediately reverts to the factory default
- **Use case**: configuration parameters intended to be set once

A point report shows the subpoint number **without braces** for non-unbundlable subpoints: `NN`.

### 18.3 EEPROM Wear Constraint

Non-unbundlable subpoints have a **manufacturer-rated lifetime of ~100,000 commanded writes** before EEPROM wear degrades the controller. Implementers MUST NOT issue write commands to non-unbundlable subpoints in tight loops; rate-limit to at most a few writes per day per subpoint to stay within the device's design envelope.

Unbundlable subpoints have effectively unlimited write cycles because they are RAM-backed; the EEPROM is updated only periodically as a checkpoint.

### 18.4 Command Pathways

| Subpoint type | HMI path | PPCL path |
|---|---|---|
| Unbundlable | `PCV` (Point / Command / Value) or `ANTICS` (Application / fLN / Tec / Initial values / Command / Set) | `SET`, assignment statement, or `OIP` with `ANTICS` |
| Non-unbundlable | `ANTICS` only | `OIP` with `ANTICS` only |

---

## 19. PPCL (Process Control Language)

PPCL is the proprietary control-strategy programming language hosted on field panels. It is line-oriented and interpreted at panel runtime. This section documents the language for protocol-level implementers; full language reference is out of scope.

### 19.1 Program Structure

A PPCL program is a sequence of numbered lines. Each line is either:

- An executable statement
- A comment line (prefixed `C`)
- A disabled line (prefixed `D`)

Lines have a maximum length (typically 80 characters). Programs may span hundreds of lines.

### 19.2 Statement Categories

#### 19.2.1 Control-Flow Statements

`GOTO`, `RETURN`, `DEACT`, `DISABL`, `ENABL`, `IF`/`THEN`/`ELSE`

Vendor note: in PPCL, `ACT` and `ENABL` are interchangeable for the same operation. On the newer PXC.A platform (BACnet-only successor) the `ACT`/`DEACT`/`ENABL`/`DISABL` set is deprecated in favor of `GOTO`/`RETURN` flow control.

#### 19.2.2 Assignment and Math

`SET`, `SETVAL` (write BACnet property), arithmetic operators (`+`, `-`, `*`, `/`, `.ROOT.`), functions (`ATN`, `COM`, `COS`, `EXP`, `LOG`, `SQRT`, `SIN`, `TAN`)

#### 19.2.3 Point Operations

`RELEAS` (release to NONE priority), `DISCOV` (disable COV transmission), `DISALM` (disable alarming), `STATE` (state text command)

#### 19.2.4 Time and Schedule

`DAY` (Day-mode test), `DBSWIT` (dead-band switch), `DC` (duty cycle), `DCR` (duty cycle routine), `SAMPLE`, `SSTO` (start/stop time optimization), `SSTOCO`, `TABLE`

#### 19.2.5 Specialized Functions

`ADAPTM` (adaptive multi-output closed-loop control), `ADAPTS` (single-output), `PDLSET` (peak demand limiting setpoints), `EMAUTO` (emergency auto status), `OIP` (operator-input program), `ONPWRT` (on-power-return handler)

Vendor note: `ADAPTM`, `DPHONE`, `OIP`, `ALARM`, and `NORMAL` are not supported on PXC.A panels.

### 19.3 Resident Points and Variables

The panel firmware exposes the following pseudo-points to PPCL programs:

| Identifier | Type | Meaning |
|---|---|---|
| **NODE0**-**NODE99** | Boolean | Per-node liveness: `1` = node communicating, `0` = node offline. Up to 100 nodes per BLN. |
| **LINK** | Boolean | This panel's BLN-communication-link status (`0` = disconnected, `1` = connected). |
| **$BATT** | Numeric | Backup-battery status reading. Some panels only. |
| **ALMCNT** | Integer | Standard alarm counter — total points currently in alarm on this panel. |
| **ALMCT2** | Integer | Second alarm counter — programmable; used for app-specific subsets. |
| **ALMPRI** | Integer 1-6 | Alarm priority level of a point (enhanced alarming). |

### 19.4 Object Status Indicators

PPCL exposes the following status indicators for points and devices:

| Indicator | Meaning |
|---|---|
| `ALARM` | Point is currently in alarm |
| `ALMACK` | Alarm has been acknowledged |
| `AUTO` | Point is in auto mode |
| `HAND` | Point is in manual override (HAND) |
| `OK` | Battery charged (normal) |
| `LOW` | Battery low (warning) |
| `DEAD` | Battery discharged |
| `DAYMOD` | Day-mode active |
| `FAILED` | Point or device failed |
| `FAST` | Fast scan rate active |
| `SLOW` | Slow scan rate active |

### 19.5 The OIP Statement

The `OIP` (Operator Input Program) statement is significant for the wire protocol: it allows a PPCL program to inject an operator-equivalent HMI command sequence keyed on a trigger point. The command sequence executes once per off-to-on trigger transition.

OIP is the PPCL-side equivalent of the `OipExec` wire operation; a panel can effectively command itself via PPCL using the same command pathway as a human operator at the terminal.

### 19.6 Command Priority Hierarchy

Each point has a current **command priority**. The priority hierarchy (lower number = higher priority):

1. EMER (Emergency) — highest
2. OPER (Operator)
3. PPCL
4. CTLR (Controller / initial value)
5. NONE — lowest (released)

When a point at priority N is released, it falls to the next-lower priority that has a pending command, or to NONE if none exists.

### 19.7 BACnet Priority Array Mapping

When commanding **P1 FLN devices** from a BACnet supervisor, the supervisor MUST write at BACnet Priority Array slot **16** (BN16, the lowest BACnet priority). The P1 FLN device's internal priority hierarchy then governs override semantics.

---

## 20. BACnet Integration

Modern field panels support BACnet as a parallel protocol. This section specifies how P2 and BACnet coexist.

### 20.1 Feature Precedence

When both BACnet and P2 provide an equivalent function, **the BACnet function is implemented**. When a function exists in P2 but has no BACnet equivalent, the P2 function is retained. The result is a BACnet-superset: BACnet features work natively, and P2-only features (PPCL pseudo-points, replication, advanced TEC override semantics) continue using the proprietary wire format.

### 20.2 Confirmed Private Transfer (CPT)

P2 messages may be encapsulated inside BACnet/IP packets using the BACnet `ConfirmedPrivateTransfer` service (service choice 18), with vendor ID 7. This allows P2 RPCs to traverse a pure BACnet/IP network without requiring direct TCP connectivity to TCP/5033/5034.

A BACnet sniffer parsing CPT requests with vendor ID 7 will see AP2Cmd payloads inside.

### 20.3 BACnet Supported Object Types

Field panels and BACnet-bridged supervisors support the following BACnet object types:

- Analog Input (AI), Analog Output (AO), Analog Value (AV)
- Binary Input (BI), Binary Output (BO), Binary Value (BV)
- Multistate Input (MI), Multistate Output (MO), Multistate Value (MV)
- Calendar, Command, Device, Event Enrollment (EE)
- Notification Class (NC)
- Schedule
- Trend Log

Not supported (out of scope for typical Apogee deployments):

- Accumulator, Averaging, File, Group, Life Safety Zone, Life Safety Point, Loop, Program, Pulse Converter

### 20.4 BACnet Object Mapping for Logical Point Classes

Each logical point class (§17) maps to a BACnet object type when exposed via the BACnet bridge:

| Logical class | BACnet object |
|---|---|
| LAI | Analog Input |
| LAO | Analog Output |
| LPACI | Analog Input (or Accumulator if supported) |
| LDI | Binary Input |
| LDO | Binary Output |
| L2SL, L2SP, LFSSL, LFSSP | Binary Value (or proprietary class wrapped in MSV) |
| LENUM | Multistate Value |
| LOOAL, LOOAP | Multistate Value (with custom enumeration {ON, OFF, AUTO}) |

### 20.5 BBMD (BACnet Broadcast Management Device)

When BACnet/IP networks span multiple subnets, BBMD entries are used to relay broadcasts. BBMD configuration:

- One BBMD per IP subnet (no more, no fewer)
- BBMD table entries MUST use subnet mask `255.255.255.255` (`/32`)
- Two-Hop Forwarding SHOULD be enabled (preferred over One-Hop)
- All BBMDs on the same BACnet/IP network MUST have identical Broadcast Distribution Tables
- Each BBMD device requires a fixed IP address

### 20.6 Cross-Trunk Service Limitation

The supervisor's Cross-Trunk Service is **push-only from P2 to BACnet**. A BACnet client cannot pull P2-resident point values through the bridge; the supervisor's BACnet Server option must be enabled to expose P2 points as readable BACnet objects.

Two workarounds:

1. Enable the supervisor's BACnet Server option (proxies P2 points as BACnet objects).
2. Use PPCL on the P2 panel to push values to BACnet objects via the Cross-Trunk Service.

### 20.7 MS/TP FLN Device Polling

A field panel polls its MS/TP FLN devices using BACnet services:

- **Who-Is** (initial discovery)
- **ReadPropertyMultiple** (capability detection: vendor ID, services supported, device type)
- **ReadProperty** (periodic state polling)

Two poll rates apply:

| Setting | Default | Range |
|---|---|---|
| Keep Alive Poll Rate (device live) | 60 s | 10-300 s |
| Discovery Poll Rate (device failed) | 60 s | 10-300 s |

If a device fails to respond, it is marked failed and subsequent polls use the Discovery Poll Rate until response resumes.

### 20.8 P1 FLN Device Commanding via BACnet

A P1 FLN device commanded from a BACnet supervisor receives the command at **BACnet Priority Array slot 16** (BN16). The P1 FLN device's internal priority hierarchy then resolves the command.

This is the **only** BACnet priority slot a P1 FLN device receives commands at, regardless of the BACnet supervisor's writeProperty priority parameter.

---

## 21. Security Considerations

This section enumerates security-relevant properties of the protocol. Implementers MUST NOT rely on the protocol itself for confidentiality, integrity, or authentication.

### 21.1 No Transport Security

P2 frames transmitted over TCP/5033, TCP/5034, or TCP/3001/3002 are:

- **Unencrypted**: all frame contents are plaintext on the wire
- **Unauthenticated**: any party that can complete a TCP handshake can send frames
- **Unverified**: there is no message-integrity check (no MAC, no signature, no HMAC)

Frame contents that are exposed in plaintext:

- BLN names, node names, supervisor hostnames, supervisor port numbers
- All point names referenced in operations
- All point values (analog as `f32` BE, digital as enumerated bytes)
- Sequence numbers and session-layer message types
- The entire AP2 RPC opcode and arguments

A passive observer on the network can therefore enumerate the building automation system, identify every device by name, and read every value exchange. An on-path attacker can also inject, modify, or replay frames subject to TCP-layer constraints.

**Cleartext is a structural property of the platform, not a configurable option.** Field-panel firmware does not ship any TLS, SSL, SSH, or SNMPv3 library — the open-source bill of materials for both P2-era (V2.8.10) and BACnet-era (V3.2.5) firmware contains no transport-security stack. The P2 TCP listener is hand-rolled C running directly on Nucleus NET sockets. There is no firmware configuration that enables transport encryption on existing P2-mode panels; the only path to encrypted building-automation traffic on the same hardware is to migrate the panel to BACnet/SC firmware (see PXC.A platform; §1).

Network-level mitigations (VLAN isolation, IPsec tunnels, jump hosts) are the only available controls. Treat any P2 network as if every byte is being read by anyone with access to the segment.

### 21.2 TCP Initial Sequence Number Predictability

Field panels running affected firmware versions have **predictable TCP Initial Sequence Numbers** (CVE-2020-28388, CVSS 6.5). An on-path attacker can use this to hijack existing TCP sessions or spoof new ones.

**Mitigation**: ensure all field panels are running firmware at or above the fixed versions:

- **P2 Ethernet firmware**: V2.8.20 or later
- **BACnet firmware**: V3.5.5 or later

### 21.3 Field Panel Web Server

Field panels with the integrated web server enabled are subject to **CVE-2022-45937** (CVSS 8.8), a privilege management vulnerability that allows a low-privilege authenticated attacker to download user account credentials.

**Mitigation**:

- Update to firmware V2.8.20 (P2) or V3.5.5 (BACnet) or later
- Disable the integrated web server on field panels that do not require it
- Restrict network access to the web server port (typically TCP/80 on the panel)

### 21.4 Nucleus RTOS DNS Stack Vulnerabilities

Field-panel firmware runs Mentor Graphics **Nucleus PLUS** real-time operating system on Freescale/Motorola PowerPC MPC852 / MPC860 hardware, with the **Nucleus NET 5.1** TCP/IP stack handling all transport-layer traffic (TCP/5033, TCP/5034, the FTP and Telnet ancillary listeners, the optional integrated web server, and DNS lookups). This shared stack is the source of the predictable-ISN issue (§21.2) and of the DNS-stack CVE cluster below.

Affected version range field panels have multiple DNS stack vulnerabilities (CVE-2020-15795, CVE-2020-27009, CVE-2020-27736, CVE-2020-27737, CVE-2020-27738, CVE-2021-25677). These can be exploited by an attacker who controls or spoofs DNS responses, leading to remote code execution or denial of service.

**Mitigation**:

- Update firmware as above
- Disable DNS lookups on field panels where DNS is not required (use static IPs and a local hosts table)
- Restrict DNS server access to trusted internal servers

### 21.5 Default Credentials on Serial-to-Ethernet Bridges

Lantronix-based serial-to-Ethernet bridges (used for AEM-bridged BLNs) ship with default credentials and several network services enabled:

- Default Telnet password: `system`
- Default SNMP community: `public`
- HTTP web manager enabled by default
- TFTP firmware download enabled by default
- Lantronix Device Installer service on port 30718 enabled by default

**Mitigation**:

- Change default Telnet password on every bridge
- Change SNMP community string or disable SNMP entirely
- Disable HTTP web manager unless actively used
- Disable TFTP unless actively performing firmware updates
- Disable the Lantronix Device Installer service on production deployments

### 21.6 Telnet Access to Field Panels

Field panels expose a Telnet HMI on TCP/23. This service is **disabled by default** but can be enabled per panel.

**Recommendation**: leave Telnet disabled. If remote HMI access is required, use a jump host or VPN to reach the panel rather than exposing Telnet directly to the network.

### 21.7 BBMD Forwarding Risks

Misconfigured BBMD entries can amplify broadcast traffic across networks. Implementers SHOULD:

- Verify BBMD tables are identical across all BBMDs in the same BACnet/IP network
- Verify only one BBMD exists per IP subnet
- Use Two-Hop Forwarding consistently
- Monitor BACnet broadcast traffic for unexpected amplification

### 21.8 Defensive Implementation Guidance

For tools that touch the protocol actively (scanners, fuzzers, dissectors):

1. **Read-only by default**: implement scanners that only observe traffic or issue read-only operations.
2. **Rate-limit**: insert delays between operations (≥1 second per probe is conservative).
3. **Back off on errors**: if consecutive errors are observed, increase the inter-probe delay or abort.
4. **Maintain a blocklist**: refuse to send opcodes whose effects are not fully understood — particularly flash writes, firmware-update commands, factory-reset, and cold-start commands.
5. **EEPROM wear awareness**: for any tool that issues writes, enforce per-subpoint write quotas to stay well below the 100,000-write design envelope.
6. **Site-safe testing**: never test against production systems without a maintenance window and a documented kill-switch.

---

## 22. Cold-Site Discovery

This section documents how a client without prior knowledge of a site's configuration can discover the BLN name(s) and panel identities needed to establish a session.

### 22.1 The Cartesian Attack

The bouncer's distinct failure signatures (§9.10) make BLN-name discovery tractable:

- **Wrong BLN name** → TCP RST (instant, visible at TCP layer)
- **Wrong slot 2 (panel name)** → silent drop (TCP stays up, no response)

A scanner can iterate candidate BLN names against a known panel IP and observe the TCP-layer response:

```
1. TCP connect to <target_ip>:5033
2. Send a handshake with candidate BLN name and arbitrary slot 2
3. If TCP RST → wrong BLN; mark this candidate eliminated, retry with next
4. If TCP stays up (silent drop) → BLN name is correct, slot 2 is wrong
5. Once BLN is found, enumerate slot 2 candidates against the same BLN
```

**Candidate sources** for BLN names:

- Site documentation (commissioning records, BAS architecture diagrams)
- Sniffed traffic on the network (BLN name appears in every frame)
- Captured traffic from the site
- The `0x0050` StatusQuery opcode (leaks supervisor name; §23.4)
- Routing-table broadcasts from neighbor panels (§12.10)

### 22.2 Discovery Flow

```
[multicast listen 30s] ──┐
                         ├──→ [list of gateway IPs]
[port scan TCP/5033]   ──┘
                              │
                              ▼
                  [for each candidate IP:]
                  ├─ [check known BLN names]
                  ├─ [if unknown, cartesian BLN probe]
                  └─ [for each found BLN:]
                       ├─ [send 0x0050 StatusQuery for identity leak]
                       ├─ [attempt handshake]
                       └─ [if successful, send 0x4634 broadcast or 0x010C SystemInfo]
                              │
                              ▼
                  [routing table observation]
                       ├─ Full BLN topology
                       └─ Names of every panel
```

### 22.3 Case-Sensitivity Note

BLN name matching is **case-sensitive** — `SITEBLN` and `siteblN` are distinct from the panel's perspective. A cartesian search SHOULD try each candidate in multiple casings. Common variants are all-uppercase (`SITEBLN`), all-lowercase (`siteblN`), and PascalCase (`SiteBln`). If a wordlist source provides a single canonical form, generating both upper and lower variants doubles the search cost but is usually worthwhile.

Slot 2 (panel name) matching is **case-insensitive** — the panel performs internal case folding. Once the BLN is known, slot 2 enumeration can use any reasonable casing.

### 22.4 BACnet-Side Discovery

If the site supports BACnet/IP (UDP/47808), a BACnet Who-Is broadcast may return device names and identifiers that can be cross-referenced with P2 BLN/node names. The two namespaces are distinct but often related (a panel's BACnet device name often matches or contains its P2 node name).

### 22.5 TCP/IP Layer Fingerprint — Panel vs Supervisor Classification

A PXC panel and a Windows-based supervisor can be distinguished without sending any P2 frames, using only passive TCP/IP-layer observations. The PXC platform runs Mentor Graphics Nucleus PLUS RTOS with the Nucleus NET TCP/IP stack (see §21.4), which has a distinctive fingerprint:

| Signal | PXC panel (Nucleus NET) | Windows supervisor |
|---|---|---|
| IPv4 TTL on outbound packets | **64** | **128** |
| Initial TCP window | **16000** (constant, never grows) | ~64240, varies per session |
| Zero-window emissions during bursts | Yes (Nucleus backpressure) | Rare |
| OS-level TCP keepalive packets | None (uses application-layer `0x4640`) | Yes (when configured) |
| TCP timestamp option | Absent | Present |

**Combined classifier**: a host that listens on TCP/5033, sends packets with IPv4 TTL=64, and uses a constant initial TCP window of 16000 is a PXC panel with high confidence. A scanner can use this fingerprint to skip a wasted handshake attempt against a Windows supervisor that happens to listen on TCP/5033 (which a few site configurations expose).

This fingerprint is purely passive — it requires only that a single TCP segment from the target host be observed. The signal holds across firmware versions because it derives from Nucleus stack defaults, which Siemens has not changed across any P2-era firmware revision.

---

## 23. Identity-Leak Surfaces

This section enumerates protocol features that reveal panel identity information to a passive or low-touch observer. Implementers of defensive monitoring tools SHOULD be aware of these surfaces; discovery-tool implementers can use them as shortcuts during cold-site discovery.

### 23.1 Routing Header in Any Response

**Every successful AND every error response** carries the panel's BLN name (slots 1 and 3) and its node name (slot 4 after the role swap). A single arbitrary read against a panel — even one returning `0x0003 not_found` — reveals the panel's identity in the response routing header.

A scanner that already knows the panel's IP can send a deliberately-doomed read (e.g. point name `xxxxx`) and learn the panel's name and BLN from the error response.

### 23.2 `0x4640` IdentifyBlock Success Response

A successful handshake response carries the panel's full IdentifyBlock TLVs (self-name, site code, BLN name). This is the most direct identity-information leak.

### 23.3 `0x010C` SystemInfo Response — The Firmware Fingerprint

The 269-byte `0x010C` response reveals:

- Firmware build (e.g. `PME1252`, `PME1300` — labeled "panel model" in the wire TLV but actually a firmware-build identifier)
- Hardware platform and firmware version (e.g. `PXME V2.8.18 APOGEE`)
- Build date (e.g. `Sep 26 2019 12:41:20`)
- Node number (embedded in feature bytes)
- Site code (in the IdentifyBlock TLV)

This is the highest-value identity leak in the protocol — `0x010C` returns more information about a panel in a single response than any other opcode.

### 23.4 `0x0050` and `0x0606` Lightweight Probes

`0x0050` (StatusQuery) returns the supervisor name (in bare form, without `|<port>` suffix). It works **without** requiring a valid handshake — the panel responds to the probe based purely on TCP-layer state. Useful for discovering the BLN's supervisor identity without prior knowledge.

`0x0606` is a similar lightweight probe with a slightly different response shape; behavior across firmware revisions varies.

### 23.5 `0x4634` Routing-Table Push — Topology in One Message

When a supervisor or panel broadcasts its routing table via `0x4634`, a passive observer captures:

- Every BLN peer name (panels and supervisors)
- Per-peer cost metrics (provides relative network position)
- Special entries (`$paneldefault`, site code, BMS-registered name)

A single `0x4634` capture enumerates the entire BLN topology — no brute-force panel-name attack required. Routing tables are pushed periodically (every ~60-300 seconds depending on firmware) and on configuration changes.

### 23.6 Panel-Initiated CONNECT — 10-16 Second Self-Announcement

Panels typically initiate an outbound TCP connection to their configured supervisor's port 5034 within 10-16 seconds of bootup. The CONNECT frame carries the panel's full identity (node name, site code, BLN name). A passive listener on the supervisor IP would capture this announcement and learn the panel's identity without sending anything.

### 23.7 BACnet Who-Has Broadcasts — Site-Code Extraction

In BACnet-mode deployments, the supervisor periodically sends BACnet Who-Has queries that include the site code in the search criteria. A passive BACnet observer extracts the site code without P2-layer interaction.

### 23.8 P2-Over-BACnet Transport (Passive — SPAN Required)

When AP2 is wrapped inside BACnet ConfirmedPrivateTransfer (CPT) on UDP/47808, all of the above identity leaks are still present in the encapsulated payload. A BACnet sniffer parsing CPT requests with Siemens Vendor ID 7 captures the full P2 frames inside.

### 23.9 Mitigation for Defenders

If you're operating a P2 deployment and want to reduce identity-leak exposure:

1. **Restrict network access** to the BLN — segment the BAS network on its own VLAN; do not bridge to corporate LAN.
2. **Filter UDP/10001** at network boundaries — the presence beacon is not needed outside the BAS segment.
3. **Disable Telnet** on all field panels (TCP/23, disabled by default but verify).
4. **Update firmware** to V2.8.20+ (P2 line) or V3.5.5+ (BACnet line) to close the predictable-TCP-ISN session-hijack vulnerability (§21.2).
5. **Monitor for unexpected TCP/5033 connections** from non-supervisor IPs — there should be none in steady state.
6. **Rate-limit `0x0050` and `0x0606` probes** at the firewall if possible — these are common cold-discovery primitives.

---

## 24. Implementation Guide

This section provides practical guidance for implementing a P2 client (scanner, dissector, gateway). It assumes the reader has read §1-§23.

### 24.1 Minimum Viable Scanner

The simplest read-only scanner needs to:

1. Acquire three identifiers: target IP, BLN name, and a scanner name.
2. Open a TCP connection to the target's listening port (typically 5033).
3. Perform a dialect-detecting handshake (§9 + §11).
4. Issue a read or enumerate operation.
5. Parse the response, handling both success (`0x01`) and error (`0x05`) directions.
6. Close the connection.

```python
# Pseudocode for a minimum scanner
def read_point(host, bln, scanner, node, device, point_name):
    sock = tcp_connect(host, 5033, timeout=5)
    if not handshake(sock, bln, scanner, node):
        return None
    seq = random_24bit_seq()
    request = build_read_request(
        seq=seq, bln=bln, scanner=scanner, node=node,
        target_device=device, target_point=point_name,
        msg_type=cached_dialect[host] or 0x33  # try 0x33 first
    )
    sock.send(request)
    response = recv_frame(sock)
    if response.direction == 0x05:
        return {"error": response.error_code}
    return parse_value(response.body)
```

### 24.2 Required Configuration

A scanner needs the following configuration:

| Field | Purpose | How to obtain |
|---|---|---|
| **BLN name** (network name) | Soft authentication. Panels reject messages with the wrong name. | Site documentation, sniff existing traffic, or use `0x0050` StatusQuery |
| **Scanner name** | Self-identifier in `<HOSTNAME>\|<PORT>` form | Choose freely (e.g. `P2SCAN\|5034`) unless the site requires a specific format |
| **Site name** | Required for handshake identity block | Site documentation |
| **Target IP** | Panel address | Discovery via multicast beacon (§3.2.2) or range scan |
| **Node name** | Optional self-identifier; can be `"node"` for read-only scanners | — |
| **Target listener port** | TCP port the **panel** is listening on (typically 5033) | Default 5033; some sites use alternates; configurable per panel |
| **Scanner listener port** | TCP port the **scanner** listens on for inbound pushes (encoded as `\|<port>` in slot 4 identity) | Typically 5034 to mirror Desigo CC; any free port works |

### 24.3 Recommended Connection Lifecycle

```
[per panel:]
1. tcp_connect(panel_ip, port=5033, connect_timeout=5s)
2. handshake() with dialect auto-detect:
     a. Send 0x33 identity with short probe timeout (≤2s)
     b. On no response: send 0x34 identity with full timeout
     c. Cache the discovered dialect per IP
3. Issue operational requests; one outstanding request at a time per session
4. Re-send 0x4640 identity refresh every 10 s during idle periods (match Desigo CC's observed cadence; see §9.5)
5. close() on done OR on protocol error
```

### 24.4 Connection Limits

In practice, field panels accept on the order of **8–16 concurrent peer sessions**; the exact limit is vendor-internal and varies by firmware revision. Exceeding the limit returns a connection refusal or a session-limit error on handshake.

Implementers SHOULD:

- Avoid running multiple parallel scanners against the same panel.
- Close connections promptly when done.
- Implement a connection pool with reuse if doing many sequential reads against the same panel.
- Back off and retry if connection setup fails with a session-limit error.

### 24.5 Sequence Number Convention

- Initialize the sequence at a **random 24-bit value** at session start (not 0 or 1).
- Increment monotonically per request.
- The panel's response echoes the request sequence; correlate by sequence not by arrival order.
- **Pair with sliding-window tolerance, not strict equality.** In busy sessions the panel's response sequence runs 1–17 frames behind the request sequence in roughly 10% of pairs (pipelining lag, see §5.2). A parser that requires strict equality will appear to lose ~10% of responses. Use a sliding-window matcher with a tolerance of at least 20 frames.

### 24.6 Buffering and Framing

A TCP stream may contain multiple P2 frames, or it may split a single frame across segments. Implementations MUST:

1. Read 4 bytes to obtain `total_length`.
2. Read until exactly `total_length` bytes (counting those first 4) have been received before parsing the frame.
3. Treat any frame with `total_length > 65536` as framing corruption and close the connection.
4. Buffer any bytes received past the end of the current frame for the next frame; do not assume frame boundaries align with TCP segment boundaries.

### 24.7 Common Implementation Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Hardcoded `session_msg_type = 0x33` | Modern panels silently don't respond | Implement dialect auto-detection (§11) |
| Sequence starting at 0 or 1 | Panel rejects handshake or silently drops | Use random 24-bit initial sequence |
| No identity refresh | Connection drops after idle timeout | Send `0x4640` every 10 s (see §9.5) |
| Treating the first u32 as body-only length | Short reads, off-by-12 framing errors | First u32 is `total_length` and includes the 12-byte session header; loop reads until that many bytes have accumulated |
| Mismatched BLN name in identity | Handshake fails silently | Use the same BLN name the panel is configured for |
| Writing SYST-scoped point with `0x0240` | Returns error `0x0E15` | Retry as `0x4222` BulkPropertyWrite |
| Treating `0x0274` direction as fixed | Misinterpret virtual writes as COV notifications | Check TCP port: 5033 = write, 5034 = COV |
| Not handling error responses (`direction = 0x05`) | Treat error as success | Check direction byte; parse error code if `0x05` |
| Cold scanning a production system without rate-limiting | Floods panels, may trip alarms | Insert ≥1-second delay between probes |

### 24.8 Multicast Beacon Listener

For passive discovery, a scanner may listen for the UDP/10001 presence beacon:

```python
import socket, struct
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 10001))
group = socket.inet_aton("233.89.188.1")
mreq = struct.pack("4sL", group, socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
while True:
    data, addr = sock.recvfrom(64)
    if data == b"\x01\x00\x00\x00":
        print(f"Beacon from {addr[0]}")
```

A scanner listening for ~12 seconds will catch at least one beacon (the cadence is ~10.5 seconds). For higher confidence, listen for ~30 seconds.

The beacon source IP is typically the panel's gateway, not the panel itself. To discover individual panels behind the gateway, follow up with active probes (port scan, BACnet Who-Is, P2 handshake) against the gateway's subnet.

### 24.9 Active Discovery Without Multicast

When the multicast beacon is filtered (segmented IT-managed networks often block UDP multicast at boundaries), use active discovery:

1. **Port scan** the target subnet for TCP/5033.
2. For each responder, attempt the handshake with a candidate BLN name.
3. If you don't know the BLN name, try `0x0050` StatusQuery — it returns the supervisor name without requiring authentication, which lets you derive the BLN name from observed traffic patterns.

### 24.10 Reading Points by Slot vs by Name

Two ways to address points:

- **By slot number**: encode the address as `FLN.Drop.SlotNumber` (modern format, §16.1).
- **By name**: encode the address as a length-prefixed string like `"<DEVICE>:<POINT>"`.

Reading by slot is faster (no name resolution at the panel) and more reliable when the supervisor's database is incomplete. Reading by name is more flexible when slot numbers vary across firmware versions of the same application.

### 24.11 Application-Specific Point Lookup

The vendor catalog associates each TEC application number (e.g. 2020 = VAV Cooling Only) with a fixed point database (slot 1 = CTLR ADDRESS, slot 4 = ROOM TEMP, etc.).

A scanner reading by slot SHOULD:

1. Read the device's APPLICATION subpoint (slot 2) first to identify which catalog applies.
2. Look up the slot-to-name mapping for that application from a local catalog.
3. Apply per-slot scaling (slope, intercept, engineering units) when rendering values for display.

### 24.12 Read-Only by Default

Tools published openly SHOULD be read-only by default. Write opcodes (`0x0240`, `0x0274`, `0x4222`, `0x4106`, etc.) MUST be:

- Disabled in the default build
- Behind an explicit `--write` or `--enable-writes` flag
- Rate-limited to prevent EEPROM wear (§18.3 — 100,000-write lifetime limit on non-unbundlable subpoints)
- Blocklisted for operations whose effects are not understood (firmware download, factory reset, cold start)

### 24.13 Testing on Production Systems

Active probing of production building-automation systems can cause real-world impact:

- Flooding panels with probes can trigger BAS alarm-event amplification.
- Cold-start opcodes can erase panel databases.
- Mistakenly writing a setpoint can cause comfort or safety issues.

Implementers and operators SHOULD:

1. Always test on a lab or maintenance-window deployment first.
2. Maintain a kill switch (signal handler, watchdog timer) in every active tool.
3. Inter-probe delay ≥1 second during production hours.
4. Snapshot the panel database before any write-capable operation.
5. Document the test scope (target IPs, time window, kill criteria) before starting.

---

## 25. Appendix A: Default Timer Values

| Timer | Default | Maximum | Purpose |
|---|---|---|---|
| Intra-site EPing Period | 10 s | — | Discovery heartbeat within a site |
| Intra-site EPing Timeout | 5 s | — | Failure detection threshold |
| Inter-site EPing Period | 60 s | 900 s | Heartbeat between sites |
| Inter-site EPing Timeout | 5 s | — | Inter-site failure threshold |
| Intra-site Notification Period | 10 s | — | Replication push interval (same site) |
| Intra-site Polling Period | 60 s | — | Replication safety-net poll (same site) |
| Intra-site Cycle Timeout | 15 s | — | Max replication cycle duration |
| Inter-site Notification Period | 10 s | 900 s | Cross-site replication push |
| Inter-site Polling Period | 180 s | 900 s | Cross-site safety-net poll |
| Inter-site Cycle Timeout | 15 s | 900 s | Cross-site cycle max |
| Holdback Delay | 10 s | — | Wait after change burst before propagating |
| Tombstone Lifetime | 86400 s | — | Memory of failed peers |
| COV Resubscribe Period | 60 min | — | Workstation re-subscribes to all COVs |
| COV Poll Rate | 60 s | — | Fallback poll for COV-subscribed points |
| MS/TP Keep Alive Poll Rate | 60 s | 10-300 s | Poll live MS/TP devices |
| MS/TP Discovery Poll Rate | 60 s | 10-300 s | Poll failed MS/TP devices |
| BLN Time Synchronization | 00:00 daily | — | Default BLN clock sync time |
| Bridge TCP Keepalive | 45 s | — | Lantronix bridge keepalive |

---

## 26. Appendix B: BACnet Integration Reference

### 26.1 BIBB Support (Terminal Equipment Controller — BACnet variant)

| BIBB | Direction | Service |
|---|---|---|
| DS-RP-B | Responder | Data Sharing — ReadProperty |
| DS-RPM-B | Responder | Data Sharing — ReadProperty Multiple (newer revisions only) |
| DS-WP-B | Responder | Data Sharing — WriteProperty |
| DM-DDB-B | Responder | Device Management — Dynamic Device Binding (Who-Is/I-Am) |
| DM-DOB-B | Responder | Device Management — Dynamic Object Binding (Who-Has/I-Have) |
| DM-DCC-B | Responder | Device Management — Device Communication Control |

BIBBs explicitly NOT supported by basic BACnet TECs:

- DS-COV-B (Change-of-Value subscription) — supervisor MUST poll for value changes
- T-V-B (Trend Log viewing)
- AE-N-B / AE-ACK-B (Alarm and Event Notification/Acknowledgment)
- SCHED-V-B / SCHED-A-B (Schedule object)
- AE-N-E-B (External Algorithmic Alarming)
- T-VMT-E-B (External Trend)
- SCHED-E-B (External Schedule)

A supervisor monitoring a BACnet-TEC fleet MUST poll each commandable point at the desired update rate, as the controllers do not push value changes spontaneously.

### 26.2 BACnet Network Configuration Defaults

| Setting | Default |
|---|---|
| BACnet IP Network Number | 1 |
| UDP Port | 47808 |
| Vendor ID filter (I-Am discovery) | 7 (Siemens) |
| Process ID list (workstation registration) | 0 and 600 |
| Device Reserved Instance Base | 10000 |
| Act as a Foreign Device | NO |

---

## 27. Appendix C: Glossary

| Term | Definition |
|---|---|
| **AEM** | Apogee Ethernet Module — Lantronix-based serial-to-Ethernet bridge that exposes a legacy P2 RS-485 BLN over TCP/IP (TCP/3001 for the P2 trunk). Vendor-licensed under SKU `LSM-VAEM` ("Virtual AEM"). See §3.2.4 and §21.5. |
| **ALN** | Automation Level Network |
| **AP2** | Apogee Protocol 2 (this specification's wire protocol) |
| **AP2Cmd** | A unit of work in the protocol (one operation with parameters) |
| **BACnet** | Building Automation and Control Network (ASHRAE 135) |
| **BBMD** | BACnet Broadcast Management Device |
| **BLN** | Building Level Network |
| **CPI** | Common Protocol Interface (supervisor-side dispatch namespace) |
| **CPT** | ConfirmedPrivateTransfer (BACnet service 18) |
| **COV** | Change-of-Value |
| **DDC** | Direct Digital Control |
| **DXR** | Discrete eXtensible Router (a BACnet/IP-native FLN device class) |
| **EPing** | Ethernet Ping — periodic heartbeat |
| **FLN** | Field Level Network |
| **HMI** | Human-Machine Interface |
| **MLN** | Management Level Network (the network connecting supervisors) |
| **MS/TP** | Master-Slave/Token-Passing (BACnet RS-485) |
| **OIP** | Operator Input Program (PPCL statement and wire operation) |
| **P1** | The legacy serial FLN protocol |
| **P2** | The supervisor↔panel protocol described herein. Long-form: "Protocol 2". |
| **P3** | A sister protocol named alongside P2 in vendor cable-type lists ("P2/P3 RS-485") and in the Siemens error text for `0x00AC`. Not described by this specification. |
| **`.P2` file** | An offline panel-database export file format produced by Desigo CC's P2 Export utility. Contains engineered panel configuration (points, PPCL, schedules, alarms) for migration tooling. **Unrelated to the P2 wire protocol** despite the shared name. |
| **PDL** | Peak Demand Limiting |
| **PPCL** | Process Control Language (proprietary panel-resident programming) |
| **POST** | Panel Operating System Transfer (database file format) |
| **PTM** | Point Termination Module |
| **PXC** | Modern field-panel hardware family (PXC Modular and PXC Compact). Successor to the legacy MEC / Power MEC / MBC controllers. |
| **PXC Modular** | DIN-rail field panel; orderable as `PXC100-PE##.A` (P2 firmware loadout) or `PXC100-BE##.A` (BACnet loadout). Up to 500 points via TX-I/O. |
| **PXC Compact** | Pre-configured 16/24/36-point field panel; orderable as `PXC16-PE.A`/`PXC24-PE.A`/`PXC36-PE.A` (P2) or `PXC16-BE.A`/`PXC24-BE.A`/`PXC36-BE.A` (BACnet). EU variants are PXC12/PXC22. |
| **PXME** | Hardware-platform identifier returned in revstrings: PXC Modular Ethernet. Sibling codes: `PXCE` (PXC Compact Ethernet), `PXMR` (PXC Modular RS-485-only), `PXCR` (PXC Compact RS-485-only). |
| **PME####** | Firmware-build identifier on the P2 firmware family (2.x branch). Known builds include `PME1121` (V2.8.5), `PME1252` (V2.8.10), `PME1300` (V2.8.18). Returned in revstrings and in the `0x010C` SystemInfo response. |
| **BME####** | Firmware-build identifier on the BACnet firmware family (3.x branch). Sibling of `PME####`. Example: `BME1290` (V3.5.2). |
| **MEC** | Modular Equipment Controller (legacy 1300-series field panel, RS-485 ALN). Predecessor to PXC Modular. |
| **Power MEC** | MEC variant with Ethernet ALN (model 1200/1210 series). Same chassis family as MEC, with onboard or external Ethernet support. |
| **MBC** | Modular Building Controller (legacy field panel). Largely retired; replaced by PXC Modular. |
| **SSTO** | Start/Stop Time Optimization |
| **TEC** | Terminal Equipment Controller |
| **UC** | Unitary Controller |
| **VFD** | Variable Frequency Drive |

---

## 28. Appendix D: Complete Opcode Reference Table

The 416-opcode catalog organized by primary function. The "Sub-op" column shows the CPI sub-opcode value placed at AP2Cmd `[+0x06]` (and therefore appearing on the wire immediately after the 2-byte wire opcode) when the encoder writes one. A "—" entry means either (a) the operation does not write a value at `[+0x06]` and the field carries a class-default value, or (b) the wire bytes after the opcode are opcode-specific (for example, TLV data, as with `0x4640`). See §7 and the per-opcode entries in §6 and §12 for body shape.

### 28.1 Point I/O Operations (0x02xx, 0x04xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x0220` | `0x00xx` | ReadShort / RegisterCOV | 5033 | Compact read; variants `0x0220`-`0x0223` |
| `0x0240` | `0x0004` | WriteWithQuality | bidirectional | NONE-scope (5034 ACK) or SYST-scope (5033, retries as `0x4222`) |
| `0x0241` | `0x0030` | PropertyEcho / DefaultPropertyResolve | 5033 | SYST-scoped, paired-response (see §29.6) |
| `0x0244` | `0x00xx` | CancelCOV / ScopedQuery | 5033 | Variants `0x0244`-`0x024D` |
| `0x0271` | `0x0010` | ReadExtended | 5033 | Legacy read; full value block |
| `0x0272` | `0x0012` | Read-MetaOnly | 5033 | Descriptor lookup without value |
| `0x0273` | `0x0011` | WriteNoValue / PointProbe / AlarmAckTrigger | 5033 | ACK-only; existence probe |
| `0x0274` | `0x0001` | ValuePush | bidirectional | Virtual write (5033) or COV notification (5034) |
| `0x0291` | — | SYST property read | 5033 | Carries SYST scope footer |
| `0x0294` | `0x0704` | SYST read (small/large variants) | 5033 | 53-byte sep=0x00 or 222-byte sep=0x01 |
| `0x0295` | `0x0702` | SYST read (sibling) | 5033 | Plant-equipment status registers |
| `0x02A1` | `0x0703` | (SYST scoped) | 5033 | — |
| `0x02A8` | — | SYST property op | 5033 | Carries SYST scope footer |
| `0x02E2` | `0x00xx` | ReadProcessData | 5033 | — |
| `0x0263` | — | SYST property op | 5033 | Carries SYST scope footer |

### 28.2 Discovery / Identity / Status (0x00xx, 0x46xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x0050` | — | StatusQuery | 5033 | Leaks supervisor name without authentication |
| `0x0100` | `0x0118` | SystemInfo (legacy) | 5033 | Firmware/model query; legacy CONNECT response |
| `0x010C` | — | SystemInfo (compact) | 5033 | 2-byte request; preferred for modern panels |
| `0x0606` | — | Lightweight probe | 5033 | Similar to `0x0050` |
| `0x4633` | `0x1601` | ReplNotify-init | bidirectional | Replication subsystem |
| `0x4634` | — | RoutingTable | bidirectional | Topology announcement (port-agnostic) |
| `0x4635` | `0x1603` | ReplNotify-event | bidirectional | Replication subsystem |
| `0x4636` | `0x1604` | ReplChanges | bidirectional | Replication update push |
| `0x4640` | `0x1600` | IdentifyBlock / EPing | bidirectional | Handshake identity + 10s heartbeat |

### 28.3 Alarms (0x05xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x0500` | — | AckAlarm (legacy) | 5033 | Alarm acknowledgment. CPI `0x0F01` maps here but is not written at `[+0x06]` |
| `0x0508` | — | AlarmReport | 5034 | Panel-initiated alarm notification |
| `0x0509` | `0x0F01` | AlarmAck (v2) | 5033 | Newer alarm-ack variant; writes `0x0F01` at `[+0x06]`. Polymorphic — see §6.6 |
| `0x0567` | `0x0F33` | (alarm priority op) | 5033 | — |

### 28.4 Object Lifecycle (0x02xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x0203` | — | ObjectLifecycle (probe) | 5033 | Carries name + initial-value f32 |
| `0x0204` | — | CreateObject | 5033 | Returns `0x0E11` already_exists if present; carries name + initial-value f32 |
| `0x0245` | — | TestProbe | 5033 | Always errors; not a real operation |
| `0x0260` | — | ObjectLifecycle (probe variant) | 5033 | Carries f32 = 1.0 default-value |
| `0x0263` | — | ObjectLifecycle (probable delete) | 5033 | ACK-only response, no per-object data; carries SYST footer (see §29.7) |
| `0x0368` | — | NodeRoutingQuery | 5033 | — |
| `0x4500` | — | TestProbe | 5033 | Always errors; test artifact only (paired with `0x0245`) |

### 28.5 Enumeration (0x09xx)

The 0x09xx family covers point enumeration, schedule queries, FLN device listing, and assorted reads. Cursor-paginated opcodes return entries until the cursor wraps to `0x0000` or to an end sentinel.

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x0961` | — | AnalogPointQuery (legacy) / EnumeratePoints FLN scope | 5033 | Cursor-based. Polymorphic — see §6.6 |
| `0x0962`, `0x0963` | — | Enumerate variants | 5033 | Sibling reads; often `0x0003` on legacy firmware |
| `0x0964` | — | TitleAnalogQuery | 5033 | Value + units + limits. Polymorphic — see §6.6 |
| `0x0965` | — | NodeDiscoveryEnumerate | 5033 | Slim `0x0986`-equivalent reachability probe |
| `0x0966` | — | ShortQuery (probe; mostly errors) | 5033 | 4-byte body, no SYST tag |
| `0x0967`, `0x0968` | — | Enumerate variants | 5033 | Sibling reads |
| `0x0969` | — | ScheduleObjectList | 5033 | Returns schedule object names under a parent |
| `0x096B` | — | Enumerate variant | 5033 | — |
| `0x0971` | — | EnhancedPointRead / EnumeratePoints subnet scope | 5033 | desc + value + units + min/max + type |
| `0x0972`, `0x0973` | — | Enumerate variants | 5033 | — |
| `0x0974` | — | MultistatePointEnumerate | 5033 | State-set-aware variant of `0x0964` |
| `0x0975` | — | NodeDiscoveryWithLines | 5033 | Cursor + line-number trailer |
| `0x0976` | — | DeviceAllSubpointsRead | 5033 | Bulk per-device f32 dump; two request shapes — see §29.12 |
| `0x0977`, `0x0978` | — | Enumerate variants | 5033 | — |
| `0x0979` | — | ShortVariant | 5033 | Cross-opcode `0x0271` reference in trailer |
| `0x097B`-`0x097F` | — | Enumerate variants | 5033 | Sibling reads in the 097x family |
| `0x0981` | — | EnumeratePoints (panel-wide) | 5033 | Cursor-based; includes PPCL variables |
| `0x0982` | — | EnumerateTrended | 5033 | Cursor-based + timestamps |
| `0x0983`, `0x0984`, `0x0987`, `0x0989` | — | EnumerateVariant | 5033 | Often returns `0x00AC` on older firmware |
| `0x0985` | — | EnumeratePrograms | 5033 | PPCL programs + source text |
| `0x0986` | — | EnumerateFLN | 5033 | FLN device list; two cursor formats |
| `0x0988` | — | EnumerateMulti | 5033 | Multi-string filter (device AND subpoint AND variant) |
| `0x098B` | — | Enumerate (newer-firmware probe) | 5033 | Constant body `09 8B 00 01 00 FA 00 00`; often errors `0x0003` |
| `0x098C` | — | ScheduleSetpointTable | 5033 | 5–7 floats per row — heat/cool setpoint band |
| `0x098D` | — | ScheduleEntries (weekly schedule with BACnet dates) | 5033 | 4-byte BACnet date encoding |
| `0x098E` | — | ScheduleGainConfig (PID/gain rows) | 5033 | 7 floats per row — gains, deadtime, sampling |
| `0x098F` | — | ScheduleDeadband (single f32) | 5033 | — |
| `0x099D`, `0x099E` | — | Enumerate variants | 5033 | — |
| `0x099F` | — | GetPortConfig | 5033 | 5-byte body; 6 indices walked (`0xFF`, `0x00`-`0x04`) — see §29.5 |
| `0x09A1`, `0x09A2`, `0x09A3`, `0x09A5`-`0x09A7`, `0x09A9`-`0x09AB` | — | Newer-firmware enumerate variants | 5033 | Often `0x00AC` on legacy firmware |
| `0x09B9`, `0x09BA`, `0x09BB` | — | Newer-firmware enumerate variants | 5033 | Often `0x00AC` on legacy firmware |
| `0x09BD` | `0x0802` | Network-status read | 5033 | Sets `[+0x06] = 0x0802` |
| `0x09BF` | `0x0803` | Network-status read | 5033 | Sets `[+0x06] = 0x0803` |
| `0x09C1`, `0x09C2`, `0x09C3` | — | Newer-firmware enumerate variants | 5033 | Often `0x00AC` on legacy firmware |

### 28.6 Session Keepalive (Bare 2-byte pings on 0x33 sessions)

These opcodes appear as 2-byte bare-opcode keepalive frames panel → supervisor inside an established Mode A session. They have no body.

| Opcode | Notes |
|---|---|
| `0x0951` | BarePing (panel-specific 2-byte keepalive) |
| `0x0954` | BarePing |
| `0x0955` | BarePing |
| `0x0956` | BarePing |
| `0x0959` | BarePing |

### 28.7 Status / Cold-Discovery Probes

| Opcode | Sub-op | Name | Notes |
|---|---|---|---|
| `0x0050` | — | StatusQuery | 14-byte body; leaks supervisor bare-form name without authentication |
| `0x0606` | — | Ping | 14-byte body; leaks panel name in routing header response |
| `0x5354` | — | Status probe | 14-byte constant body; always errors `0x0003`; semantics unknown |

### 28.8 PPCL Editor and Display (0x040A, 0x41xx, 0x5038)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x040A` | — | MultiStateLabelCatalog | 5033 | State-text labels for multi-state points |
| `0x4100` | — | PpclLineUpdate (polymorphic; also Report-EQS-MemberLog) | 5033 | Carries SYST scope footer |
| `0x4103` | `0x04xx` | PpclClearTrace | 5033 | `00 01 7F FF` tracebit-clear marker; 12-byte SYST scope footer adjacent |
| `0x4104` | — | PpclUpload (LineRead/Delete) | 5033 | Line-number + length/mode u16s |
| `0x4106` | `0x0xxx` | DefinePpcl | 5033 | Install program; clears tracebits + triggers re-execution |
| `0x4107` | `0x0412` | PPCL op | 5033 | — |
| `0x4108` | `0x0414` | PPCL op | 5033 | — |
| `0x410E` | `0x0403` | PPCL op | 5033 | — |
| `0x4137` | `0x0417` | PPCL op | 5033 | — |
| `0x5003` | — | ScheduleObjectInfoQuery | 5033 | — |
| `0x5020` | — | ScheduleEntryWrite | 5033 | — |
| `0x5022` | — | ScheduleSlotInit | 5033 | Allocate-then-write pair |
| `0x5038` | — | ObjectDisplayLabels | 5033 | Cursor enumerate name→label |

### 28.9 SYST-Scoped Property Operations

| Opcode | Notes |
|---|---|
| `0x0241` | PropertyEcho / DefaultPropertyResolve (SYST) — echoes (dev, pt) for fully-qualified targets; fills MODE/etc. into empty 2nd-TLV for object-only probes |
| `0x0244` | ScopedQuery (SYST-restricted read variant; returns `0x0002` out-of-scope) |
| `0x0291` | SYST property op (probable write — `01 00 c8 [type] [f32]` value marker) |
| `0x0294` | SYST read variant — small (53B sep=0x00) and large (222B preallocated sep=0x01) forms |
| `0x0295` | SYST-scoped read (sibling of 0x0294; plant-equipment status registers) |
| `0x02A8` | SYST property op (probable write w/ priority trailer `50 00`; otherwise like 0x0291) |

### 28.10 Bulk Property (0x42xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x4200` | `0x1103` | PropertyQuery | 5033 | Browse (~30-40 B) or deep-read (222 B) forms |
| `0x4220` | — | BulkProperty variant (222B preallocated) | 5033 | `00 10` selector at sentinel. Provisional — prefer `0x4221` (see §29.10) |
| `0x4221` | `0x11xx` | BulkPropertyRead (273B form) | 5033 | Constant 273-byte preallocated request |
| `0x4222` | `0x1114` | BulkPropertyWrite | 5033 | Canonical SYST setpoint write; `0x0240` retry target |
| `0x4245` | `0x1202` | SensitivityReport | 5033 | — |

### 28.11 BACnet Integration (0x40xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x4000` | `0x1000` | BACnet op | 5033 | — |
| `0x4001`-`0x4006` | — | BACnet op variants | 5033 | Sub-opcodes inherited; capability probes on legacy firmware |
| `0x400B` | `0x1007` | BACnet op | 5033 | — |
| `0x400C` | `0x1008` | BACnet op | 5033 | — |
| `0x400D`, `0x400E` | — | BACnet op variants | 5033 | — |
| `0x400F` | — | UploadReportDescriptor probe (CPI `0x100D`) | 5033 | Often `0x00AC` on legacy firmware |
| `0x4010` | — | UploadTeamDescriptor probe (CPI `0x100A`) | 5033 | Often `0x00AC` on legacy firmware |
| `0x4011` | — | DefineReportDescriptor probe (CPI `0x100C`) | 5033 | Often `0x00AC` on legacy firmware |
| `0x4017` | `0x100E` | BACnet op | 5033 | — |
| `0x4018` | — | BACnet op variant | 5033 | — |
| `0x4133` | — | Capability probe | 5033 | Constant 12–17 byte body; often `0x00AC` on legacy firmware |

`0x4500` is unrelated to the BACnet family — it is a test-probe artifact (always errors) and is listed in §28.4 Object Lifecycle.

### 28.12 BLN Management (0x43xx, 0x48xx, 0x4Bxx, 0xF0xx)

| Opcode | Sub-op | Name | Direction | Notes |
|---|---|---|---|---|
| `0x4300` | `0x1500` | Network maintenance | 5033 | — |
| `0x4332` | `0x1504` | Network maintenance | 5033 | — |
| `0x4824`-`0x4B03` | `0x208x` | BLN management ops | 5033 | Various |
| `0x4842` | `0x0704` | (alarm/event extended) | 5033 | — |
| `0x4967` | `0x112F` | (bulk/modify) | 5033 | — |
| `0xF038` | `0x2097` | BLN management | 5033 | Vendor-extended range |

### 28.13 Reserved and Vendor-Extended Ranges

| Range | Status |
|---|---|
| `0x0000`-`0x6FFF` | Standard AP2 operations (416 catalogued) |
| `0x7000`-`0xEFFF` | Reserved |
| `0xF000`-`0xFFFF` | Vendor-extended (sub-opcode high byte `0xE3` for opcodes `0x0031`-`0x0033`) |

### 28.14 Notes on Catalog Completeness

The 416 catalogued wire opcodes are those reachable through the supervisor's protocol dispatcher. Implementers may encounter additional reserved or rarely-used opcode values that this specification does not enumerate; parsers SHOULD treat unknown opcode values as informational and SHOULD NOT close the connection on first sight of an unrecognized opcode.

Of the 416 opcodes, **134 explicitly set the `[+0x06]` CPI sub-opcode** (the value appears on the wire immediately after the 2-byte opcode); the remaining 282 leave `[+0x06]` at its inherited class-default value.

---

## 29. Appendix E: Wire Body Catalog

This appendix specifies the exact wire bodies for opcodes whose formats are stable. These complement the prose descriptions in §12 and are intended for parser, dissector, and fuzzer authors who need byte-level reference.

Notation: byte sequences are shown as hex pairs separated by spaces; quoted ASCII represents the literal characters; `LL` denotes a u16 BE length field; angle brackets `<…>` denote variable content.

### 29.1 `0x0050` StatusQuery — Constant 14-byte Body

**Request body** (always exactly 14 bytes):

```
00 50 01 00 04 "SYST" 23 3F FF FF FF
```

The `0x23` separator marks SYST scope; the `3F FF FF FF` sentinel is the standard SYST-scope wildcard.

**Response body** (~30 bytes, supervisor-name leak):

```
01 00 04 "SYST" 23 3F FF FF FF 00 02 01 00 LL <SVR-name> 01 00 00
```

Response field breakdown:
- `01 00 04 "SYST" 23 3F FF FF FF` — request SYST scope echoed back (12 bytes)
- `00 02` — u16 BE status / TLV-count field (constant `0x0002`; precise semantic unconfirmed)
- `01 00 LL <SVR-name>` — TLV carrying the supervisor's bare-form name (no `|<port>` suffix)
- `01 00 00` — trailing empty TLV terminator

This opcode responds **without requiring a valid handshake** — the panel answers based on TCP-layer state alone, making it the lowest-touch cold-discovery primitive.

### 29.2 `0x0606` Lightweight Probe

**Request body** (14 bytes; same shape as `0x0050` with different opcode):

```
06 06 01 00 04 "SYST" 23 3F FF FF FF
```

Response carries the panel name in the routing header (slot 4 after role-swap). Body is typically empty or near-empty. Behavior across firmware revisions varies.

### 29.3 `0x5354` — Status Probe (Always Errors)

**Request body** (constant 14 bytes):

```
53 54 01 00 04 "SYST" 00 3F FF FF FF
```

**Note the `0x00` separator** (not `0x23`) — this distinguishes `0x5354`'s body from `0x0050` and `0x0606`. The opcode always returns error code `0x0003` (not_found); the semantics of the operation are not defined by this specification. Parsers and IDS signatures SHOULD recognize the constant body but treat the operation as a probe-only artifact.

### 29.4 `0x098B` — Newer-Firmware Enumerate Probe

**Request body** (constant 8 bytes on firmware builds `PME1252` and `PME1300`):

```
09 8B 00 01 00 FA 00 00
```

The `00 01` and `00 FA` (= 250) bytes are constants — apparently a hardcoded feature-ID probe. Returns error `0x0003` (not_found) on current firmware. Implementers MAY ignore this opcode in scanners targeting the current firmware base; dissectors SHOULD label it correctly.

### 29.5 `0x099F` GetPortConfig — Full Body and Walk Pattern

**Request body** (5 bytes):

```
09 9F 00 04 XX
```

Where `XX` is the port index byte.

**Walk pattern**: Desigo CC walks exactly six indices per audit cycle: `0xFF`, `0x00`, `0x01`, `0x02`, `0x03`, `0x04`. The walk is not a full 0–255 scan; it is a fixed small set. Clients SHOULD use the same six-index walk.

**Response fields** (parsed from semicolon-delimited config string):

| Field | Meaning |
|---|---|
| `;bd=<baud>` | Serial baud rate |
| `;pa=<parity>` | Serial parity (`N`/`O`/`E`) |
| `;mk=<mask>` | Serial framing mask |
| `;mid=<BLN-id>` | BLN node ID assignment for this port |
| `;ety=<encoding-type>` | Encoding type byte |
| `;pdl=<pad-length>` | Pad length |

**Index → label mapping**:

| Index | Label string |
|---|---|
| `0xFF` | "USB Modem" port |
| `0x00` | "HMI" port |
| `0x01`–`0x03` | Application-specific (varies by panel hardware) |
| `0x04` | "undefined" (returned label is literally undefined) |

### 29.6 `0x0241` PropertyEcho / DefaultPropertyResolve

**Two distinct response behaviors** depending on request body:

**Form A — Fully-qualified target** (request carries `(device-TLV, point-TLV)`, e.g. `TEC1 / ROOM TEMP`):

Response echoes both TLVs with `00 00` framing. Acts as a property-existence confirmation, semantically equivalent to a SYST-scoped `0x0273`.

**Form B — Object-only probe** (request carries `(name-TLV, EMPTY-TLV)`, e.g. `EXAMPLE.ZN` with empty second slot):

Response may fill the empty slot with a default property name (e.g. `MODE` for `EXAMPLE.ZN`) — acts as a "what's the canonical property of this object?" resolver. For some single-name targets the response keeps the empty 2nd slot.

Implementers SHOULD recognize both response forms and dispatch based on the body shape.

### 29.7 `0x0263` ObjectLifecycle (Probable Delete)

**Request body**:

```
02 63 01 00 04 "SYST" 23 3F FF FF FF 00 00
01 00 LL <object-name>
01 00 00 00 00 01 00 00 01 00 00
```

**Response** — fixed empty ACK regardless of object name (8 bytes):

```
00 00 01 00 00 01 00 00
```

Delete semantics are inferred from the operation's pairing with `0x0204` CreateObject and from the fixed empty-ACK response shape, which is consistent with a delete-style operation. The behavior could equally describe a property-clear or lifecycle-finalize operation. Implementations SHOULD NOT rely on `0x0263` having destructive semantics in production code without verifying against the target firmware first.

### 29.8 `0x0291` SYST Property Write (Probable)

**Request body — value-bearing form**:

```
02 91 01 00 04 "SYST" 23 3F FF FF FF 00 00
01 00 LL <device>
01 00 LL <point>
00 00 01 00 00 01 00 00 01 00 c8 <type-byte> <f32 BE>
```

**Request body — no-value form**:

```
02 91 ... [same prefix as above] ...
01 00 c8 00
```

**Response** echoes (device, point) with `00 00` framing — no value returned. Succeeds against SYST scope (no `0x0E15` error).

Write semantics are **inferred from the body shape** (the request carries value bytes consistent with a set/write); they have not been confirmed by a before/after read sequence. This opcode is also polymorphic with a trend-delete operation — see §6.6.

### 29.9 `0x02A8` SYST Property Write (Priority Variant)

Same body shape as §29.8 `0x0291`, with an additional fixed 6-byte trailer after the value (or after `01 00 c8 00` in the no-value form):

```
00 01 00 00 50 00
```

The `50 00` bytes are constant; the trailer may encode priority or a sub-property selector. Same write-semantics caveat as §29.8.

### 29.10 `0x4220` BulkProperty Variant

**Request body** (222 bytes total, preallocated):

```
42 20 01 00 04 "SYST" 23 3F FF FF FF 00 10 FF FF 00 00
01 00 LL <device>
01 00 LL <point>
<trailer + zero-pad to 222 bytes total>
```

The `00 10 FF FF` bytes after the sentinel sit at the same position where `0x4200` carries the trailing `FF FF` wildcard property-id. The `00 10` field may encode a property-id selector; this interpretation is not confirmed.

**Response** (~129 bytes) carries the same value+units+resolution+max+type-code shape as `0x4221` BulkPropertyRead. `0x4220` should be treated as a member-controller read variant. Implementers SHOULD prefer the canonical `0x4221` and treat `0x4220` as provisional.

### 29.11 `0x0979` ShortVariant — Response Format

**Response body**:

```
00 00
01 00 LL <object-name>
<u32 BE entry-count>
01 00 01 01
<4-byte field>
<BACnet date+time 8 bytes>
<priority byte>
<u32 BE slot index>
fc 13
```

The trailing `fc 13` is the state-set reference. The request body for `0x0979` carries a cross-opcode trailing reference `02 71` (the `0x0271` extended-read opcode), signaling that `0x0979` reuses the `0x0271` reading semantics for schedule-entry / point-metadata lookup.

### 29.12 `0x0976` DeviceAllSubpointsRead — Note on Variant Shapes

This opcode occurs in two distinct request shapes:

**Variant A — SYST-tagged form** (older convention, returns full per-device subpoint dump):

```
09 76 01 00 04 "SYST" 23 3F FF FF FF 00 00
01 00 LL <device>
```

**Variant B — cursor-pagination form** (Mode-C / newer convention, frequently goes unanswered by the panel):

```
09 76 00 00 01 00 01 2A 00 00 01 00 LL <device-name>
```

The cursor form is what Desigo emits in recent firmware against Mode-C streams; panels often do not respond to it. Implementers SHOULD use `0x0976` only when fallback enumeration opcodes (`0x0981`, `0x0986`) are not available, and SHOULD prefer Variant A when SYST-scope is acceptable.

---

## 30. Appendix F: Firmware Build Registry

### 30.1 Purpose

This appendix catalogs known firmware-build identifiers (`PME####` / `BME####`) observed in the field, along with their associated firmware version, hardware platform, and wire-protocol dialect. Implementers MAY use this table as a fast lookup to skip the dialect-detection roundtrip (§11.2) when a `0x010C` SystemInfo response has already been parsed and the build identifier is known.

The registry is **non-exhaustive**. Siemens does not publish a complete build catalog, and OEM-respun builds may carry identifiers not listed here. Clients SHOULD fall back to dynamic dialect detection (§11.2) for any build not present in this table.

### 30.2 Known Build Registry

| Build Tag | Branch | Firmware Version | Approx. Build Date | Dialect | Read Opcode Family | Notes |
|---|---|---|---|---|---|---|
| `PME1121` | P2 (2.x) | V2.8.5 | ~2012 | Legacy (`0x33` DATA) | `0x0271` ReadExtended | Older P2 build; predates the dialect break |
| `PME1252` | P2 (2.x) | V2.8.10 | Oct 2013 | Legacy (`0x33` DATA) | `0x0271` ReadExtended | CONNECT-response uses `0x0100` in `0x2E` body (§9.12); the highest known build before the dialect transition |
| `PME1300` | P2 (2.x) | V2.8.18 | Sep 2019 | Modern (`0x34` HEARTBEAT) | `0x0220` family (RegisterCOV / read-short) | Final P2 release; adds Adaptive Control (LSM-ADAPT); CONNECT-response uses `0x4640` IdentifyBlock |
| `BME1290` | BACnet (3.x) | V3.5.2 | ~2019 | N/A (BACnet/IP UDP/47808) | BACnet ReadProperty / ReadPropertyMultiple | BACnet firmware on identical PXC hardware; not addressable via this specification's wire opcodes |

Additional builds are known to exist in the `PME11xx`–`PME12xx` range and the `BME12xx`–`BME13xx` range; specific identifiers and version mappings are not documented here. Implementers encountering an unlisted build SHOULD log the full revstring (firmware build + hardware revision + build date) and treat the panel via dynamic detection.

### 30.3 Build-Number Ranges and the Dialect Boundary

The transition from the legacy `0x33` DATA dialect to the modern `0x34` HEARTBEAT dialect occurred between firmware versions V2.8.10 and V2.8.15. The exact build at which the dialect flipped is not publicly documented, but field observations are consistent with the following heuristic:

```
if build_tag starts with "PME":
    build_number = int(build_tag[3:])
    if build_number <= 1252:
        dialect = LEGACY      # session_msg_type = 0x33 DATA
    elif build_number >= 1300:
        dialect = MODERN      # session_msg_type = 0x34 HEARTBEAT
    else:
        dialect = UNKNOWN     # fall back to §11.2 detection
elif build_tag starts with "BME":
    dialect = NOT_APPLICABLE  # BACnet firmware; use BACnet/IP transport
```

The 1252–1300 gap should be treated as ambiguous, not as "interpolate the dialect." A `PME1275` (if such a build exists) could be on either side of the break. Implementers SHOULD NOT extrapolate.

### 30.4 Recommended Lookup Strategy

For a P2 client (scanner, bridge, supervisor implementation) that has already received a `0x010C` SystemInfo response from a panel, the recommended sequence is:

```python
# Pseudocode — adapt to the implementation's own session structures.
KNOWN_BUILDS = {
    "PME1121": {"dialect": "legacy",  "read_family": "0x0271"},
    "PME1252": {"dialect": "legacy",  "read_family": "0x0271"},
    "PME1300": {"dialect": "modern",  "read_family": "0x0220"},
}

def negotiate_dialect(panel_addr, build_tag=None):
    if build_tag and build_tag in KNOWN_BUILDS:
        # Fast path — skip the §11.2 dialect probe.
        entry = KNOWN_BUILDS[build_tag]
        return entry["dialect"], entry["read_family"]
    # Slow path — perform dynamic detection per §11.2.
    return detect_dialect_dynamic(panel_addr)
```

The fast path saves one TCP roundtrip (typically ~2 seconds of dialect-probe timeout against modern panels that silently drop the legacy probe). On a building with dozens of panels, this is a meaningful start-up cost reduction for bridges and scanners.

### 30.5 Limitations and Caveats

1. **Build numbers are not strictly monotonic across branches.** A `PME1252` (P2 branch) and a `BME1290` (BACnet branch) were both shipped within roughly the same calendar window; the numbers reflect independent build counters on the two branches. Build tag ordering is meaningful only within the same branch prefix.

2. **OEM and field-respun builds may exist.** Siemens occasionally produces customer-specific firmware respins, particularly for UL864 smoke-control applications. These may carry non-standard build tags and SHOULD trigger dynamic detection.

3. **The hardware revision string is the authoritative version source.** When `0x010C` returns both the firmware-build tag (`PME1300`) and the hardware revision string (`PXME V2.8.18 APOGEE`), the version string in the latter is more reliable for feature detection than inferring from the build tag. Use the build tag for fast dialect lookup; use the version string for feature gating (Adaptive Control, SNMP, etc.).

4. **Updates and corrections.** As additional builds are identified in the field, this registry SHOULD be updated. Implementers are encouraged to log unknown build tags with the full revstring context to support future spec revisions.

---

## End of Specification

This specification will be revised as additional protocol details are documented. Corrections and additions are welcome.
