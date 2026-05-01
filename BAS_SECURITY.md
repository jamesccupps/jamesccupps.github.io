# Securing HVAC and Building Automation Networks

Most building automation protocols — BACnet/IP, Modbus/TCP, APOGEE P2, KNX/IP, LonWorks, and similar — were designed in an era that assumed networks themselves were trusted. They generally have no built-in authentication, no encryption, and no message integrity. Defending a BAS deployment is therefore a network and operational discipline problem, not a protocol problem. The recommendations below cover the realistic priorities for any BAS environment.

---

## 1. Segregate the BAS network

The single most important control. Building automation traffic should be isolated on its own VLAN with deny-by-default routing to other segments — corporate, tenant, guest, IoT, cameras, badge access, parking. If only the supervisor server and BAS controllers can reach each other, most attack vectors are closed off at the network layer. Walk the building's ethernet drops physically at least once: public-area jacks, conference rooms, and unused offices should not be on the BAS VLAN. Older buildings accumulate stale patch-panel decisions and this catches them.

## 2. Don't expose the BAS to the internet

Shodan regularly indexes thousands of building-automation devices reachable on public IPs — BACnet routers, Niagara stations, Desigo CC servers, vendor web interfaces, even individual controllers. None of these belong on the open internet. Verify with an external scan of your public IP space; if any BAS device responds, get it behind a VPN or firewall immediately. Vendor remote-access tools should be on-demand, not always-on.

## 3. Harden the supervisor server

The BAS supervisor (Desigo CC, Niagara station, Metasys ADX, EBI server, whatever your platform uses) is the highest-value target on the network — compromising it is equivalent to compromising every controller it manages. Treat it like a domain controller:

- EDR / endpoint security software installed and active
- No general-purpose use (no browsing, email, personal accounts)
- Locked-down RDP (specific source IPs only, or eliminate RDP entirely)
- Patched on a normal cadence
- Strong, audited admin credentials separate from general IT accounts

## 4. Change default credentials

BAS equipment ships with vendor default passwords that are widely documented. Niagara stations, BACnet devices with web UIs, controller commissioning tools, vendor remote-support accounts — all of them have known defaults that get used in commissioning and never changed. Audit every device with an authentication interface and rotate credentials. Document the new ones in your password manager, not on a spreadsheet next to the equipment.

## 5. Discipline contractor and vendor access

The most common real-world BAS compromise is a contractor's laptop carrying malware onto the network — the 2013 Target retail breach famously started this way. Mitigations:

- Maintain a written list of who's authorized to plug into the BAS network; review quarterly
- Revoke access promptly when contractor relationships end
- Where possible, provide a hardened guest workstation for vendor visits rather than allowing contractor-owned laptops on the BAS network
- Log and retain switch-port and VPN activity so you know who connected when

## 6. Run continuous packet capture on the BAS segment

A SPAN port mirroring BAS traffic to a small capture host with 30+ days of retention is cheap insurance. Most BAS protocols are plaintext, so captures provide complete forensic visibility if anything ever goes wrong. The same infrastructure enables the next item.

## 7. Alert on write operations from unexpected sources

Once you have packet capture, set up IDS rules (Suricata, Zeek, or similar) to alert when control-modifying operations come from any source IP that isn't the registered supervisor. The specifics vary by protocol — BACnet `WriteProperty` and `AtomicWriteFile` services, Modbus write-coil and write-register function codes (0x05, 0x06, 0x0F, 0x10), APOGEE program-edit and property-write opcodes — but the principle is universal: state-changing operations are rare and operator-driven, so a non-supervisor source IP doing them is anomalous and worth investigating. False-positive rates are low because these operations are infrequent in normal use.

## 8. Version-control and back up configurations

Periodically export controller programs, schedules, and graphics; commit to a version-controlled repository; diff against the prior baseline. Unexpected changes get investigated. The diff is your audit trail because BAS protocols generally don't provide one. This also doubles as disaster recovery — if a controller dies or gets replaced, you have its configuration. Vendor backup tools (Niagara station backups, Desigo project archives, Metasys archive databases) should also run on a schedule with offsite copies.

## 9. Audit inter-VLAN firewall rules annually

Firewall configurations drift over years. Convenience exceptions become permanent. A yearly review of every rule that touches the BAS VLAN catches the slow accumulation of permissive holes that creates real-world compromise paths. Pay specific attention to rules added during construction or major renovations — those often outlive their original purpose.

## 10. Document and rehearse recovery procedures

Power-cycle procedures for stuck controllers, restoration steps for supervisor configuration, replacement-controller commissioning, BBMD reconfiguration for BACnet sites, vendor-support contact escalation paths. None of this is novel, but it should be written down and practiced before you need it under incident-response pressure. Equipment-room access and physical-security procedures belong in the same document — controlling who can touch the hardware is part of controlling the system.

---

## What this protects against

The realistic threat model for a BAS deployment is some combination of:

- Contractor or vendor laptop carrying malware onto the network
- Compromised supervisor host (typically through phishing or credential reuse)
- Network configuration drift creating unexpected reachability
- Compromised IoT or third-party-managed equipment sharing infrastructure
- Internet-exposed devices found by automated scanning

The recommendations above address all of these. The protocol-level concerns (no encryption, no authentication) cannot be fixed at the protocol layer — they're compensated for at the network and operational layers, which is the standard approach for BAS, SCADA, and other industrial-control environments.

## What this doesn't cover

Migration to newer protocols (BACnet/SC, OPC UA with security profiles), formal compliance certification (NERC CIP, IEC 62443, NIST SP 800-82), and detailed incident-response planning are beyond the scope of these recommendations but worth considering for sites with regulatory exposure or higher-criticality requirements. None of those are substitutes for the basics above.
