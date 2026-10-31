# Device compatibility

m0nitor monitors any device that sends standard telemetry, and parses vendor-specific logs where a parser exists.
This page is generated from the device profiles in [`app/netmon/vendors.py`](../app/netmon/vendors.py);
`tests/test_vendors.py` fails if the table below and the code disagree.

## Status

| Status | Meaning |
|---|---|
| **VERIFIED** | Implemented and validated against a real device of this family in a running deployment. |
| **PARTIAL** | A vendor log parser is implemented and tested with **synthetic** fixtures written from the vendor's documented log format. Not yet validated on hardware: field positions can differ by firmware. Flows, SNMP and generic syslog work as for GENERIC. |
| **GENERIC** | No vendor parser. Flows (NetFlow/IPFIX/sFlow), SNMP counters and generic syslog storage only. |
| **UNSUPPORTED** | Not usable. |

Capability cells describe **the device**, from vendor documentation: `yes` = documented, `no` = not offered,
`unknown` = depends on model/firmware or not confirmed. "unknown" is never shown as working: Settings → Devices
shows what actually arrives.

**Monitor side:** syslog is accepted over UDP and TCP on 5514. TLS syslog (RFC 5425) is **not implemented on the
monitor yet**, even where the device supports it. Flows: NetFlow v5/v9 and IPFIX on UDP 2055, IPFIX also on 4739,
sFlow v5 on 6343. Only registered device addresses are let through the host firewall.

## Matrix

| Device | Status | NetFlow v5 | NetFlow v9 | IPFIX | sFlow | Syslog UDP/TCP/TLS | SNMP v2c/v3 | Parsed categories | Firewall decisions | Enforcement |
|---|---|---|---|---|---|---|---|---|---|---|
| OPNsense (`opnsense`) | VERIFIED | yes | yes | no | no | yes/yes/yes | yes/yes | traffic, ids, auth, config, vpn, interface, dns, system | yes | opnsense |
| pfSense (`pfsense`) | PARTIAL | yes | yes | yes | no | yes/no/no | yes/unknown | traffic, ids, auth, system | yes | pfsense |
| Fortinet FortiGate (`fortigate`) | PARTIAL | no | yes | yes | yes | yes/yes/yes | yes/yes | traffic, ids, auth, vpn, config, interface, ha, threat, system | yes | — |
| Palo Alto Networks PAN-OS (`panos`) | PARTIAL | no | yes | no | no | yes/yes/yes | yes/yes | traffic, ids, threat, auth, vpn, config, ha, routing, system | yes | — |
| Cisco ASA (`cisco_asa`) | PARTIAL | no | yes | no | no | yes/yes/yes | yes/yes | traffic, auth, vpn, config, interface, ha, system | yes | — |
| Cisco Firepower / FTD (`cisco_ftd`) | PARTIAL | no | yes | no | no | yes/yes/yes | yes/yes | traffic, auth, vpn, config, interface, ha, ids, system | yes | — |
| Cisco IOS / IOS-XE (`cisco_ios`) | PARTIAL | yes | yes | yes | no | yes/yes/no | yes/yes | traffic, auth, config, interface, routing, system | yes | — |
| Cisco Meraki MX (`meraki`) | PARTIAL | no | yes | no | no | yes/no/no | yes/yes | traffic, ids, vpn, system | yes | — |
| Juniper SRX / Junos (`junos`) | PARTIAL | yes | yes | yes | unknown | yes/yes/yes | yes/yes | traffic, ids, auth, config, interface, routing, system | yes | — |
| MikroTik RouterOS (`mikrotik`) | PARTIAL | yes | yes | yes | unknown | yes/unknown/no | yes/yes | traffic, auth, config, interface, vpn, system | yes | — |
| Ubiquiti UniFi gateways / UDM (`unifi`) | PARTIAL | unknown | unknown | unknown | unknown | yes/unknown/no | yes/unknown | traffic, system | yes | — |
| Ubiquiti EdgeRouter / EdgeOS (`edgeos`) | PARTIAL | yes | yes | yes | unknown | yes/no/no | yes/yes | traffic, auth, system | yes | — |
| VyOS (`vyos`) | PARTIAL | yes | yes | yes | yes | yes/yes/no | yes/yes | traffic, auth, system | yes | — |
| Linux nftables / iptables (`linux`) | PARTIAL | yes | yes | yes | yes | yes/yes/yes | yes/yes | traffic, auth, system | yes | — |
| OpenWrt (`openwrt`) | PARTIAL | yes | yes | yes | unknown | yes/yes/no | yes/yes | traffic, system | yes | — |
| DD-WRT (`ddwrt`) | PARTIAL | yes | no | no | no | yes/no/no | yes/no | traffic, system | yes | — |
| Sophos Firewall (SFOS) (`sophos`) | PARTIAL | unknown | unknown | unknown | unknown | yes/yes/yes | yes/yes | traffic, ids, auth, vpn, config, threat, system | yes | — |
| SonicWall (SonicOS) (`sonicwall`) | PARTIAL | yes | yes | yes | no | yes/yes/no | yes/yes | traffic, ids, auth, vpn, system | yes | — |
| WatchGuard Firebox (`watchguard`) | PARTIAL | unknown | unknown | unknown | unknown | yes/yes/yes | yes/yes | traffic, system | yes | — |
| Check Point (Gaia) (`checkpoint`) | PARTIAL | yes | yes | no | no | yes/yes/yes | yes/yes | traffic, ids, threat, vpn, auth, system | yes | — |
| Huawei (USG / AR / CE) (`huawei`) | PARTIAL | yes | yes | yes | unknown | yes/yes/unknown | yes/yes | traffic, auth, config, interface, system | yes | — |
| HPE Aruba (CX / AOS-S) (`aruba`) | GENERIC | no | unknown | unknown | yes | yes/unknown/unknown | yes/yes | interface, auth, system | no | — |
| TP-Link Omada (`omada`) | GENERIC | no | no | no | no | yes/no/no | yes/unknown | interface, auth, system | no | — |
| Generic router / switch / firewall (`generic`) | GENERIC | yes | yes | yes | yes | yes/yes/no | yes/yes | interface, auth, routing, system | no | — |

- **Firewall decisions** = the parser yields explicit allow/deny decisions. Only these feed firewall views,
  blocked-country counts and the blocked-traffic rules. A device whose logs carry no action (MikroTik and plain
  netfilter lines without an action prefix, generic devices) never produces block counts; a flow-only device never
  does either.
- **Enforcement** = an adapter exists for approval-gated blocking. Every other device is monitoring only, and
  m0nitor never uses NetFlow/syslog as a control channel.

## Test coverage

| Path | Tests (synthetic) |
|---|---|
| NetFlow v5, NetFlow v9, IPFIX, sFlow v5 decoding; templates, sequence gaps, clock drift, sampling changes, malformed packets | `tests/test_flowdiag.py` |
| Vendor parsers: FortiGate, PAN-OS, Cisco ASA/FTD/IOS, Junos, MikroTik, netfilter family, Meraki, SonicWall, Sophos, Check Point, WatchGuard, Huawei, Generic | `tests/test_vendors.py` |
| Device ownership with two vendors plus Generic at once, malformed input, rate limits, OPNsense path unchanged | `tests/test_vendors.py` |
| Onboarding validation, one sender per device, SNMPv3 secrets, RBAC, no blocking without an adapter | `tests/test_devices.py` |
| Rules over device events (VPN, interface, routing, HA, config, failed logins) | `tests/test_vendors.py` |

The flow decoders in `netmon.flowdiag` are diagnostics: Akvorado remains the collector. Akvorado's own NetFlow/IPFIX/sFlow
decoding is upstream code and is not re-tested here.

## Profiles

### OPNsense (`opnsense`) — VERIFIED

NetFlow via Reporting -> NetFlow (v5/v9). filterlog, Suricata EVE, Unbound, audit and gateway events via remote syslog (RFC 5424, TCP). Tested on 26.x.

### pfSense (`pfsense`) — PARTIAL

NetFlow/IPFIX via the softflowd package (WAN only). Remote syslog is UDP. filterlog uses the OPNsense field order. SNMPv3 needs the net-snmp package.

### Fortinet FortiGate (`fortigate`) — PARTIAL

Syslog format 'default' (key=value). 'mode reliable' = TCP (RFC 6587); 'enc-algorithm' enables TLS. NetFlow v9 is configured per interface (netflow-sampler); FortiOS 7.2+ moved collectors under 'config collectors'. sFlow via 'config system sflow'.

### Palo Alto Networks PAN-OS (`panos`) — PARTIAL

CSV syslog (BSD or IETF). Field positions follow the PAN-OS 10.x/11.x log field documentation; custom log formats are not parsed. NetFlow v9 only (no IPFIX, no sFlow).

### Cisco ASA (`cisco_asa`) — PARTIAL

Syslog message IDs (%ASA-n-NNNNNN). NetFlow is NSEL (event-based flow export, not periodic flow records): byte counts and timing differ from router NetFlow. With TCP syslog set 'logging permit-hostdown' so a down collector never blocks traffic.

### Cisco Firepower / FTD (`cisco_ftd`) — PARTIAL

LINA syslog (%FTD-n-NNNNNN, same IDs as ASA) and intrusion events 430001. Configured from FMC/FDM Platform Settings -> Syslog. NSEL as for ASA.

### Cisco IOS / IOS-XE (`cisco_ios`) — PARTIAL

ACL log lines (%SEC-6-IPACCESSLOGP) are rate-limited summaries: they count logged denies, not every packet. Flexible NetFlow v9; IPFIX on IOS-XE. TCP syslog on IOS-XE only.

### Cisco Meraki MX (`meraki`) — PARTIAL

Syslog is UDP only with Meraki's own header. 'flows'/'firewall' lines carry pattern: allow/deny; they are only generated for rules with logging enabled.

### Juniper SRX / Junos (`junos`) — PARTIAL

Structured syslog (sd-syslog) RT_FLOW session logs and RT_IDP. sFlow is available on EX/QFX switches, not generally on SRX. Inline J-Flow v9/IPFIX depends on platform.

### MikroTik RouterOS (`mikrotik`) — PARTIAL

RouterOS firewall log lines do not contain the rule action: an action is only taken from a log-prefix that names it (DROP/REJECT/ACCEPT); otherwise it is unknown and never counted as a block. Traffic Flow exports NetFlow v5/v9/IPFIX.

### Ubiquiti UniFi gateways / UDM (`unifi`) — PARTIAL

Firewall logs are netfilter kernel lines; the action comes from UniFi's rule prefix suffix (-A accept, -D drop, -R reject). NetFlow/IPFIX availability depends on the UniFi Network version and gateway model: check what arrives on the Devices page before relying on it.

### Ubiquiti EdgeRouter / EdgeOS (`edgeos`) — PARTIAL

netfilter log lines with [RULESET-RULE-A/D/R] prefixes.

### VyOS (`vyos`) — PARTIAL

nftables log prefixes [ipv4-NAM-filter-default-D]. Syslog syntax changed in 1.5 (system syslog remote).

### Linux nftables / iptables (`linux`) — PARTIAL

Kernel netfilter log lines (IN= OUT= SRC= DST= ...). The action is taken from the log prefix only (e.g. 'm0nitor DROP: '); without one it is unknown. Flows via softflowd/pmacct, sFlow via hsflowd.

### OpenWrt (`openwrt`) — PARTIAL

fw4 log prefixes ('drop wan in: ', 'reject wan in: '). Flows need the softflowd package; SNMP needs snmpd.

### DD-WRT (`ddwrt`) — PARTIAL

Remote syslog is UDP. Firewall logging (Security -> Log) writes 'DROP IN=...'/'ACCEPT IN=...' lines. RFlow exports NetFlow v5.

### Sophos Firewall (SFOS) (`sophos`) — PARTIAL

Device standard (key=value) syslog format, both the pre-19.5 and the 19.5+ field names. Flow export depends on the SFOS version: check the Devices page.

### SonicWall (SonicOS) (`sonicwall`) — PARTIAL

Default/Enhanced syslog (id=firewall ... m=NNN ...). The action is taken from fw_action when present, else from the message text. AppFlow exports NetFlow v5/v9 and IPFIX.

### WatchGuard Firebox (`watchguard`) — PARTIAL

Traffic log lines with msg_id 3000-0148 (deny) / 3000-0151 (allow) and positional fields. Flow export is not documented for Fireware: shown as unknown.

### Check Point (Gaia) (`checkpoint`) — PARTIAL

Log Exporter in syslog format (key:"value"; pairs). NetFlow v5/v9 from Gaia.

### Huawei (USG / AR / CE) (`huawei`) — PARTIAL

USG POLICYPERMIT/POLICYDENY session logs and common SHELL/IFNET events. NetStream exports NetFlow v5/v9/IPFIX; sFlow on CE/S switches.

### HPE Aruba (CX / AOS-S) (`aruba`) — GENERIC

Switches: sFlow v5 for traffic, SNMP for counters, generic syslog stored as system events. No firewall decisions.

### TP-Link Omada (`omada`) — GENERIC

Remote syslog from the controller/gateway is stored as generic system events. No documented flow export.

### Generic router / switch / firewall (`generic`) — GENERIC

Any device that sends NetFlow v5/v9, IPFIX or sFlow, standard syslog and SNMP. Syslog is stored and categorized by keyword only; no allow/deny decisions are derived from generic logs.

## Setup examples

Each profile carries a device-side setup example with your monitor address filled in (Settings → Devices → a device →
*Device-side setup*). They are starting points: menu paths and CLI syntax vary by firmware version, so check your
vendor's documentation. Corrections from real deployments are welcome — see [CONTRIBUTING](../CONTRIBUTING.md); please
attach a sanitized sample log line so the parser test can be extended.
