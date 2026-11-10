# Field validation: real-device status and procedure

This page lists which vendor paths have been checked against real hardware and which are covered by synthetic
fixtures only. It also gives the procedure for checking a new device. A claim stays **unverified** until someone runs
the procedure on a real device and publishes the result here. A fixture shows that the parser follows the vendor's
documented format. It does not show that a given firmware actually sends that format.

## Status (2026-11-10)

| Vendor path | Real device | What has real-device evidence | Fixture-only |
|---|---|---|---|
| OPNsense: NetFlow v9 (routed, WAN + LAN bridge), filterlog/Suricata/Unbound syslog, REST blocking | **yes** (reference deployment, OPNsense 26.x) | WAN flows, LAN return flows, firewall logs, shared-NAT attribution (manual two-host upload check before v1.59: both hosts "high", sum = WAN egress; the in-app guided validation has not been run on it yet), blocking alias | NetFlow v5 |
| pfSense: softflowd (capture, WAN only), filterlog over UDP syslog, REST package blocking | **no** | — | filterlog parsing (OPNsense field order), capture-mode boundary logic, `wan_only` NAT tier, blocking adapter (fake firewall) |
| FortiGate: NetFlow v9 / IPFIX per interface, key=value syslog over TCP | **no** | — | traffic/IPS/VPN/login/config log parsing, routed boundary logic with `netflow-sampler` on WAN + LAN, NAT attribution on LAN-sampled records |
| PAN-OS, Cisco ASA / FTD / IOS, Meraki, Junos, MikroTik, UniFi, EdgeOS, VyOS, Linux netfilter, OpenWrt, DD-WRT, Sophos, SonicWall, WatchGuard, Check Point, Huawei | **no** | — | every parser and boundary path (see [vendors](vendors.md)) |
| Aruba, Omada, generic | **no** | — | generic flows/syslog storage only |

Field hardware for pfSense and FortiGate was not available for this release. Those rows are unverified: the
profiles stay **PARTIAL**, and nothing in the app or these docs claims real-device results for them. Collector
throughput for every vendor comes from the [end-to-end benchmark](performance-benchmarks.md#pipeline-runs) with
synthetic NetFlow v9 records, not from a device.

## Priority order

1. **pfSense** (softflowd, capture mode): confirm the WAN-only boundary, that the LAN side is really absent (so shared-NAT
   uploads are `wan_only`, never attributed), the UDP syslog filterlog field order, and the blocking adapter against the
   REST package. If a second softflowd instance on the LAN interface gives usable LAN records, record how its records
   identify the interface (ifindex or none). Only then can the profile change.
2. **FortiGate** (FortiOS 7.x): confirm interface names and ifindexes in the NetFlow records, that `netflow-sampler both`
   on WAN and LAN gives one WAN egress record per connection (no double-counted volume), the reply record towards the
   LAN host, and the key=value log fields for traffic, UTM/IPS, VPN and admin login.

## Procedure (any device, about two hours)

Use a lab or maintenance window. Do **not** change blocking, NAT or rule settings on a production firewall for this
procedure. The only firewall-side changes are export destinations (flows and syslog) to the monitor, plus, for step 4,
a temporary second flow destination.

1. **Record the device**: vendor, model, firmware version, the exact export settings (screenshots or `show` output with
   secrets removed), sampling rate, active/inactive timeouts.
2. **Configure exports** as shown in Settings → Firewalls & sites (the steps include your addresses). Set the
   firewall's vendor, exporter address, WAN and LAN interface names, syslog source and shared outbound NAT addresses.
3. **Onboarding test** (Settings → Onboarding test, pick the firewall), after 10 minutes of normal traffic:
   - WAN flows, LAN return flows, firewall logs and usable NAT evidence each show *arriving, fresh* or a specific reason;
   - "interfaces seen" matches the configured WAN/LAN names (a mismatch is named on the page);
   - record the four states and the quality rows.
4. **Export check** (loss, duplicates, clock): add `MONITOR:2056/udp` as a *second* flow destination for 5 minutes and run
   `docker exec app-netmon-app-1 python -m netmon.flowdiag --listen 0.0.0.0:2056 --seconds 300 --record`. Record
   protocol and version, templates, sampling, sequence gaps, duplicates and clock drift. Then remove the destination.
5. **Guided NAT validation** (same page): two hosts you operate behind the shared NAT, one destination you are authorised
   to upload to. Run the four steps shown on the page and evaluate. Expected: A and B at high/medium; the simultaneous
   step ambiguous; the unanswered attempt unanswered or no LAN return path; no other host named. On a WAN-only exporter
   the expected (correct) result is `wan_only` and "fail: per-host attribution not possible".
6. **Logs**: produce one blocked and one passed connection on a logged rule and check them in Firewall logs (action,
   direction, rule, addresses, ports). Save 20 raw log lines, **replace every address with documentation addresses**
   (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 10.x), and add them as fixtures in `app/tests/test_vendors.py`.
7. **Volume check**: download a file of known size from one host and compare the WAN volume on the host page with
   the transferred bytes (±5 % plus headers).
8. **Publish**: open a pull request that adds a row to the table above. Include the device, firmware, date, the
   onboarding states, the export check, the validation verdict and the volume check, plus the sanitised fixtures. A
   profile changes from PARTIAL to VERIFIED only when steps 3 to 7 pass on that device.

## Result template

```text
Device:            <vendor> <model>, firmware <version>, date <YYYY-MM-DD>
Exports:           flows <protocol/version, interfaces, sampling, timeouts>; syslog <transport, format>
Onboarding test:   WAN flows <state> · LAN return <state> · firewall logs <state> · NAT evidence <state>
Export check:      <packets> packets, lost <n>, duplicates <n>, clock drift <s>, templates <ids>
NAT validation:    <verdict>; A <tier/bytes>; B <tier/bytes>; simultaneous <ambiguous bytes>; unanswered <n>
Logs:              block <ok/fields wrong: ...>; pass <ok/...>
Volume check:      sent <bytes>, shown <bytes> (<diff %>)
Not verified:      <anything skipped and why>
```
