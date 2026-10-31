# Firewall resource requirements

What sending flows, logs and SNMP to m0nitor costs a firewall, how the monitor finds the firewall's hardware and
load, and where it has to say *unknown*.

Every device page has a **Hardware & capacity** card (Devices → *device* → Hardware & capacity). It shows
discovered and manual hardware values, measured CPU and memory, the device's measured export rates, export
bandwidth, a calculator for feature changes and three monitoring profiles. Labels are the ones used in the
[capacity planner](capacity-planning.md#labels).

## Discovery (Auto-populate firewall resources)

**Auto-populate firewall resources** reads standard MIBs over the device's configured SNMP credentials. It also runs in the
background every 6 hours. It never walks large tables (at most 256 rows per table) and never writes to the device.
Each step reports *answered*, *not supported*, *timeout*, *authentication failure* or *permission denied*, so a
partial result explains itself.

| Step | MIB | Fields |
|---|---|---|
| System | SNMPv2-MIB | description, object ID (→ manufacturer from the enterprise number), uptime |
| CPU | HOST-RESOURCES-MIB `hrProcessorTable`, `hrDeviceDescr` | processor count, CPU model, per-processor load |
| Memory, storage | HOST-RESOURCES-MIB `hrMemorySize`, `hrStorageTable` | installed RAM, fixed-disk size and use |
| CPU and memory use | UCD-SNMP-MIB (net-snmp) | CPU idle → CPU %, total and available memory |
| Interfaces | IF-MIB | interface count, fastest interface speed (up interfaces) |
| Model | ENTITY-MIB | hardware model, where the agent provides it |
| Vendor | FORTINET-FORTIGATE-MIB, PAN-COMMON-MIB | CPU %, memory, sessions — **OIDs from vendor documentation, not verified on hardware** |

Tested: **OPNsense** (net-snmp agent): HOST-RESOURCES, UCD-SNMP and IF-MIB answer; ENTITY-MIB and a pf MIB are not
provided, so model stays UNKNOWN unless entered. pfSense's default `bsnmpd` provides a different subset. Other
vendors' agents vary: whatever is not answered is listed with the reason and can be entered manually.

**SNMPv3 (authPriv) is recommended.** With v2c the page warns that the community string crosses the network in clear
text.

Not used: vendor HTTP APIs. OPNsense's diagnostics endpoints exist but need API privileges beyond those the blocking
key holds (they answer 403 to it); granting a monitoring key more rights for hardware data is not worth the risk, so
no API adapter is implemented.

## Manual values

An administrator can enter: manufacturer, model, CPU model, CPU cores, installed RAM, typical CPU and memory use,
number of interfaces, fastest interface speed, approximate and peak throughput, IDS/IPS mode, logging level, flow
export type and flow active timeout.

**A manual value is never overwritten by discovery.** The discovered value is kept and shown beside it. Clearing
the field falls back to the discovered value. Every save is written to the audit log.

| Field | Auto-populated | Manual only |
|---|---|---|
| manufacturer, CPU model, cores, RAM, interfaces, interface speed, storage, uptime | ✓ (where the MIB answers) | |
| CPU %, memory % | ✓ (UCD-SNMP or vendor MIB, sampled every minute) | |
| model | ✓ only with ENTITY-MIB | usually |
| throughput, peak throughput | measured separately (IF-MIB counters, flows) | ✓ as a planning value |
| IDS/IPS mode, logging level, flow export type, active timeout | | ✓ |

## What is measured per firewall

* **Flow records/s exported**: stored flows from this exporter, per minute. MEASURED.
* **Log events/s**: stored rows from this device, per minute. MEASURED. Lines that are recognized but not stored
  (session starts, for example) also cross the wire and are not counted.
* **CPU and memory**: SNMP samples every minute (UCD-SNMP on the 1-minute poll, otherwise a 5-minute sample),
  P95 and peak, trend after 2 days. Host CPU from SNMP does not always reflect data-plane load on appliances with
  offload hardware.
* **Export bandwidth**: flow export bytes per record are MEASURED from Akvorado's inlet counters where available.
  Otherwise ESTIMATED from the format: NetFlow v5 48.8 B/record, v9 and IPFIX 40–70 B depending on the template.
  sFlow is UNKNOWN without packet and sampling rates. Syslog bandwidth uses the measured line length from the log
  files.

## Calculator: what a change costs

For a change such as *flow export on one more interface*, *shorter active timeout*, *pass-rule logging* or *IDS alert
export*, the calculator gives the extra records/s and bandwidth from this firewall's measured rates.

**CPU impact is given only when it was measured**, that is when the firewall's CPU samples show a significant
relation to its export rate (same validity rules as the server model). Otherwise it reads *insufficient
information*. Memory impact is always *insufficient information*: flow-cache and log-buffer memory are not
exposed over SNMP. Flow export is generally light compared with packet filtering, IDS/IPS inspection and VPN
encryption on the same box, but that is general guidance, not a measurement of your firewall.

## Monitoring profiles

| Profile | What is exported |
|---|---|
| **Lightweight** | WAN flows only, block logs only, SNMP every 60 s, no DNS/IDS export |
| **Balanced** | flows on WAN (plus LAN capture where NAT attribution needs it), block and system logs, IDS alerts, SNMP health |
| **Detailed** | flows on all interfaces, pass-rule logging, DNS and VPN events, optional Zeek sensor |

Each profile shows its expected records/s, events/s and export bandwidth, ESTIMATED from this firewall's
measurements. The profiles are advice: m0nitor never changes the firewall configuration to apply them. The cost of
IDS/IPS *inspection* is already part of the firewall's current load in every profile; only exporting its alerts is
counted.

## General guidance

* Export flows from the interface(s) that see the traffic you need; the WAN alone loses LAN hosts behind NAT
  ([NAT attribution](nat-attribution.md)).
* An active timeout of 60–120 s keeps long connections visible without much extra volume; 1,800 s exports long
  sessions only at their end.
* Log block rules; log pass rules only where you need them (they can multiply log volume).
* SNMP polling every 60 s with a few GETs is negligible for the firewall; avoid frequent full walks of large tables.
