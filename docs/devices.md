# Devices: multi-vendor onboarding

m0nitor started with OPNsense. It now takes telemetry from any firewall, router or switch that exports standard
protocols, and parses vendor logs where a parser exists. What each family offers: [vendors.md](vendors.md).

## Two kinds of device

| | Site firewall | Additional device |
|---|---|---|
| Where | Settings → Firewalls & sites | Settings → Devices |
| Role | Defines the site: its WAN interface is the accounting boundary for bandwidth, connections, countries and the flow-based detectors | Router, switch, secondary firewall, sensor attached to a site |
| Flows | Counted in the site's WAN totals | Kept under their own exporter name; **never added to the site's WAN totals**, so traffic that passes two devices is not counted twice |
| Logs | Owned by the site firewall | Owned by the device (`device` column on every event) |
| Profiles | Any (OPNsense, pfSense, FortiGate, PAN-OS, …) | Any |
| Blocking | OPNsense and pfSense only | None (monitoring only) |

One sender address belongs to exactly one device: the form refuses a flow or syslog address that is already used,
so events can never be attributed to the wrong device, even when devices share a site, a NAT address or a network.

## Adding a device

1. **Settings → Devices → Add a device.** Choose the profile (or *Generic*), the site, and the addresses the monitor
   will see as the source of flows and/or syslog. Either is enough; read-only monitoring needs no credentials.
2. Select the flow protocols the device is set to send. The form refuses a protocol the profile documents as not
   offered (for example NetFlow v5 on PAN-OS).
3. Optional: WAN interface or WAN zone names, so logged traffic gets an inbound/outbound direction. Without them the
   direction is unknown, not guessed.
4. Optional: SNMP for interface counters. **SNMPv3 authPriv** (SHA-family authentication, AES privacy) is the default;
   v2c is accepted with a clear-text warning. Credentials go to the secrets directory (mode 600) and are never shown
   again, logged or exported.
5. Save. The host helper lets the new addresses through the host firewall (UDP 2055/4739/6343 for flows, 5514 for
   syslog) within seconds, and registers flow exporters with Akvorado.
6. Configure the device: the device page shows a setup example with this monitor's address filled in.

## What the device page shows

Everything on the device page is read live; reload it to test again.

- **Supported / Configured / Receiving** per protocol. *Receiving* means data from that device arrived in the last
  15 minutes; *no data* is shown in red; *unknown* means the monitor cannot tell (for example ClickHouse unreachable).
  Missing telemetry is never shown as zero.
- **Flows:** the exporter address actually seen, the last flow, flows per hour, sampling rates seen (volumes are
  multiplied by the sampling rate), and field coverage — the share of flows that carry input/output interface,
  direction, IPv6 and AS numbers. From Akvorado's own counters: packets per listener, the protocol version decoded,
  templates per observation domain, decoder errors.
- **Syslog:** lines received, parsed, unrecognized (kept as system events) and recognized-but-not-stored (for
  example a session-start line whose session-end line carries the same connection), the actual source address, a
  sample normalized event and a sample unrecognized line.
- **Warnings** for UDP syslog (unauthenticated, can be lost or spoofed), SNMPv2c (clear-text community) and
  unauthenticated flow export.
- **Test SNMP now** runs one read (`sysDescr`, `sysUpTime`).

## Flow diagnostics

Before pointing a new exporter at the collector, or when its numbers look wrong:

```sh
# temporarily publish 2056/udp on the app container, or run it on a host the exporter can reach
docker exec app-netmon-app-1 python -m netmon.flowdiag --listen 0.0.0.0:2056 --seconds 60
```

It decodes NetFlow v5/v9, IPFIX and sFlow v5 headers and reports per exporter and observation domain: templates,
data that arrives before its template, expired templates, sequence gaps (export packets or records lost in transit),
sequence restarts, sampling-rate changes, exporter clock drift and sFlow agent drops. Nothing is stored.

## Accuracy rules

- **Blocked counts come only from firewall decisions in logs**: deny/drop/reject lines a parser recognized as such.
  Dropped flows are never estimated, and a flow-only device has no blocked counts.
- **An action the log does not state is unknown.** RouterOS and plain netfilter lines carry no action unless the
  log prefix names one (`DROP`, `-D]`, …); they are kept as events with action *unknown*.
- **Session start/end pairs count once** (PAN-OS `start`/`end`, ASA Built/Teardown, SRX CREATE/CLOSE,
  SonicWall Opened/Closed).
- **Timestamps:** the receipt time is used unless the log carries a zoned timestamp, or the device is marked as
  running on UTC. A device clock more than 7 days off is ignored in favour of receipt time.
- **Sampling** is reported per exporter; sampled volumes are scaled by the collector, and the device page shows
  the rates seen.

## Security notes

- Senders are allowlisted per address: the host firewall drops flows and syslog from anything not registered.
- Each non-OPNsense sender is capped at 5,000 syslog lines per received second (`syslog_max_lines_per_second`);
  drops are counted on the Devices page and in ingest state, never silent.
- Lines longer than 16 KiB are truncated; a parser error never stops ingestion (the line is kept unparsed).
- UDP syslog, SNMPv2c and NetFlow/IPFIX/sFlow are unauthenticated protocols: keep them on a management network or
  a VPN. TLS syslog (RFC 5425) is not implemented on the monitor yet.
