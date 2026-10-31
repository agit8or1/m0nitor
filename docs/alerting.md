# Findings and alerting

## Findings

The detector runs every 5 minutes (configurable). Each finding records its evidence, the exact query, the baseline
it was compared to, other possible explanations and next steps, and — where the telemetry allows — a verified
direction. Novelty rules stay silent until the learning period (`min_learning_days`) has passed. Findings from device
events name the device and include the original log lines.

| Rule | Raises a finding when |
|---|---|
| New country / New network (ASN) | a server talks to a country or network it has not used during the baseline |
| Unexpected inbound service | inbound connections reach a port that is not a declared exposure |
| Outbound volume above baseline | outbound bytes exceed the same-hour baseline by a factor |
| Scanning / fan-out | one address contacts many destinations or ports in a short window (traceroute ports ignored) |
| Periodic connections | connections repeat at very regular intervals (beacon-like) |
| IDS signature | Suricata alerts (grouped per signature, source and target) |
| Blocked inbound scanning / Outbound blocked | logged firewall blocks form a scan pattern, or outbound traffic is repeatedly blocked |
| DNS anomaly / external resolvers | NXDOMAIN or random-label bursts, hosts bypassing the local resolver |
| VPN tunnel down / Interface down / Routing neighbor down / HA failover | a device reports the state change in its own log |
| Configuration change | a device reports a configuration change (who and what, from its log) |
| Repeated failed logins to a device | ≥ N failed logins to a firewall/router/switch from one source in a window |
| Telemetry stopped / Firewall log feed stopped / Device log feed stopped / Source health / Disk space / Detector error | monitoring itself needs attention |

Thresholds and on/off switches: Settings → Alert rules (seeded from `rules:` in config.yaml).

## Working with findings

- **Security** page: open / acked / closed tabs, *Ack* per finding, *Ack all* and *Unack all*.
- **This is normal** on a finding suppresses the rule, the exact finding or the device and closes matching findings.
  **Expected devices** (Security → Suppressions) excludes known-legitimate hosts, including their share of traffic
  behind a shared NAT address.
- **Maintenance windows** (Settings → Maintenance) mute notifications during planned work.
- **AI analysis** (optional, manual, preview-first): you see exactly what would be sent; internal addresses are
  pseudonymized; daily caps apply; AI output never changes the firewall.

## Notifications

Settings → Notifications. Supported channels: email (SMTP), SMS (Twilio or a carrier email gateway), generic webhook
(JSON, HMAC-signed), Slack, Microsoft Teams (Workflows webhook), Discord, ntfy and Pushover. A channel stays off until
a test message to it succeeded. Credentials are stored as secrets and never shown again.

## Blocking and auto-response (optional, off by default)

- **Block requests**: approval-gated blocks through one firewall alias created for m0nitor — see [BLOCKING.md](BLOCKING.md).
- **Auto-response** (Settings → Auto-response): brute force, high-severity IDS signatures and floods — never scans —
  can add addresses to m0nitor's own alias with an expiry. It ships in **dry run**; every candidate decision is logged
  with the guardrail that stopped it. Guardrails include protected addresses, established-client checks and rate
  limits. m0nitor only changes firewall objects it created and recorded.
