# Architecture

    firewall(s) ──NetFlow v9 UDP 2055──▶ Akvorado inlet ─▶ Kafka ─▶ outlet ─▶ ClickHouse (default.flows*)
               ──syslog TCP/UDP 5514──▶ rsyslog ─▶ /var/log/netmon/*.log ─▶ netmon log ingest ─▶ ClickHouse (netmon.*)
               ◀──SNMP (read-only)──── netmon counters
               ◀──HTTPS API (read; one alias write)── netmon (policy reads, blocking, auto-response)
    browser ──HTTPS 443──▶ Caddy ─▶ netmon app (127.0.0.1:8090) ─┬─▶ ClickHouse HTTP (readonly=1)
                                   └─▶ Akvorado console (forward_auth via the app)   └─▶ SQLite /data/netmon.db

## Components
| Component | Role | Notes |
|---|---|---|
| Akvorado (upstream, AGPL-3.0) | NetFlow collection, enrichment (GeoIP, interface metadata), ClickHouse storage, flow explorer | not vendored; `akvorado/` is an overlay |
| netmon app (`app/netmon`) | UI, detector, health engine, log ingest, NAT attribution, optional blocking/auto-response/AI/notifications | one container, non-root, read-only rootfs |
| rsyslog (host) | receives firewall syslog on 5514, writes daily files the app tails | config rendered by `host/netmon-apply-sites` |
| Caddy | TLS, security headers, routes; Akvorado console behind the app's session check | |
| `host/netmon-apply-sites` (root, systemd path unit) | validates the app's site list and renders ufw/DOCKER-USER ACLs, rsyslog senders and Akvorado exporter metadata | the only root-side writer |

## Threads in the app
detector (5 min), health engine (60 s), log ingest (tail), SNMP counters (10 s), optional Zeek ingest, notification
worker, auto-response (when enabled), inventory sync (hourly virtual-IP / 1:1 NAT read).

## Trust boundaries
- Everything in telemetry (hostnames, AS names, DNS names, log text) is untrusted and escaped on output; it is also
  marked as untrusted data in AI prompts.
- The app cannot write ClickHouse flow data and has read-only ClickHouse credentials; netmon's own tables are filled
  through a separate insert path for logs.
- Root-side changes go only through `netmon-apply-sites`, which re-validates every value with strict patterns.

## Observation semantics (OPNsense, routed export)
- WAN → LAN record: inbound across the WAN, destination is the real internal host (after de-NAT).
- * → WAN record: outbound across the WAN, source is post-NAT (public address).
- Empty input interface: usually firewall-originated, but not proof of it.
Validate these for your own firewall before trusting per-host numbers: see nat-attribution.md.
