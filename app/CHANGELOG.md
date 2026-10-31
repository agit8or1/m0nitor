# Changelog

Versions are `vMAJOR.MINOR` with two-digit minors (v1.05, v1.06, ... v1.10). Every change ships as a new version
with its own section here; the running version is in the page footer and on Changelog in the app.

## v1.06 — 2026-10-31

### Added
- Reverse DNS under every remote address in connection tables (Connections page, Overview recent connections,
  server and country pages): "(name)", or "(no rDNS)" when the address has no PTR record.

## v1.05 — 2026-10-31

### Added
- Map tooltips list the top five source → destination address pairs per arc, region, endpoint and the site's own
  country, per direction. The firewall side is shown as the public address it is reached on — "WAN" (the outbound
  NAT address) or "WAN alias <description>" (an interface virtual IP) — followed by the internal server(s) behind it.
  LAN hosts behind one NAT address are merged into one line.
- Reverse DNS names in parentheses after addresses: PTR support in the built-in DNS client and a non-blocking,
  in-memory cache resolved through the site's firewall (new names appear on the next refresh).
- Finding pages: reverse DNS under each remote endpoint ("no rDNS" when the address has no PTR record).
- Virtual IP sync records each VIP's interface and description (setting `fwaddr:db`).
- Version number and this changelog: footer link on every page, `/netmon/changelog`, `version` in `/netmon/healthz`.

### Changed
- Map zooms to 24x; dots, site markers, labels and finding markers keep their screen size, so zooming separates
  nearby sources.
- Finding markers catch the pointer only on the diamond (the ring no longer hides neighbouring sources).
- The near-site ring around each firewall location is gone (it hid the site); its traffic stays in the site's
  tooltip and in the numbers under the site label.

## Before v1.05 (2026-10-29 – 2026-10-30, unversioned)
### Added
- Monitor identity setting (Settings → Firewalls & sites → This monitor): FQDN served by the TLS front end (root
  helper renders the Caddyfile site line, validates, restarts Caddy) and used in notification links; address firewalls
  send to; live DNS check of the FQDN (recognises a reverse proxy on one of your own addresses).
- FQDNs for remote addresses from the Unbound query log (re-resolved on the same resolver, `netmon.dns_resolved`),
  shown under remote addresses in conversation tables; per-firewall DNS card (query log mode record, resolver,
  status) and IDS / DNS query log lines on Settings → Firewalls & sites.
- Optional Zeek sensor service (`docker compose --profile zeek`, pinned zeek/zeek 9.0.0, read-only, capture caps
  only) and three documented feeds: Proxmox bridge mirror (`host/pve-mirror.sh` + timer), switch SPAN, firewall
  bridge span — docs/zeek-sensor.md.
- Threat intelligence from the ExploitHound Threat Radar (Security → Threat intel): IDS findings citing a radar CVE
  are marked (optional one-level raise for CISA KEV), servers get a *Software* list matched against the radar, firewalls
  are matched on their vendor. Enrichment only.
- Server aliases (other names per address), editable from the Servers list; "This is normal" on findings
  (suppress the finding type, the exact finding or the device, and close matching open findings).
- Demo mode (`demo/`): isolated compose project, synthetic seed and live feeder, screenshots from it.
- Expected devices: operator-declared legitimate hosts are excluded from findings, including their destinations
  behind a shared NAT address; managed on Security → Suppressions or from a finding's LAN host list.
- `brand` config option; CSV GeoIP source (`NETMON_GEOIP_DB=*.csv`) for offline tests and the demo;
  `akvorado_metrics: {}` for installs without Akvorado collector metrics.
- Return-path NAT attribution for shared outbound NAT (bandwidth per LAN host with confidence tiers; fan-out
  findings list the LAN hosts their destinations replied to).
- Source health engine with hold-down, recovery and per-source transport judgement; Coverage page.
- ClickHouse schema module (`python -m netmon.schema`) with DNS, Zeek and authentication event tables.
- Unbound query-log and sshd/sudo/su/OPNsense-audit parsing; optional Zeek JSON ingestion.
- DNS context (transport per host, DoT/DoH labels, correlation with confidence, NXDOMAIN and random-label anomalies).
- AI threat score (0-100) with rationale and history; saved analyses load on the finding page without a new request.
- Logged firewall blocks by country; per-site live GeoIP policy.
- Connections filters (direction, protocol, port, server, remote IP).

### Changed
- Several new countries/networks for one host in one window are a single finding.
- 1:1 NAT public addresses are labelled with the internal server behind them.
- Fan-out rule ignores UDP 33434-33534 traceroute probes.
- Block-target validation reports "overlaps our own network" before "private range".

### Fixed
- Security page status tabs rendered a Python function name.
- "last verified null" on the Countries page when the policy comes from the config snapshot.
- Map: French Guiana, Svalbard and Crimea no longer inherit France/Norway/Russia shading.
- Finding pages no longer overflow horizontally on phones.
