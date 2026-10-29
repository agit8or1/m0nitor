# Changelog

## Unreleased

### Added
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
