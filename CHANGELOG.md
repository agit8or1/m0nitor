# Changelog

## Unreleased

### Added
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
- Fan-out rule ignores UDP 33434-33534 traceroute probes.
- Block-target validation reports "overlaps our own network" before "private range".

### Fixed
- Map: French Guiana, Svalbard and Crimea no longer inherit France/Norway/Russia shading.
- Finding pages no longer overflow horizontally on phones.
