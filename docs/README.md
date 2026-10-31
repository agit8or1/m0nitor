# m0nitor documentation

| Topic | Document |
|---|---|
| **Try it** — isolated demo with synthetic data | [demo.md](demo.md) |
| **Install**, upgrade, rollback, backup, restore, uninstall | [install.md](install.md) |
| **Configuration** — config file, what lives in the UI, secrets | [configuration.md](configuration.md) |
| **Devices** — add routers, switches and other vendors' firewalls; what is actually arriving | [devices.md](devices.md) |
| **Device compatibility** — VERIFIED / PARTIAL / GENERIC per vendor, protocols, test coverage | [vendors.md](vendors.md) |
| **Firewall setup** — OPNsense and pfSense: NetFlow, syslog, SNMP, Suricata, API user, Unbound | [opnsense-setup.md](opnsense-setup.md) |
| **Blocking** — one-time alias and rules per firewall | [BLOCKING.md](BLOCKING.md) |
| **Maps and traffic views** — arcs, tooltips, WAN aliases, reverse DNS | [maps.md](maps.md) |
| **Findings and alerting** — rules, notifications, suppressions, auto-response | [alerting.md](alerting.md) |
| **NAT attribution** — LAN hosts behind a shared outbound NAT address | [nat-attribution.md](nat-attribution.md) |
| **GeoIP** — country policy vs. enforcement | [geoip.md](geoip.md) |
| **Threat intelligence** — CVE enrichment for IDS findings and server software | [threat-intel.md](threat-intel.md) |
| **Optional sources** — DNS names, Zeek, host logs | [dns-zeek-hostlogs.md](dns-zeek-hostlogs.md), [zeek-sensor.md](zeek-sensor.md) |
| **Security and privacy** — ports, accounts, secrets, retention | [privacy-hardening.md](privacy-hardening.md), [../SECURITY.md](../SECURITY.md) |
| **Architecture** — components, data flow, trust boundaries | [architecture.md](architecture.md) |
| **API and storage** — HTTP API, ClickHouse and SQLite schema | [api.md](api.md) |
| **Troubleshooting** | [troubleshooting.md](troubleshooting.md) |
| **Roadmap** | [ROADMAP.md](ROADMAP.md) |
| **Changelog** | [../CHANGELOG.md](../CHANGELOG.md) |
| **Contributing** | [../CONTRIBUTING.md](../CONTRIBUTING.md) |

Screenshots in [screenshots/](screenshots/) are taken from the demo with `demo/screenshots.py` (synthetic data,
documentation address ranges only).
