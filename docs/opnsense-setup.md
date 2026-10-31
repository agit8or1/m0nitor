# OPNsense setup

Menu paths verified on OPNsense 26.7.x. These are done by an administrator in the firewall GUI — m0nitor never changes
them. Settings → Data sources shows the same steps with your monitor's address filled in, and the Coverage page shows
which telemetry is arriving. (m0nitor writes to a firewall only through its own block alias and auto-response
objects, and only when you enable those features — see [BLOCKING.md](BLOCKING.md).)

1. **NetFlow** — Reporting → NetFlow: listening interfaces WAN + LAN (or LAN bridge); WAN interfaces (egress only) WAN;
   version v9; destination `<monitor>:2055`; active timeout 120 s.
2. **Remote syslog** — System → Settings → Logging → Remote: TCP(4) to `<monitor>:5514`, rfc5424, applications
   filterlog, suricata, dpinger, wireguard, openvpn, audit, configd.py (and unbound for DNS context, optional).
3. **SNMP (optional)** — plugin os-net-snmp, read-only community, LAN address only. Community goes in `secrets/snmp_community`.
4. **Suricata (optional)** — Services → Intrusion Detection: IPS mode **off**, syslog alerts + eve syslog output on.
5. **API user (optional; needed for the live GeoIP policy, inventory sync and blocking)** — a dedicated user with only:
   Firewall: Alias: Edit (alias_util), Firewall: Rules (read), Virtual IPs, 1:1 NAT pages (read in practice). Store the
   key as `secrets/opnsense_block.key` or per firewall in Settings → Firewalls. See [BLOCKING.md](BLOCKING.md) for the alias and rules.

## Unbound query logging (optional, for DNS context)
Services → Unbound DNS → Advanced: Log queries / Log replies. Volume can be large; DNS retention is separately
configurable and short by default (7 days) because query names are sensitive.

## pfSense
NetFlow via softflowd on WAN only (softflowd reports the capture interface as both input and output), syslog over
UDP. Internal hosts behind NAT are not visible in pfSense flows. Blocking needs the pfSense REST API package.
