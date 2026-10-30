# DNS, Zeek and host logs (optional sources)

| Source | Adds | Needs |
|---|---|---|
| Flow metadata (always) | DNS transport per host: which resolvers, DoT (853), possible DoH to public resolvers | nothing |
| Unbound log-queries/replies | client, name, type, rcode (no answers) | firewall setting, syslog app `unbound` |
| Zeek dns/conn/ssl/http/notice ([setup](zeek-sensor.md)) | answers + TTLs (enables DNS→connection correlation), LAN-to-LAN connections the mirror sees, TLS SNI (not content), cleartext HTTP request lines | a sensor on a mirror/TAP port, JSON logs mounted at `NETMON_ZEEK_DIR` |
| Server auth logs via syslog | sshd/sudo/su events, OPNsense audit (config changes) | forward to the monitor's 5514 |

DNS correlation confidence: **high** — the host's own query answered with the address, connection within the TTL,
one name; **medium** — several names share the address (CDN); **low** — only another client's answer matches
(shared resolver cache). Encrypted DNS content is never visible.

Nothing here is enabled automatically; each source shows "awaiting" on the Coverage page until data arrives.
No agents are deployed to other hosts by this project.

## Names for remote addresses (FQDN)

Resolver logs carry names, not answers. With the query log arriving, m0nitor asks the same resolver for each A/AAAA
name a host looked up. By default that's the firewall that sends the log; set another resolver per firewall under
Settings → Firewalls & sites → DNS. It records the answers in `netmon.dns_resolved` (same retention as DNS events).
A caching resolver normally returns the answer the host got, so Connections and the server pages show the name under
each remote address. Each name comes from one of two sources:

- **the host's own lookup**: this host asked for the name, and it resolved to this address;
- **≈ another host's lookup**: only other hosts asked. Shared hosting and CDNs put many names on one address, so up
  to three are listed.

Names are context, not evidence: no finding depends on them. The same card records how the firewall side is set up
(query log mode, who recorded it and when), next to the live "DNS query log" status.
