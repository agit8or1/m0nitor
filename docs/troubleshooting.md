# Troubleshooting

Start with the **Coverage** page: each source is judged by its own transport ("no events" is not "broken").

| Symptom | Check |
|---|---|
| A device shows "no data" | Settings → Devices → the device: actual source address seen, collector counters, decoder errors; the device's destination/port; host ACL status banner |
| Device logs arrive but stay "unrecognized" | the device page shows a sample line: check the log format against [vendors.md](vendors.md) (e.g. FortiGate format `default`, PAN-OS default CSV); open an issue with a sanitized sample |
| Flow numbers look wrong for a new exporter | `docker exec app-netmon-app-1 python -m netmon.flowdiag --listen 0.0.0.0:2056` while the exporter sends to 2056: templates, sequence gaps, sampling changes, clock drift ([devices.md](devices.md)) |
| A device has no blocked counts | only parsed deny/drop decisions count; flow-only devices and logs without an action never do (by design) |
| No flows | `docker compose logs akvorado-inlet`; inlet metrics `curl -s http://127.0.0.1:8080/api/v0/inlet/metrics`; firewall destination/port; host ACL (`iptables -L DOCKER-USER`) lists the exporter |
| Flows but wrong direction | interface metadata in `akvorado/config/outlet.yaml` (rendered from Settings → Firewalls: ifindex and names) |
| No firewall events | `ls -l /var/log/netmon/`; rsyslog AllowedSender; syslog transport/format (rfc5424) on the firewall |
| Per-host bandwidth missing behind NAT | LAN-side export (listening on the LAN interface), see [nat-attribution.md](nat-attribution.md) |
| "Unanswered" always 0 | Akvorado `schema: enabled: [TCPFlags]` applied and orchestrator/outlet restarted |
| GeoIP policy "fallback" | API key file, API user privileges (403 = missing privilege), TLS server name |
| AI request fails | key file, model name, daily cap; "max output tokens" includes reasoning tokens |
| UI shows stale data | freshness pill in the header; Settings → Health (collection, detector) |
| A page keeps showing the loading bar | the top progress bar shows pending requests; busy countries' 7-day block preview loads last (cached 10 min) |

Schema changes: `docker exec <app> python -m netmon.schema | docker exec -i <clickhouse> clickhouse-client --multiquery`
(the app's own ClickHouse user is read-only).
