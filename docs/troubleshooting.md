# Troubleshooting

Start with the **Coverage** page: each source is judged by its own transport ("no events" is not "broken").

| Symptom | Check |
|---|---|
| No flows | `docker compose logs akvorado-inlet`; inlet metrics `curl -s http://127.0.0.1:8080/api/v0/inlet/metrics`; firewall destination/port; host ACL (`iptables -L DOCKER-USER`) lists the exporter |
| Flows but wrong direction | interface metadata in `akvorado/config/outlet.yaml` (rendered from Settings → Firewalls: ifindex and names) |
| No firewall events | `ls -l /var/log/netmon/`; rsyslog AllowedSender; syslog transport/format (rfc5424) on the firewall |
| Per-host bandwidth missing behind NAT | LAN-side export (listening on the LAN interface), see nat-attribution.md |
| "Unanswered" always 0 | Akvorado `schema: enabled: [TCPFlags]` applied and orchestrator/outlet restarted |
| GeoIP policy "fallback" | API key file, API user privileges (403 = missing privilege), TLS server name |
| AI request fails | key file, model name, daily cap; "max output tokens" includes reasoning tokens |
| UI shows stale data | freshness pill in the header; detector status in Settings |

Schema changes: `docker exec <app> python -m netmon.schema | docker exec -i <clickhouse> clickhouse-client --multiquery`
(the app's own ClickHouse user is read-only).
