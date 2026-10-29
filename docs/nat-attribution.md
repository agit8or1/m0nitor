# NAT attribution

Outbound flows leave the WAN with the post-NAT source. With a **shared outbound NAT address** every LAN host looks
the same, so per-address numbers aggregate many hosts. **1:1 NAT** (binat, single host) is deterministic and read from
the firewall (setting `nat11:db`).

## Return-path method
When a remote end answers, its reply crosses WAN → LAN towards the real host and is exported with the host's own
address. netmon matches each egress group (remote address, remote port, protocol) to the host(s) that received
replies from that same remote address and port:

| Tier | Meaning |
|---|---|
| high | exactly one LAN host received replies in the same minute |
| medium | exactly one host in the same 5 minutes |
| low | exactly one host anywhere in the window |
| ambiguous | several hosts — never split between them |
| no_return | no reply crossed to the LAN (unanswered, or firewall-originated) |
| unanswered | TCP flows with SYN and never ACK (needs Akvorado's `TCPFlags` column, enabled in the overlay) |

Fan-out findings on a shared NAT address apply the same idea per destination and list the LAN hosts their
destinations replied to, with counts; destinations that never replied (true probes) are reported as not attributable.

## Limits
- Unanswered connections cannot be attributed from flow records. Logging the LAN allow rule on the firewall would add
  pre-NAT records (cost: one log line per connection) — optional, and an operator decision.
- If the firewall does not export LAN-side records (capture only on WAN, or pfSense softflowd), only 1:1 NAT and port
  forwards are attributable.

## Validating on your network
Generate a known amount of traffic from two LAN hosts (e.g. `curl` uploads of 1.5 MB and 3 MB to a server you control)
and compare the attributed bytes per host with the WAN egress total for that window. The reference deployment matched
both hosts at "high" confidence and the sum equalled WAN egress exactly; an unanswered SYN to a documentation address
was classified as unanswered. Repeat this after firewall upgrades or capture changes.
