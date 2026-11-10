# NAT attribution

Outbound flows leave the WAN with the post-NAT source address. With a **shared outbound NAT address** every LAN host
looks the same, so per-address numbers aggregate many hosts. **1:1 NAT** (binat, single host) is deterministic and is
read from the firewall (setting `nat11:db`).

To check one firewall end to end, use **Settings → Onboarding test**. It shows whether WAN flows, LAN return flows,
firewall logs and usable NAT evidence are arriving and fresh, and what to fix when they are not. It also offers the
guided validation described below. Coverage summarises the test for every firewall you can see.

## Return-path method
When a remote end answers, its reply crosses WAN → LAN towards the real host and is exported with the host's own
address. netmon matches each egress group (exporter, remote address, remote port, protocol) with the internal hosts
that received replies from that same remote address and port **on the same exporter**:

| Tier | Meaning |
|---|---|
| high | exactly one internal host received replies in the same minute |
| medium | exactly one host in the same 5 minutes |
| low | exactly one host anywhere in the window |
| ambiguous | several hosts. The bytes are never split between them |
| no_return | no reply reached the LAN: unanswered, firewall-originated, or the reply took another path (asymmetric routing) |
| unanswered | TCP flows with SYN and never ACK (needs Akvorado's `TCPFlags` column, enabled in the overlay) |
| wan_only | the exporter captures only the WAN (capture mode, e.g. pfSense softflowd): no LAN-side record exists |

Rules that keep the tiers honest (each is covered by `tests/test_nat_scenarios.py` against a real ClickHouse):

- **Only internal addresses count as return evidence.** Only addresses inside the firewall's own internal networks
  count, never its NAT address. Before v1.59, on a WAN-only exporter the reply to the NAT address was counted as "one
  host" and reported as *high* for the NAT address itself.
- **No pairing across exporters.** A reply that comes back through another firewall (multi-WAN, HA, a second site)
  does not confirm this firewall's egress. The egress stays `no_return`.
- **Unanswered bytes stay unanswered.** SYN-only flows are counted as `unanswered` even when another host's answered
  connection shares the same remote address, port and minute. They are never added to that host.
- **Collection problems can only lower a tier.** The health loop records collector receive drops and duplicate exports,
  and the export check records sequence gaps. In a window with recorded **export loss**, single-host results are capped
  at *low*, because a lost reply record can hide a second host. With **duplicate exports** (≥ 1 % identical records)
  they are capped at *medium*. The moved bytes and the reasons are shown with the result.
- **Unmeasured loss is stated.** The collector does not keep NetFlow/IPFIX sequence numbers. Until the export check has
  run for a firewall (in the last 30 days), every attribution result says that *high* assumes no records were lost on
  the way.
- **Clock skew does not cap.** Pairing uses the collector's receive time, so an exporter clock that is wrong cannot move
  records into the same minute. Delayed export only lowers tiers. Skew is shown on the onboarding test (firewall logs
  vs monitor, and the export header time) because it breaks time correlation between logs and flows.
- **Weaker tiers name the only candidate.** *medium* and *low* say that exactly one host received replies from that
  remote in the wider window. With delayed export, or a lost reply, that host may not be the one that sent the
  upload. Use *high* for decisions about a host.

Fan-out findings on a shared NAT address apply the same idea per destination and list the LAN hosts their
destinations replied to, with counts. Destinations that never replied (true probes) are reported as not attributable.

## Limits
- Unanswered connections cannot be attributed from flow records. Logging the LAN allow rule on the firewall would add
  pre-NAT records (cost: one log line per connection). That is optional and an operator decision.
- If the firewall does not export LAN-side records (capture only on WAN, or pfSense softflowd), only 1:1 NAT and port
  forwards are attributable. The onboarding test shows *LAN return flows: not possible with this export*.

## Guided validation on your network
On **Settings → Onboarding test**, an analyst or admin enters two internal hosts they operate and a public destination
they are authorised to send test uploads to (for example a server they run). netmon never sends traffic itself. The
page shows four commands to run on the hosts:

1. host A uploads 1.5 MB;
2. two minutes later, host B uploads 3 MB;
3. optional: both upload 0.5 MB at the same moment (expected: **ambiguous**, never split);
4. optional: host A tries a port the destination does not answer (expected: **unanswered** or **no LAN return path**).

**Evaluate** then shows, for that destination only, what was attributed to which host and at which tier. It checks that
A and B each got at least 90 % of their upload, that no other host was named, and that the simultaneous and unanswered
steps were *not* turned into single-host results. Collection problems in the window are listed as limits. A WAN-only
exporter fails the validation by design, because per-host attribution is not possible there. The last result per
firewall appears on Coverage. Repeat the validation after firewall upgrades or export changes.

The reference deployment (OPNsense, routed, WAN + LAN bridge) matched both hosts at *high* in a manual upload check
before the guided validation existed, and the sum equalled WAN egress exactly. Other vendors have not been validated
on hardware: see [field validation](field-validation.md).
