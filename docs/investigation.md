# Investigating with m0nitor

Every investigation page follows the same pattern: **summary → affected device → evidence → next action**. Devices are
named by their friendly name first; IP address and site are secondary. Confidence is always written out (and explained),
never shown by colour alone. Raw evidence, queries and thresholds sit behind expandable sections.

Empty pages say *why* they are empty: setup incomplete, still learning, nothing matched, the data needed is not
available, a source stopped reporting, or the check is switched off for that firewall.

## Device identity (v1.41)

A device keeps its history when its address changes.

**Where:** every device page has an **Address history** card; **Internal devices → Identity review** lists devices,
open questions, and each device's record (merge, separate, rename, history).

**How it works.** Every 15 minutes discovery records, per site and with a timestamp:

| Evidence | Source | Used for |
|---|---|---|
| MAC address | firewall ARP table (IPv4), NDP table (IPv6), DHCP leases | the device's identity (strongest key) |
| IP address interval (first → last seen) | the same, plus traffic | who had the address when |
| hostname | ARP table, DHCP | shown as evidence only |
| DHCP lease (start, end) | ISC DHCPv4 or Kea | lease history |

- **History stays with the device.** When a new MAC appears on an address, the address gets a new owner from that
  moment. Older findings keep the device that had the address at the time ("Device at the time" on the finding page,
  with a warning when the address now belongs to someone else).
- **Sites are separate.** The same private address at two sites is two devices; devices at different sites are never
  merged.
- **Weak evidence is labelled, never promoted.**
  - Traffic without a MAC proves only that an address is in use. After a gap it is attributed as *probable* (low
    confidence) until the firewall confirms the MAC again.
  - Randomized ("private") MACs are recognised and marked medium confidence.
  - Two devices on one address at the same moment are reported as ambiguous, not guessed.
- **No automatic merging.** A shared hostname, the same MAC at two sites, or a device that moved creates a question
  under *Needs your review*. Generic names (`ubuntu`, `android-…`) do not. Merges and separations can be undone and
  are recorded in the device's history and the audit log (admin role).
- **Two addresses at once** (one machine, two IPs or two NICs on one MAC) are one device. Two NICs with different
  MACs stay two devices until you merge them.

**Data it needs:** the ARP table privilege (already used by discovery). Optional: *Diagnostics: NDP Table* for IPv6,
*Services: ISC DHCPv4: Leases* (or *Services: DHCP: Kea(v4)*) for leases. A missing privilege is named on
Settings → Inventory → Auto-discovery. Without an API user, identities are built from traffic only (low confidence).

**Limits:** devices behind another router (no ARP entry at the firewall) are identified by address only. MAC addresses
of routed or VPN clients are not visible. Inventory names are still kept per address: when a device moves, the review
page asks whether its name should follow.

## Per-firewall monitoring choices (v1.41)

**Settings → Firewalls & sites → (firewall) → What to monitor**: choose per firewall which sources and checks are
analysed: traffic, firewall log, IDS, DNS, SNMP, device events, ARP/NDP/DHCP discovery, WAN/VPN probes and
segmentation checks. A source you switch off is shown as "not monitored on this firewall (your choice)". It does not
fail health checks or raise findings, and a health finding it had open is closed. Nothing changes on the firewall.

Each firewall also has a **time zone** (IANA name, e.g. `America/New_York`). It is used for schedules, local times and
time-of-day baselines, including daylight-saving changes.

## Choosing firewalls on the dashboard (v1.41)

With more than one firewall, the scope bar has a firewall picker: **All firewalls**, one, or any combination. The
choice is part of the page address (`?site=a,b`), so it survives navigation and can be shared as a link.

## What changed? (v1.42)

**Where:** **Investigate → What changed**, and the top three on the Overview (**Important changes today**).

Pick a comparison: today vs yesterday, this week vs last week, a selected period vs the one before, the same weekday
and time on previous weeks (1–8 weeks), or two custom periods (each up to 31 days, in the firewall's time zone). The
page shows up to twelve sentences, at most three of each kind, with **View evidence** links. Everything else is
under *All changes by type*.

| Kind | Meaning |
|---|---|
| Monitoring data | flow records or a log source covered much less of the period than before |
| Newly observed inbound services | a device answered outside clients on a port not seen in the history searched |
| New destinations of fixed-function devices | an IoT, management or network device contacted an address it has not used |
| More uploaded / received than usual | ≥ 3× (and ≥ 100 MB) per hour with data |
| Less traffic than usual | ≤ ⅓ per hour with data, only when the period is fully covered |
| Configuration changes | the firewall's audit log, with who, from where and which page |
| Newly observed devices | first internet traffic, or a new MAC address reported by the firewall |
| New countries / networks | grouped per device |

**How to read it:**
- *Newly observed* means not seen in the history searched; each line says how many days that was. It does not prove
  that something is new.
- Hours without flow records are not counted as zero. When data is missing, a warning comes first and an empty list
  is never presented as a clean bill of health.
- A configuration change followed by new inbound traffic is shown as an association in time, not as the cause.
- Devices marked as expected are listed with their reason, but never at the top. Traffic through the shared NAT
  address cannot be attributed to a single device, so it is marked low confidence.

## Incidents (v1.43)

**Where:** **Investigate → Incidents**. A finding that belongs to an incident links to it. Any other finding offers
**Start an incident from this finding** (analyst).

**How findings are grouped:**
- **Same device**, using its identity, so an address change does not split it, within 6 hours; or **the same remote
  address** on different devices within 6 hours. The reason is shown on every finding.
- An incident starts only with two related findings, one of them a security finding of medium severity or higher.
  Low-severity and informational findings can join but never start one. Health and TEST findings, and the shared
  NAT address, are not grouped automatically.
- An incident follows one device or one remote address. It never chains other devices in through shared findings,
  and it covers at most 24 hours of activity.
- Grouping means "related in time and place", not "caused by".

**Handling an incident (analyst):** assign it, add notes, set the status (open → investigating → resolved; resolving
needs a reason and can close the findings too), split a finding out (it is never re-added automatically), add a
finding by number, merge incidents. **Dismiss** (on each open incident in the list and on its page) resolves it
as "Dismissed (no action needed)" in one click and leaves its findings as they are; **Reopen** on the Resolved tab undoes
it. Everything goes into the incident's timeline and the audit log. **Export evidence
(JSON)** downloads the incident, its findings with evidence and queries, and the history; each export is audited.

**Notifications:** if a channel already received a finding from an incident in the last 6 hours, it does not get
another one of the same or lower severity. A higher-severity finding is always sent. Messages link to the incident.

**Overview → Needs attention:** open incidents (and how many are unassigned), high-severity findings that are not in
an incident, and monitoring problems. When nothing is open it says so only if all monitored sources are reporting.

## Baselines and precise exceptions (v1.44)

**Saying "this is normal" precisely.** On a finding, **This is normal** offers, from narrow to broad:

1. only this behaviour (this kind of finding, this device, this subject);
2. this device to **one destination** (IP or CIDR, at most a /16) and/or **one service** (`tcp/443`);
3. any finding of this kind for the device (broad);
4. every finding for the device, i.e. an expected device (broadest).

Any of these can be limited to a **schedule** (days and a local time window, overnight allowed, in the firewall's time
zone) and given an **expiry date** (90 days by default). **Preview what this hides** shows the sentence, how many
findings of the last 30 days it would have hidden, examples, and how many findings for the device would still be
raised. Nothing is saved until you confirm.

**What an exception cannot hide:** a destination-limited exception only hides a finding that names exactly that
destination. Scanning, external-DNS and blocked-outbound findings involve many destinations and are never hidden by
one. For **outbound volume**, the traffic to the excepted destination is left out of the count and the rest is
still compared with the baseline: a normal backup does not hide an unrelated upload.

**Reviewing:** Security → Suppressions lists each exception as a sentence, how many findings it hid and when last,
and its expiry (with a warning shortly before). You can extend it by 30 days or remove it; changes are audited.

**How "usual" is calculated (outbound volume):** the same local hour on earlier days, in the firewall's time zone and
across daylight-saving changes; weekdays are compared with weekdays and weekends with weekends once three of each
exist. Hours without traffic records from the firewall are left out (never counted as zero), and hours with
unresolved volume findings for that address are not learned. The Baselines card shows each firewall's learning
progress.

## Threat hunt (v1.45)

**Where:** **Investigate → Threat hunt**.

**Question it answers:** did anything here talk to a known-bad address, address range or domain, and when?

1. Pick one or more **indicator lists** and/or paste indicators for this hunt (one per line: IPs, ranges up to /16,
   domains, URLs, or defanged forms like `evil[.]example`).
2. Choose the period (up to 31 days, limited by what is retained) and the firewalls, then **Search history**. The
   hunt runs in the background, with progress and **Cancel**.

**Results**, per indicator:
- each affected device (the device at the time) and firewall;
- first and last contact, how many records, volume and direction;
- a link to the records;
- the indicator's list, source and confidence, when netmon first knew it and when it was published, and whether it
  is still valid;
- **Create a finding** (analyst), to triage it or group it into an incident.

**How much a match means:** *a match is evidence to investigate, not proof.* Results warn when:
- the contact happened **before the indicator was published** (the address may not have been malicious then);
- the address belongs to a **CDN** or **shared hosting** (it serves many unrelated sites);
- the indicator is **stale** (past its validity, or older than 180 days);
- the connection went through the **shared NAT address** and no reply named the device.

**What was searched:** every hunt lists the history per source and firewall (traffic records, DNS query log), with
gaps. Akvorado's long-term tables keep no addresses, so the hunt reaches back only as far as the raw traffic records.

**Lists:** analysts add manual lists (plain or CSV: `value,confidence,published,valid_until`). Admins can add an
**HTTPS feed** that netmon fetches on a schedule (size-limited). Indicators that disappear from a feed are kept but
marked inactive. Lists are deduplicated when hunting.

## Segmentation (v1.46)

**Where:** **Internal devices → Segmentation**. This is monitoring only: netmon never changes firewall rules.

1. **Groups:** address ranges per firewall (for example Guest Wi-Fi, IoT, Servers, Management). Mark a group
   *sensitive* to raise findings about it at high severity.
2. **Rules** for the communication you expect, from one group (or any group) to another:
   - *communication expected*, optionally only on listed services (`tcp/443, udp/53`); other services are then
     unexpected;
   - *no communication expected*, optionally only for listed services;
   - optionally only during a schedule (outside it the rule does not apply).
   A rule for a specific pair of groups beats one for "any group". **Templates** set up common cases: guest isolated,
   IoT kept apart, servers on listed services only, management only from admins.
3. The **communication matrix** shows, per pair, what your rules expect and what the firewall saw: records,
   unexpected records, and blocks recorded in the firewall log. Open a cell for the top conversations.

**What "not seen" means:** only traffic that passes the firewall is visible. Devices on the same switch or VLAN talk
to each other without the firewall seeing it, so *not seen never means blocked*. "Blocked" is shown only when the
firewall log recorded blocks. Groups with no visible traffic are named on the page. The firewall's own address
(proxies, NAT reflection) is not counted as device traffic. Who opened a connection is inferred from ports.

**Findings:** traffic your rules call unexpected becomes a *Unexpected internal communication* finding, with the
rule it broke. Use **This is normal** to except one device, destination and service precisely, or change the rule.
Switch the check off per firewall under *What to monitor → Segmentation checks*.

## Applications (v1.47)

**Where:** **Internal devices → Applications**.

1. **Create an application:** give it a name, and optionally an owner and a "critical" mark. Add the devices it runs
   on, for example a mail server, its database and its backup target. A device keeps its place when its address
   changes, because members follow the device identity.
2. Each application page lists:
   - **What it uses:** internal servers and services, and internet services grouped by network owner and service.
     Reply records tie these to the device, even behind a shared address.
   - **What uses it:** internal devices and internet clients. This is the **outage impact**.

   Every row shows the service, records, last seen, when netmon first saw it, and a **confidence**. Confidence is
   how many days of the period the dependency was seen, or how many 4-hour periods when you look at 24 hours.
   **New** marks dependencies first seen in the last 24 hours.
3. **Confirm** the dependencies that are real and dismiss the rest. A confirmed dependency that was not seen in the
   period stays on the list as *not seen*: **lack of traffic does not prove a dependency is gone**. It may only be
   used monthly, or only during a failover.
4. **Outage impact of one device:** enter an internal address on the Applications page. You see which applications
   and devices used it in the last 7 days, and whether it is reached from the internet.
5. **Show picture** draws the application with its main dependencies. The list is always the complete version.

Only traffic that passes the firewall is visible: devices on the same switch or VLAN are not seen talking to each other.

## WAN / VPN quality (v1.48)

**Where:** **Settings → Status → WAN / VPN quality**. A problem also shows on the Overview and as a Health row.

1. **Add probes:** probes are opt-in. **Add the recommended probes** pings the firewall and two anycast resolvers,
   sends a DNS query through the firewall, and makes one HTTPS request, every 60 s. The page lists exactly what will
   be added. You can add your own:
   - ping, a TCP port, a DNS resolver, or an HTTPS address;
   - with a role (*the firewall*, *the provider's first hop*, *an internet host*, *a VPN site*, *a service*);
   - with an interval of 30 s to 1 h.
   There are never bandwidth tests.
2. **Now:** each probe shows its state with current values and its usual values. A small chart shows latency over
   the period, with marks where there was loss or no answer. A new probe learns its usual values for about an hour.
3. **Degraded periods:** two or more bad rounds in a row (loss, no answer, or more than twice the usual time). Each
   period lists **facts**: what was affected and what was not, how busy the WAN link was, and what the firewall logged
   at the same time. A **suspected cause** appears only when the probes support it:
   - the firewall probe was affected too → the local network or the firewall;
   - every internet probe was affected and the link was busy → a busy link;
   - every internet probe was affected, the link was not busy, and the firewall was fine → beyond the firewall;
   - the same, plus the **provider's first hop** was affected → *possibly a provider problem*. Without that probe,
     netmon does not blame the provider;
   - only one target was affected → that destination or the path to it;
   - only DNS was affected → the DNS resolver;
   - a VPN probe was affected while internet probes were fine → the VPN tunnel or the remote site.

Tip: to recognise provider problems, add a ping to the first public address in a traceroute from the firewall,
with the role *the provider's first hop*. Set the contracted capacity under *Firewalls & sites* so that link use
shows as a percentage.

## Search (v1.49)

**Where:** **Investigate → Search**, or type in the header search and choose *Ask it as a question*.

1. **Ask in plain English:** for example *Which devices talked to Russia in the last 7 days?*, *Blocked
   connections to 10.0.0.5 yesterday*, *Which devices looked up example.com this week?*, *High severity findings in
   the last 30 days*. netmon interprets the question itself; nothing leaves the server. The page shows what it
   understood under **Searching for** (data, period, filters, grouping), and lists any words it did not understand.
2. **Change the filters** to adjust anything, or to search without a question.
3. **Results** link to devices, remote addresses and findings. A shared public (NAT) address is labelled as
   *several devices*. The volume *sent* by one device behind a shared address cannot be known from the firewall's
   records, and the page says so. *Received* volume can be tied to the device.
4. **AI (optional, when configured):** *Interpret with AI instead…* first shows exactly what would be sent: only the
   question, with internal addresses and device names replaced, plus the model and today's request count. The
   answer is only a set of filters, which you see before the results.
5. **Save** a search, privately or shared (analysts). An analyst can **propose it as a detection**: choose how often
   it runs, the number of results that raises a finding, and the severity. **An admin reviews it first**: the review
   shows how many findings per day it would have raised over the last week. Only then does it run. Its findings
   follow your notification rules and exceptions, and never block anything. Admins can stop it at any time.

Searches are read-only and bounded: the period is limited to how long each kind of data is kept, and each search
returns at most 200 rows.

## Testing detections (v1.50)

**Where:** **Investigate → Test detections**, and **Settings → Alert rules**.

1. **Test a detection:** choose a scenario and a device, adjust the numbers if you like, and press **Test detection**.
   The scenarios are a new country, a large upload, an exposed port, a scan, beaconing, and a normal day. Or press
   **Run all scenarios**. The real rules run against made-up records that exist only inside the query: nothing is
   stored, recorded, notified or blocked.
2. Each test shows **expected vs actual**:
   - *raised*: with the rule's own explanation;
   - *not raised*: with the likely reason. For example, the threshold is higher than the scenario, the rule or the
     data source is switched off, netmon is still learning, a port forward makes the exposure intended, or an
     exception or expected device would hide it (named, so you can check it).
3. **Preview rule changes:** on *Settings → Alert rules*, change thresholds and press **Preview rule changes**
   instead of Save. The preview lists what changes, runs the matching scenarios with the current and the proposed
   settings, and can **replay** the changed rules on your retained data. The replay covers the last 24 hours, 3 days
   or 7 days, runs in the background and can be cancelled; it compares how many findings each version would have
   raised, with examples. **Save these rules** applies the change; leaving the page discards it.

