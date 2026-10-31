"""Device profiles: what each vendor family can actually export, and what m0nitor implements for it.

Statuses (per profile, shown in Settings -> Devices and docs/vendors.md):
  VERIFIED     implemented and validated against a real device of this family in a deployment
  PARTIAL      a vendor log parser is implemented and tested with synthetic fixtures written from the vendor's
               documented log format; not yet validated on hardware. Generic protocols work as for GENERIC.
  GENERIC      no vendor parser: flows (NetFlow/IPFIX/sFlow), SNMP counters and generic syslog storage only
  UNSUPPORTED  not usable

Capability values: True = documented by the vendor, False = not offered, None = firmware/model dependent or not
confirmed (shown as "unknown", never as working). `parser` names a module in netmon.parsers; `decisions` says whether
that parser yields firewall allow/deny decisions (only those feed blocked counts). Enforcement is implemented only
where `response` is set.
"""

VERIFIED, PARTIAL, GENERIC, UNSUPPORTED = "VERIFIED", "PARTIAL", "GENERIC", "UNSUPPORTED"
FLOW_PROTOCOLS = ("netflow_v5", "netflow_v9", "ipfix", "sflow")
SYSLOG_TRANSPORTS = ("udp", "tcp", "tls")
CATEGORIES = ("traffic", "ids", "auth", "vpn", "config", "interface", "routing", "ha", "dhcp", "dns", "threat", "system")

# Ports on the monitor. NetFlow v5/v9 and IPFIX share Akvorado's netflow input; sFlow has its own decoder input.
PORTS = {"netflow": 2055, "ipfix": 2055, "sflow": 6343, "syslog": 5514}


def _p(name, status, flows, syslog, snmp, parser=None, categories=(), decisions=False, flow_mode="routed",
       api=None, response=None, notes="", setup=""):
    return {"name": name, "status": status, "flows": dict(zip(FLOW_PROTOCOLS, flows)),
            "syslog": dict(zip(SYSLOG_TRANSPORTS, syslog)), "snmp": dict(zip(("v2c", "v3"), snmp)), "parser": parser,
            "categories": tuple(categories), "decisions": decisions, "flow_mode": flow_mode, "api": api,
            "response": response, "notes": notes, "setup": setup}


# Setup snippets: {MON} = monitor address, {SYSLOG} = syslog port, {FLOW} = NetFlow/IPFIX port, {SFLOW} = sFlow port.
PROFILES = {
    "opnsense": _p("OPNsense", VERIFIED, (True, True, False, False), (True, True, True), (True, True),
                   parser="opnsense", categories=("traffic", "ids", "auth", "config", "vpn", "interface", "dns", "system"),
                   decisions=True, api="REST (read-only user)", response="opnsense",
                   notes="NetFlow via Reporting -> NetFlow (v5/v9). filterlog, Suricata EVE, Unbound, audit and gateway "
                         "events via remote syslog (RFC 5424, TCP). Tested on 26.x.",
                   setup="Settings -> Firewalls & sites shows the OPNsense steps with your values filled in."),
    "pfsense": _p("pfSense", PARTIAL, (True, True, True, False), (True, False, False), (True, None),
                  parser="opnsense", categories=("traffic", "ids", "auth", "system"), decisions=True, flow_mode="capture",
                  api="REST API package (third party)", response="pfsense",
                  notes="NetFlow/IPFIX via the softflowd package (WAN only). Remote syslog is UDP. filterlog uses the "
                        "OPNsense field order. SNMPv3 needs the net-snmp package.",
                  setup="Settings -> Firewalls & sites shows the pfSense steps with your values filled in."),
    "fortigate": _p("Fortinet FortiGate", PARTIAL, (False, True, True, True), (True, True, True), (True, True),
                    parser="fortigate", categories=("traffic", "ids", "auth", "vpn", "config", "interface", "ha", "threat", "system"),
                    decisions=True, api="REST (not used yet)",
                    notes="Syslog format 'default' (key=value). 'mode reliable' = TCP (RFC 6587); 'enc-algorithm' enables TLS. "
                          "NetFlow v9 is configured per interface (netflow-sampler); FortiOS 7.2+ moved collectors under "
                          "'config collectors'. sFlow via 'config system sflow'.",
                    setup="""config log syslogd setting
    set status enable
    set server "{MON}"
    set port {SYSLOG}
    set mode reliable
    set format default
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
end
config system netflow
    set collector-ip {MON}          # FortiOS 7.2+: config collectors / edit 1 / set collector-ip {MON}
    set collector-port {FLOW}
end
config system interface
    edit "wan1"
        set netflow-sampler both
    next
end"""),
    "panos": _p("Palo Alto Networks PAN-OS", PARTIAL, (False, True, False, False), (True, True, True), (True, True),
                parser="panos", categories=("traffic", "ids", "threat", "auth", "vpn", "config", "ha", "routing", "system"),
                decisions=True, api="XML/REST (not used yet)",
                notes="CSV syslog (BSD or IETF). Field positions follow the PAN-OS 10.x/11.x log field documentation; "
                      "custom log formats are not parsed. NetFlow v9 only (no IPFIX, no sFlow).",
                setup="""Device -> Server Profiles -> Syslog: add {MON}, transport TCP (or SSL), port {SYSLOG}, format IETF, default (CSV) log format
Objects -> Log Forwarding: profile with Traffic + Threat -> that syslog profile; attach it to your security rules
  (keep "Log at Session End"; add "Log at Session Start" only if you need it)
Device -> Log Settings: System, Configuration, User-ID, GlobalProtect -> the same syslog profile
Device -> Server Profiles -> NetFlow: add {MON}:{FLOW}; Network -> Interfaces -> <WAN/LAN> -> Advanced -> NetFlow Profile"""),
    "cisco_asa": _p("Cisco ASA", PARTIAL, (False, True, False, False), (True, True, True), (True, True),
                    parser="cisco", categories=("traffic", "auth", "vpn", "config", "interface", "ha", "system"),
                    decisions=True,
                    notes="Syslog message IDs (%ASA-n-NNNNNN). NetFlow is NSEL (event-based flow export, not periodic "
                          "flow records): byte counts and timing differ from router NetFlow. With TCP syslog set "
                          "'logging permit-hostdown' so a down collector never blocks traffic.",
                    setup="""logging enable
logging timestamp
logging trap informational
logging host inside {MON} 17/{SYSLOG}        ! UDP; for TCP: logging host inside {MON} 6/{SYSLOG}
logging permit-hostdown
! optional NSEL flow export
flow-export destination inside {MON} {FLOW}
policy-map global_policy
 class class-default
  flow-export event-type all destination {MON}"""),
    "cisco_ftd": _p("Cisco Firepower / FTD", PARTIAL, (False, True, False, False), (True, True, True), (True, True),
                    parser="cisco", categories=("traffic", "auth", "vpn", "config", "interface", "ha", "ids", "system"),
                    decisions=True,
                    notes="LINA syslog (%FTD-n-NNNNNN, same IDs as ASA) and intrusion events 430001. Configured from "
                          "FMC/FDM Platform Settings -> Syslog. NSEL as for ASA.",
                    setup="""FMC: Devices -> Platform Settings -> Syslog -> Syslog Servers: add {MON}, UDP {SYSLOG} (or TCP)
Logging Setup: Enable Logging; Logging Destinations: Syslog Servers, level Informational
Policies -> Access Control -> rule -> Logging: Log at End of Connection, send to the syslog server
Intrusion events: Policies -> Intrusion -> Advanced Settings -> Syslog Alerting -> {MON}"""),
    "cisco_ios": _p("Cisco IOS / IOS-XE", PARTIAL, (True, True, True, False), (True, True, False), (True, True),
                    parser="cisco", categories=("traffic", "auth", "config", "interface", "routing", "system"),
                    decisions=True,
                    notes="ACL log lines (%SEC-6-IPACCESSLOGP) are rate-limited summaries: they count logged denies, not "
                          "every packet. Flexible NetFlow v9; IPFIX on IOS-XE. TCP syslog on IOS-XE only.",
                    setup="""service timestamps log datetime msec show-timezone
logging trap informational
logging host {MON} transport udp port {SYSLOG}
login on-failure log
login on-success log
archive
 log config
  logging enable
  notify syslog contenttype plaintext
flow exporter M0NITOR
 destination {MON}
 transport udp {FLOW}
 export-protocol netflow-v9
flow monitor M0NITOR
 exporter M0NITOR
 record netflow ipv4 original-input
interface GigabitEthernet0/0
 ip flow monitor M0NITOR input"""),
    "meraki": _p("Cisco Meraki MX", PARTIAL, (False, True, False, False), (True, False, False), (True, True),
                 parser="meraki", categories=("traffic", "ids", "vpn", "system"), decisions=True, api="Dashboard API (not used yet)",
                 notes="Syslog is UDP only with Meraki's own header. 'flows'/'firewall' lines carry pattern: allow/deny; "
                       "they are only generated for rules with logging enabled.",
                 setup="""Network-wide -> General -> Reporting
  Syslog servers: add {MON}, port {SYSLOG}, roles: Flows, Security events, Appliance event log
  NetFlow traffic reporting: Enabled, collector {MON}, port {FLOW}"""),
    "junos": _p("Juniper SRX / Junos", PARTIAL, (True, True, True, None), (True, True, True), (True, True),
                parser="junos", categories=("traffic", "ids", "auth", "config", "interface", "routing", "system"),
                decisions=True, api="NETCONF/REST (not used yet)",
                notes="Structured syslog (sd-syslog) RT_FLOW session logs and RT_IDP. sFlow is available on EX/QFX "
                      "switches, not generally on SRX. Inline J-Flow v9/IPFIX depends on platform.",
                setup="""set system syslog host {MON} any info
set system syslog host {MON} port {SYSLOG}
set system syslog host {MON} structured-data
set security log mode stream
set security log format sd-syslog
set security log stream m0nitor host {MON}
set security log stream m0nitor host port {SYSLOG}
set security policies from-zone untrust to-zone trust policy <name> then log session-close
# log denies with a final explicit deny policy that has 'then log session-init'"""),
    "mikrotik": _p("MikroTik RouterOS", PARTIAL, (True, True, True, None), (True, None, False), (True, True),
                   parser="mikrotik", categories=("traffic", "auth", "config", "interface", "vpn", "system"),
                   decisions=True, api="REST (RouterOS 7, not used yet)",
                   notes="RouterOS firewall log lines do not contain the rule action: an action is only taken from a "
                         "log-prefix that names it (DROP/REJECT/ACCEPT); otherwise it is unknown and never counted as a "
                         "block. Traffic Flow exports NetFlow v5/v9/IPFIX.",
                   setup="""/system logging action add name=m0nitor target=remote remote={MON} remote-port={SYSLOG} bsd-syslog=yes
/system logging add topics=firewall action=m0nitor
/system logging add topics=account action=m0nitor
/system logging add topics=system,info action=m0nitor
/ip firewall filter set [find where action=drop] log=yes log-prefix="DROP"
/ip traffic-flow set enabled=yes interfaces=all
/ip traffic-flow target add dst-address={MON} port={FLOW} version=9"""),
    "unifi": _p("Ubiquiti UniFi gateways / UDM", PARTIAL, (None, None, None, None), (True, None, False), (True, None),
                parser="netfilter", categories=("traffic", "system"), decisions=True,
                notes="Firewall logs are netfilter kernel lines; the action comes from UniFi's rule prefix suffix "
                      "(-A accept, -D drop, -R reject). NetFlow/IPFIX availability depends on the UniFi Network "
                      "version and gateway model: check what arrives on the Devices page before relying on it.",
                setup="""UniFi Network -> Settings -> CyberSecure / System -> Traffic Logging (wording varies by version)
  Activity Logging (Syslog): SIEM server {MON}, port {SYSLOG}
Enable logging on the firewall rules you want to see"""),
    "edgeos": _p("Ubiquiti EdgeRouter / EdgeOS", PARTIAL, (True, True, True, None), (True, False, False), (True, True),
                 parser="netfilter", categories=("traffic", "auth", "system"), decisions=True,
                 notes="netfilter log lines with [RULESET-RULE-A/D/R] prefixes.",
                 setup="""set system syslog host {MON}:{SYSLOG} facility all level info
set firewall name WAN_IN enable-default-log
set system flow-accounting interface eth0
set system flow-accounting netflow version 9
set system flow-accounting netflow server {MON} port {FLOW}
commit ; save"""),
    "vyos": _p("VyOS", PARTIAL, (True, True, True, True), (True, True, False), (True, True),
               parser="netfilter", categories=("traffic", "auth", "system"), decisions=True, api="HTTP API (not used yet)",
               notes="nftables log prefixes [ipv4-NAM-filter-default-D]. Syslog syntax changed in 1.5 "
                     "(system syslog remote).",
               setup="""set system syslog host {MON} facility all level info        # 1.5+: set system syslog remote {MON} ...
set system syslog host {MON} port {SYSLOG}
set firewall ipv4 input filter default-log
set system flow-accounting interface eth0
set system flow-accounting netflow version 9
set system flow-accounting netflow server {MON} port {FLOW}
set system sflow server {MON} port {SFLOW}"""),
    "linux": _p("Linux nftables / iptables", PARTIAL, (True, True, True, True), (True, True, True), (True, True),
                parser="netfilter", categories=("traffic", "auth", "system"), decisions=True,
                notes="Kernel netfilter log lines (IN= OUT= SRC= DST= ...). The action is taken from the log prefix "
                      "only (e.g. 'm0nitor DROP: '); without one it is unknown. Flows via softflowd/pmacct, sFlow via hsflowd.",
                setup="""# nftables: log before the drop, with a prefix that names the action
nft add rule inet filter input counter log prefix \\"m0nitor DROP: \\" drop
# rsyslog: forward kernel + auth logs (TCP)
echo 'kern.*;auth,authpriv.* @@{MON}:{SYSLOG}' > /etc/rsyslog.d/90-m0nitor.conf && systemctl restart rsyslog
# flows (WAN interface only, to avoid double counting)
softflowd -i eth0 -n {MON}:{FLOW} -v 9 -t maxlife=120"""),
    "openwrt": _p("OpenWrt", PARTIAL, (True, True, True, None), (True, True, False), (True, True),
                  parser="netfilter", categories=("traffic", "system"), decisions=True,
                  notes="fw4 log prefixes ('drop wan in: ', 'reject wan in: '). Flows need the softflowd package; "
                        "SNMP needs snmpd.",
                  setup="""uci set system.@system[0].log_ip='{MON}'
uci set system.@system[0].log_port='{SYSLOG}'
uci set system.@system[0].log_proto='udp'
uci set firewall.@zone[1].log='1'        # wan zone
uci commit && /etc/init.d/log restart && fw4 reload
opkg install softflowd   # then set interface and destination {MON}:{FLOW} in /etc/config/softflowd"""),
    "ddwrt": _p("DD-WRT", PARTIAL, (True, False, False, False), (True, False, False), (True, False),
                parser="netfilter", categories=("traffic", "system"), decisions=True,
                notes="Remote syslog is UDP. Firewall logging (Security -> Log) writes 'DROP IN=...'/'ACCEPT IN=...' "
                      "lines. RFlow exports NetFlow v5.",
                setup="""Services -> Services -> System Log: Syslogd Enable, Remote Server {MON} (port 514 on most builds:
  forward it with a relay or map 514 -> {SYSLOG} on the monitor)
Security -> Log: Enable, Log level High, Dropped/Rejected: Enable
Services -> Services -> RFlow / MACupd: RFlow Enable, Server IP {MON}, Port {FLOW}"""),
    "sophos": _p("Sophos Firewall (SFOS)", PARTIAL, (None, None, None, None), (True, True, True), (True, True),
                 parser="kv", categories=("traffic", "ids", "auth", "vpn", "config", "threat", "system"), decisions=True,
                 api="XML API (not used yet)",
                 notes="Device standard (key=value) syslog format, both the pre-19.5 and the 19.5+ field names. "
                       "Flow export depends on the SFOS version: check the Devices page.",
                 setup="""System services -> Log settings -> Syslog servers -> Add
  IP {MON}, port {SYSLOG}, protocol TCP (or TLS), format Device standard format
  Select Firewall, IPS, Anti-virus, Authentication, Admin, VPN, System events"""),
    "sonicwall": _p("SonicWall (SonicOS)", PARTIAL, (True, True, True, False), (True, True, False), (True, True),
                    parser="kv", categories=("traffic", "ids", "auth", "vpn", "system"), decisions=True,
                    notes="Default/Enhanced syslog (id=firewall ... m=NNN ...). The action is taken from fw_action when "
                          "present, else from the message text. AppFlow exports NetFlow v5/v9 and IPFIX.",
                    setup="""Device -> Log -> Syslog -> Syslog Servers -> Add: {MON}, port {SYSLOG}, format Enhanced Syslog
Device -> Log -> Settings: enable syslog for Security Services, Users, VPN, Network
AppFlow -> Flow Reporting -> External collector: NetFlow v9 or IPFIX, {MON}:{FLOW}"""),
    "watchguard": _p("WatchGuard Firebox", PARTIAL, (None, None, None, None), (True, True, True), (True, True),
                     parser="watchguard", categories=("traffic", "system"), decisions=True,
                     notes="Traffic log lines with msg_id 3000-0148 (deny) / 3000-0151 (allow) and positional fields. "
                           "Flow export is not documented for Fireware: shown as unknown.",
                     setup="""System -> Logging -> Syslog Server: Enable, IP {MON}, port {SYSLOG}, log format Syslog
Enable 'Send a log message' on the policies whose traffic you want to see"""),
    "checkpoint": _p("Check Point (Gaia)", PARTIAL, (True, True, False, False), (True, True, True), (True, True),
                     parser="kv", categories=("traffic", "ids", "threat", "vpn", "auth", "system"), decisions=True,
                     notes="Log Exporter in syslog format (key:\"value\"; pairs). NetFlow v5/v9 from Gaia.",
                     setup="""cp_log_export add name m0nitor target-server {MON} target-port {SYSLOG} protocol tcp format syslog read-mode semi-unified
cp_log_export restart name m0nitor
# Gaia NetFlow: set netflow collector ip {MON} port {FLOW} export-format Netflow_V9 ; save config"""),
    "huawei": _p("Huawei (USG / AR / CE)", PARTIAL, (True, True, True, None), (True, True, None), (True, True),
                 parser="huawei", categories=("traffic", "auth", "config", "interface", "system"), decisions=True,
                 notes="USG POLICYPERMIT/POLICYDENY session logs and common SHELL/IFNET events. NetStream exports "
                       "NetFlow v5/v9/IPFIX; sFlow on CE/S switches.",
                 setup="""info-center enable
info-center loghost {MON} port {SYSLOG}       # syntax and options vary by series and version
security-policy -> rule <name> -> session logging"""),
    "aruba": _p("HPE Aruba (CX / AOS-S)", GENERIC, (False, None, None, True), (True, None, None), (True, True),
                parser="generic", categories=("interface", "auth", "system"),
                notes="Switches: sFlow v5 for traffic, SNMP for counters, generic syslog stored as system events. "
                      "No firewall decisions.",
                setup="""sflow collector {MON} port {SFLOW}
sflow enable
logging {MON} udp {SYSLOG}"""),
    "omada": _p("TP-Link Omada", GENERIC, (False, False, False, False), (True, False, False), (True, None),
                parser="generic", categories=("interface", "auth", "system"),
                notes="Remote syslog from the controller/gateway is stored as generic system events. No documented flow export.",
                setup="Omada Controller -> Settings -> Services -> Remote Logging: Enable, server {MON}, port {SYSLOG}"),
    "generic": _p("Generic router / switch / firewall", GENERIC, (True, True, True, True), (True, True, False), (True, True),
                  parser="generic", categories=("interface", "auth", "routing", "system"), decisions=False,
                  notes="Any device that sends NetFlow v5/v9, IPFIX or sFlow, standard syslog and SNMP. Syslog is stored "
                        "and categorized by keyword only; no allow/deny decisions are derived from generic logs.",
                  setup="""Flows:  NetFlow v5/v9 or IPFIX -> {MON}:{FLOW}, sFlow -> {MON}:{SFLOW}
Syslog: RFC 3164 or RFC 5424 -> {MON}:{SYSLOG} (TCP preferred)
SNMP:   read-only v3 user (authPriv) or v2c community"""),
}


def profile(vendor):
    return PROFILES.get(vendor or "generic") or PROFILES["generic"]


def setup_text(vendor, monitor):
    p = profile(vendor)
    return (p["setup"].replace("{MON}", monitor or "MONITOR").replace("{SYSLOG}", str(PORTS["syslog"]))
            .replace("{FLOW}", str(PORTS["netflow"])).replace("{SFLOW}", str(PORTS["sflow"])))


def cap_label(v):
    return "yes" if v is True else "no" if v is False else "unknown"


def matrix_markdown():
    """The docs/vendors.md table, generated from PROFILES (tests/test_vendors.py keeps the document in sync)."""
    head = ("| Device | Status | NetFlow v5 | NetFlow v9 | IPFIX | sFlow | Syslog UDP/TCP/TLS | SNMP v2c/v3 | "
            "Parsed categories | Firewall decisions | Enforcement |")
    rows = [head, "|" + "---|" * 11]
    for k, p in PROFILES.items():
        f, s, n = p["flows"], p["syslog"], p["snmp"]
        rows.append(f"| {p['name']} (`{k}`) | {p['status']} | " + " | ".join(cap_label(f[x]) for x in FLOW_PROTOCOLS) +
                    f" | {'/'.join(cap_label(s[x]) for x in SYSLOG_TRANSPORTS)} | {'/'.join(cap_label(n[x]) for x in ('v2c', 'v3'))} | "
                    f"{', '.join(p['categories']) or '—'} | {'yes' if p['decisions'] else 'no'} | {p['response'] or '—'} |")
    return "\n".join(rows)
