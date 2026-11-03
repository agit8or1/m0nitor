"""What a server does, for AI calibration: the role an admin declared (Settings → Inventory) plus the services it was
actually seen serving and using over the last 7 days. Inbound SMTP is routine for a mail server and suspicious for a
backup box; the model can only weigh that if it knows which one it is looking at."""
from .core import PROTO, expected_devices, expected_match

# (proto, port) -> function. Only well-known ones; anything else is reported as a bare port.
FUNCTIONS = {
    ("tcp", 25): "mail (SMTP)", ("tcp", 465): "mail (SMTPS)", ("tcp", 587): "mail (submission)",
    ("tcp", 110): "mail (POP3)", ("tcp", 995): "mail (POP3S)", ("tcp", 143): "mail (IMAP)", ("tcp", 993): "mail (IMAPS)",
    ("tcp", 80): "web (HTTP)", ("tcp", 443): "web (HTTPS)", ("udp", 443): "web (HTTP/3)", ("tcp", 8080): "web (HTTP alt)",
    ("tcp", 8443): "web (HTTPS alt)", ("tcp", 53): "dns", ("udp", 53): "dns", ("tcp", 853): "dns (DoT)",
    ("tcp", 22): "ssh", ("tcp", 2222): "ssh", ("tcp", 3389): "remote desktop (RDP)", ("tcp", 5900): "remote desktop (VNC)",
    ("tcp", 21): "ftp", ("tcp", 8006): "hypervisor UI (Proxmox VE)", ("tcp", 8007): "backup server UI (Proxmox Backup)",
    ("tcp", 10000): "admin panel (Webmin)", ("tcp", 9090): "admin panel", ("tcp", 2083): "admin panel (cPanel)",
    ("tcp", 2087): "admin panel (WHM)",
    ("udp", 51820): "vpn (WireGuard)", ("udp", 1194): "vpn (OpenVPN)", ("tcp", 1194): "vpn (OpenVPN)",
    ("udp", 500): "vpn (IPsec)", ("udp", 4500): "vpn (IPsec)",
    ("tcp", 3306): "database (MySQL)", ("tcp", 5432): "database (PostgreSQL)", ("tcp", 1433): "database (MSSQL)",
    ("tcp", 6379): "database (Redis)", ("tcp", 27017): "database (MongoDB)",
    ("tcp", 445): "file sharing (SMB)", ("tcp", 2049): "file sharing (NFS)", ("tcp", 873): "file sync (rsync)",
    ("udp", 123): "time (NTP)", ("udp", 161): "snmp", ("tcp", 389): "directory (LDAP)", ("tcp", 636): "directory (LDAPS)",
    ("tcp", 3478): "voice/video (STUN/TURN)", ("udp", 3478): "voice/video (STUN/TURN)", ("udp", 5060): "voip (SIP)",
}

MIN_CLIENTS = 3      # a port counts as "served" only if several distinct remotes completed connections to it


def function_of(proto, port):
    return FUNCTIONS.get((proto, int(port)), f"{proto}/{int(port)}")


def classify(served, used):
    """served/used: [{proto, port, peers, flows}] -> observed functions, most peers first, plus a summary role.
    served = ports remote clients connected to on this server; used = remote services this server connected to."""
    def fold(rows, min_peers):
        out = {}
        for r in rows:
            if r["peers"] < min_peers or r["proto"] not in ("tcp", "udp"):
                continue
            f = function_of(r["proto"], r["port"])
            o = out.setdefault(f, {"function": f, "ports": [], "peers": 0, "flows": 0})
            o["ports"].append(f"{r['proto']}/{r['port']}")
            o["peers"] += int(r["peers"])
            o["flows"] += int(r["flows"])
        return sorted(out.values(), key=lambda x: -x["peers"])[:6]
    srv, use = fold(served, MIN_CLIENTS), fold(used, 1)
    families = sorted({s["function"].split(" (")[0] for s in srv if not s["function"].startswith(("tcp/", "udp/"))})
    return {"observed_serves": srv, "observed_uses": use, "observed_role": "+".join(families) or "no public service seen"}


def observed(dash, ip, site="all"):
    """Services seen over 7 days at the WAN boundary, from inbound records only (exact for one LAN host, even behind
    the shared NAT): remote -> host:port with an ACK is a served connection; remote:well-known port -> host:high port
    is a reply to a connection the host opened (a service it uses). Bare SYNs (scans) and ICMP are not counted."""
    sc = dash.scope(site=site, range_key="7d", host=ip)
    served = dash.q(sc, f"""
        SELECT Proto AS proto, DstPort AS port, uniq(SrcAddr) AS peers, count() AS flows
        FROM flows WHERE {dash.where(sc)} AND INB AND TOLAN AND Proto IN (6, 17) AND DstPort < 32768
          AND (Proto != 6 OR bitAnd(TCPFlags, 16) != 0)
        GROUP BY proto, port ORDER BY peers DESC LIMIT 25""", ttl=600)
    used = dash.q(sc, f"""
        SELECT Proto AS proto, SrcPort AS port, uniq(SrcAddr) AS peers, count() AS flows
        FROM flows WHERE {dash.where(sc)} AND INB AND TOLAN AND Proto IN (6, 17) AND DstPort >= 1024
          AND (SrcPort < 1024 OR has({{svc:Array(UInt16)}}, SrcPort))
        GROUP BY proto, port ORDER BY peers DESC LIMIT 25""", ttl=600)
    norm = lambda rows: [{"proto": PROTO.get(r["proto"], str(r["proto"])), "port": int(r["port"]), "peers": int(r["peers"]),
                          "flows": int(r["flows"])} for r in rows]
    return classify(norm(served), norm(used))


def server_profile(cfg, conn, dash, ip):
    """Declared + observed function of an internal server. Never raises: the profile is context, not evidence."""
    a = cfg.get("assets", {}).get(ip) or {}
    out = {"declared_role": a.get("role") or "not set", "software": a.get("software", []),
           "sensitive": bool(a.get("sensitive"))}
    if a.get("notes"):
        out["admin_notes"] = str(a["notes"])[:200]
    exp = expected_devices(conn)
    t = expected_match(exp, ip)
    if t:
        out["expected_device"] = exp[t].get("reason") or "marked expected by an admin"
    if dash is not None:
        try:
            out |= observed(dash, ip)
        except Exception as ex:   # ClickHouse down: say so instead of failing the preview
            out["observed_role"] = f"unavailable ({type(ex).__name__})"
    return out
