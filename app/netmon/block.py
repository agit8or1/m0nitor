"""Approval-gated blocking on one fixed alias per firewall (site).

OPNsense — verified on 26.7.7 (AliasUtilController.php): POST /api/firewall/alias_util/add/<alias> and
/delete/<alias> with form field `address`. For Host/Network aliases the change is written to config and the
pf table. Privilege: "Diagnostics: PF Table IP addresses" (covers all aliases, so the alias name is fixed
in config and never taken from user input).

pfSense — needs the pfSense REST API package (pfrest.org, pfSense-pkg-RESTAPI v2). GET
/api/v2/firewall/aliases?name=<alias> finds the alias; PATCH /api/v2/firewall/alias {id, address} replaces
its address list and the model reloads the filter. Auth: header X-API-Key. Privileges:
api-v2-firewall-aliases-get, api-v2-firewall-alias-patch. pfSense has no add/remove-one call, so the
list is read, changed and written back under a per-site lock.
"""
import ipaddress
import json
import ssl
import time

import httpx

from . import secretbox
from .core import audit


class BlockError(Exception):
    pass


def validate_target(cfg, address: str) -> str:
    """Return normalized address/CIDR or raise BlockError if it must not be blocked."""
    oc = cfg.get("blocking") or cfg["opnsense"]  # guardrails apply to every firewall
    try:
        net = ipaddress.ip_network(address.strip(), strict=False)
    except ValueError:
        raise BlockError("not an IP address or CIDR")
    minp = oc["min_prefix_v4"] if net.version == 4 else oc["min_prefix_v6"]
    if net.prefixlen < minp:
        raise BlockError(f"prefix /{net.prefixlen} is broader than the allowed /{minp}")
    for n in cfg.internal_nets + cfg.public_nets:
        if net.version == n.version and net.overlaps(n):
            raise BlockError(f"overlaps our own network {n}")
    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved \
            or net.is_unspecified:
        raise BlockError("private/special-purpose range")
    for p in oc.get("protected", []):
        pn = ipaddress.ip_network(p, strict=False)
        if net.version == pn.version and net.overlaps(pn):
            raise BlockError(f"overlaps protected address {p} (DNS/gateway/management)")
    is_host = net.prefixlen == net.max_prefixlen
    return str(net.network_address) if is_host else str(net)


def read_key(path):
    text = secretbox.read_file(path)
    if not text:
        return None
    if "secret=" in text:  # OPNsense apikey.txt download: key=...\nsecret=...
        kv = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        return (kv.get("key", ""), kv.get("secret", ""))
    key, sep, secret = text.partition(":")
    return (key, secret) if sep else (text, "")


class Enforcer:
    vendor = "?"

    def __init__(self, site):
        self.site = site
        self.bc = site.get("block") or {}
        self.alias = self.bc.get("block_alias", "netmon_block")
        self.base_url = self.bc.get("base_url", "")

    def creds(self):
        return read_key(self.bc.get("key_file"))

    @property
    def enabled(self) -> bool:
        c = self.creds()
        return bool(self.base_url and c and c[0])

    def _client(self):
        ctx = ssl.create_default_context(cafile=self.bc.get("ca_file") or None)  # full verification
        return httpx.Client(base_url=self.base_url, verify=ctx, timeout=20, **self._auth())

    def _call(self, method, path, data=None, json_=None, params=None):
        ext, hdr = {}, {}
        if self.bc.get("tls_server_name"):
            ext, hdr = {"sni_hostname": self.bc["tls_server_name"]}, {"Host": self.bc["tls_server_name"]}
        with self._client() as c:
            r = c.request(method, path, data=data, json=json_, params=params, extensions=ext, headers=hdr)
        if r.status_code != 200:
            raise BlockError(f"{self.vendor} HTTP {r.status_code}: {r.text[:200]}")
        return r.json()


# netmon-owned objects on OPNsense. Rules are floating (evaluated before every interface rule), quick, and only ever
# reference netmon's own aliases, which can hold external addresses only (validate_target). The app touches a rule
# only if its UUID is recorded in netmon's DB *and* its description still starts with OWN_PREFIX.
OWN_PREFIX = "netmon:"
AUTO_ALIAS = "netmon_auto"
CATEGORY = "netmon"
RULE_SPECS = [
    # key, alias setting, side, description
    ("block_in", "block", "source", "manual blocks: traffic from blocked addresses"),
    ("block_out", "block", "destination", "manual blocks: traffic to blocked addresses"),
    ("auto_in", "auto", "source", "auto-response: traffic from auto-blocked addresses"),
    ("auto_out", "auto", "destination", "auto-response: traffic to auto-blocked addresses"),
]


class OPNsense(Enforcer):
    vendor = "OPNsense"

    def _auth(self):
        return {"auth": self.creds()}

    @property
    def auto_alias(self):
        return self.bc.get("auto_alias", AUTO_ALIAS)

    def alias_exists(self, name=None) -> bool:
        return (name or self.alias) in self._call("GET", "/api/firewall/alias_util/aliases")

    def list(self, name=None):
        return self._call("GET", f"/api/firewall/alias_util/list/{name or self.alias}")

    def add(self, address, name=None):
        res = self._call("POST", f"/api/firewall/alias_util/add/{name or self.alias}", {"address": address})
        return res.get("status") == "done", res

    def delete(self, address, name=None):
        return self._call("POST", f"/api/firewall/alias_util/delete/{name or self.alias}", {"address": address})

    # ---- netmon-owned firewall objects ----
    def plan(self, state):
        """What setup() would create, as reviewable rows. `state` = netmon's record of objects it created."""
        names = {"block": self.alias, "auto": self.auto_alias}
        rows = [{"kind": "category", "name": CATEGORY, "exists": bool(state.get("category"))}]
        rows += [{"kind": "alias", "name": n, "detail": "Host(s) alias, empty", "exists": bool(state.get("aliases", {}).get(n))}
                 for n in names.values()]
        for key, a, side, desc in RULE_SPECS:
            rows.append({"kind": "rule", "key": key, "name": f"{OWN_PREFIX} {desc}", "exists": bool(state.get("rules", {}).get(key)),
                         "detail": f"Floating · quick · block · in · any interface · IPv4+IPv6 · {side} = {names[a]} · logged"})
        return rows

    def _find(self, rows, name):
        return next((x for x in rows if x.get("name") == name), None)

    def setup(self, state):
        """Create the netmon category, aliases and rules that are missing. Never edits anything else.
        Returns the updated state and a list of what was done. On failure the BlockError carries .state/.done
        with whatever was created, so a retry never duplicates rules."""
        state = {"category": state.get("category"), "aliases": dict(state.get("aliases") or {}), "rules": dict(state.get("rules") or {})}
        done = []
        try:
            return self._setup(state, done)
        except Exception as ex:
            err = ex if isinstance(ex, BlockError) else BlockError(str(ex))
            err.state, err.done = state, done
            raise err

    def _setup(self, state, done):
        cats = self._call("GET", "/api/firewall/category/search_item").get("rows", [])
        c = self._find(cats, CATEGORY)
        if not c:
            r = self._call("POST", "/api/firewall/category/add_item", json_={"category": {"name": CATEGORY, "auto": "0", "color": "2459d3"}})
            if r.get("result") != "saved":
                raise BlockError(f"category not created: {str(r)[:200]}")
            c = {"uuid": r["uuid"]}
            done.append(f"created category {CATEGORY}")
        state["category"] = c["uuid"]
        aliases = self._call("GET", "/api/firewall/alias/search_item", params={"rowCount": "-1"}).get("rows", [])
        for n, what in ((self.alias, "manual blocks"), (self.auto_alias, "auto-response blocks, with expiry")):
            a = self._find(aliases, n)
            if a and a.get("type") not in ("host", "network"):
                raise BlockError(f"alias {n} exists with type {a.get('type')}; rename it or set a different alias name")
            if not a:
                r = self._call("POST", "/api/firewall/alias/add_item", json_={"alias": {
                    "enabled": "1", "name": n, "type": "host", "content": "", "categories": state["category"],
                    "description": f"{OWN_PREFIX} {what} (managed by netmon)"}})
                if r.get("result") != "saved":
                    raise BlockError(f"alias {n} not created: {str(r)[:200]}")
                a = {"uuid": r["uuid"]}
                done.append(f"created alias {n}")
            state["aliases"][n] = a["uuid"]
        if done:
            self._call("POST", "/api/firewall/alias/reconfigure")
        names = {"block": self.alias, "auto": self.auto_alias}
        for i, (key, a, side, desc) in enumerate(RULE_SPECS):
            if state["rules"].get(key) and self.rule(state["rules"][key]):
                continue
            body = {"enabled": "1", "action": "block", "quick": "1", "interface": "", "direction": "in", "ipprotocol": "inet46",
                    "protocol": "any", "source_net": "any", "destination_net": "any", f"{side}_net": names[a], "log": "1",
                    "sequence": str(i + 1), "categories": state["category"], "description": f"{OWN_PREFIX} {desc}"}
            r = self._call("POST", "/api/firewall/filter/add_rule", json_={"rule": body})
            if r.get("result") != "saved":
                raise BlockError(f"rule {key} not created: {str(r)[:300]}")
            state["rules"][key] = r["uuid"]
            done.append(f"created rule “{OWN_PREFIX} {desc}”")
        if any(x.startswith("created rule") for x in done):
            self.apply()
        return state, done

    def rule(self, uuid):
        """A netmon rule as {enabled, description}, or None if it is gone or no longer netmon's."""
        r = (self._call("GET", f"/api/firewall/filter/get_rule/{uuid}") or {}).get("rule") or {}
        desc = r.get("description", "")
        if not desc.startswith(OWN_PREFIX):
            return None
        return {"enabled": r.get("enabled") == "1", "description": desc}

    def toggle(self, state, key, enabled: bool):
        uuid = (state.get("rules") or {}).get(key)
        if not uuid or not self.rule(uuid):
            raise BlockError("not a netmon rule (run setup again)")
        r = self._call("POST", f"/api/firewall/filter/toggle_rule/{uuid}/{1 if enabled else 0}")
        if r.get("result") not in ("Enabled", "Disabled"):
            raise BlockError(f"toggle failed: {str(r)[:200]}")
        self.apply()
        return r["result"]

    def apply(self):
        return self._call("POST", "/api/firewall/filter/apply")

    def kill_states(self, address, cap=300):
        """Drop pf states whose source or destination is exactly `address` (query, then delete by id;
        the filter-based kill_states call matches substrings, so 1.2.3.4 would also hit 1.2.3.45)."""
        rows = self._call("POST", "/api/diagnostics/firewall/query_states",
                          data={"searchPhrase": address, "rowCount": str(cap), "current": "1"}).get("rows", [])
        n = 0
        for s in rows:
            if address in (s.get("src_addr"), s.get("dst_addr"), s.get("nat_addr")) and "/" in str(s.get("id", "")):
                sid, creator = s["id"].split("/", 1)
                self._call("POST", f"/api/diagnostics/firewall/del_state/{sid}/{creator}")
                n += 1
        return n

    def describe(self, address, op="add"):
        return f"POST {self.base_url}/api/firewall/alias_util/{op}/{self.alias}  address={address}"


class PfSense(Enforcer):
    vendor = "pfSense"
    _locks: dict = {}

    def _auth(self):
        return {"headers": {"X-API-Key": self.creds()[0]}}

    auto_alias = AUTO_ALIAS

    def _alias(self, name=None):
        name = name or self.alias
        d = self._call("GET", "/api/v2/firewall/aliases", params={"name": name}).get("data") or []
        m = [a for a in d if a.get("name") == name]
        if not m:
            raise BlockError(f"alias {name} does not exist on pfSense; create it first (docs/BLOCKING.md)")
        return m[0]

    def alias_exists(self, name=None) -> bool:
        try:
            return self._alias(name)["type"] in ("host", "network")
        except BlockError:
            return False

    def list(self, name=None):
        return self._alias(name).get("address") or []

    def _write(self, change, name=None):
        import threading
        with self._locks.setdefault(self.site["id"], threading.Lock()):
            a = self._alias(name)
            addrs, details = list(a.get("address") or []), list(a.get("detail") or [])
            addrs, details = change(addrs, details)
            res = self._call("PATCH", "/api/v2/firewall/alias", json_={"id": a["id"], "address": addrs, "detail": details})
            return res

    def add(self, address, name=None):
        def ch(addrs, det):
            det = (det + [""] * len(addrs))[:len(addrs)]  # pfSense: no more details than addresses
            if address not in addrs:
                addrs.append(address)
                det.append(f"netmon {time.strftime('%Y-%m-%d')}")
            return addrs, det
        res = self._write(ch, name)
        ok = res.get("code") == 200 and address in ((res.get("data") or {}).get("address") or [])
        return ok, res

    def delete(self, address, name=None):
        def ch(addrs, det):
            det = (det + [""] * len(addrs))[:len(addrs)]
            keep = [i for i, a in enumerate(addrs) if a != address]
            return [addrs[i] for i in keep], [det[i] for i in keep]
        return self._write(ch, name)

    def describe(self, address, op="add"):
        return (f"PATCH {self.base_url}/api/v2/firewall/alias  {{id: <{self.alias}>, address: <current list "
                f"{'+' if op == 'add' else '−'} {address}>}}  (pfSense REST API; reloads the filter)")


class Unsupported(Enforcer):
    """Monitoring-only device: no enforcement adapter exists for this vendor. Every write is refused; nothing is ever
    sent to the device. NetFlow/syslog ingestion is never used as a control channel."""

    def __init__(self, site):
        super().__init__(site)
        from .vendors import profile
        self.vendor = profile(site.get("vendor"))["name"]

    @property
    def enabled(self) -> bool:
        return False

    auto_alias = ""

    def describe(self, address, op="add"):
        return f"not available: no enforcement adapter for {self.vendor} (monitoring only)"

    def __getattr__(self, name):   # list/add/delete/setup/... -> refused
        if name.startswith("_"):
            raise AttributeError(name)

        def refuse(*a, **k):
            raise BlockError(f"enforcement is not implemented for {self.vendor}: monitoring only")
        return refuse


ADAPTERS = {"opnsense": OPNsense, "pfsense": PfSense}   # capability-driven: vendors.PROFILES[...]["response"]


def enforcer(site) -> Enforcer:
    from .vendors import profile
    return ADAPTERS.get(profile(site.get("vendor", "opnsense"))["response"] or "", Unsupported)(site)


def preview(cfg, address, site, alias=None):
    fw = enforcer(site)
    if alias:
        fw.alias = alias
    return {
        "api_call": fw.describe(address),
        "effect": f"Adds {address} to Host/Network alias '{fw.alias}' on {site['name']} ({fw.vendor}). Persisted to the "
                  f"firewall config and loaded into the pf table immediately. Enforced by the netmon floating block rules that "
                  f"reference '{fw.alias}' (Settings → Auto-response → Firewall objects); netmon never edits your own rules.",
        "existing_states": "pf block rules do not kill existing states by default: established "
                           "connections to/from this address continue until they close or time out. "
                           "Killing states is a separate manual action (Diagnostics → States).",
        "rollback": f"Remove from this page, or {fw.describe(address, 'delete')}, or "
                    f"Firewall → Aliases → {fw.alias} → edit content.",
    }


def impact(det, address, site, days=7):
    """Historical traffic at `site` that the block would have affected (both directions)."""
    sql = """
    SELECT if(INB, 'inbound', 'outbound') AS dir,
           replaceOne(IPv6NumToString(if(INB, DstAddr, SrcAddr)), '::ffff:', '') AS ours,
           groupUniqArray(10)(DstPort) AS ports,
           count() AS flows, sum(Bytes) AS bytes, toUInt32(max(TimeReceived)) AS last
    FROM flows
    WHERE ExporterName = {exporter:String} AND TimeReceived > now() - INTERVAL {d:UInt32} DAY
      AND ((INB AND isIPAddressInRange(replaceOne(IPv6NumToString(SrcAddr), '::ffff:', ''), {cidr:String}))
        OR (OUTB AND isIPAddressInRange(replaceOne(IPv6NumToString(DstAddr), '::ffff:', ''), {cidr:String})))
    GROUP BY dir, ours ORDER BY bytes DESC LIMIT 50"""
    cidr = address if "/" in address else (address + ("/128" if ":" in address else "/32"))
    prev, det.site = det.site, site
    try:
        rows = det.q(sql, {"d": days, "cidr": cidr})
    finally:
        det.site = prev
    for r in rows:
        r["asset"] = det.cfg.asset_label(r["ours"]) if det.cfg.is_internal(r["ours"]) else r["ours"]
    return rows


def request_block(conn, det, user, address, reason, alert_id=None, sites=None):
    """One pending request per selected site. Returns the first request id."""
    addr = validate_target(det.cfg, address)
    if not reason.strip():
        raise BlockError("a reason is required")
    chosen = [x for x in det.cfg.sites if not sites or x["id"] in sites]
    if not chosen:
        raise BlockError("choose at least one firewall")
    ids = []
    for site in chosen:
        imp = impact(det, addr, site)
        cur = conn.execute("INSERT INTO blocks(address,alias,reason,alert_id,requested_by,requested_at,status,impact,site) "
                           "VALUES (?,?,?,?,?,?,?,?,?)",
                           (addr, enforcer(site).alias, reason.strip()[:500], alert_id, user, time.time(),
                            "pending", json.dumps(imp, default=str), site["id"]))
        ids.append(cur.lastrowid)
        audit(conn, user, "block_requested", {"id": cur.lastrowid, "address": addr, "site": site["id"], "reason": reason[:500]})
    conn.commit()
    return ids[0]


def site_of_block(cfg, b):
    s = cfg.site(b["site"]) if b["site"] else cfg.sites[0]
    if not s:
        raise BlockError(f"firewall {b['site']} is no longer configured")
    return s


def apply_block(conn, cfg, user, block_id):
    b = conn.execute("SELECT * FROM blocks WHERE id=?", (block_id,)).fetchone()
    if not b or b["status"] != "pending":
        raise BlockError("block is not pending")
    validate_target(cfg, b["address"])  # re-check guardrails at apply time
    site = site_of_block(cfg, b)
    fw = enforcer(site)
    if not fw.enabled:
        raise BlockError(f"no enforcement API key configured for {site['name']} (Settings → Firewalls)")
    if not fw.alias_exists():
        raise BlockError(f"alias {fw.alias} does not exist on {site['name']}; create it first (docs/BLOCKING.md)")
    try:
        ok, res = fw.add(b["address"])
    except Exception as e:
        res, ok = {"error": str(e)}, False
    conn.execute("UPDATE blocks SET status=?, approved_by=?, applied_at=?, result=? WHERE id=?",
                 ("applied" if ok else "failed", user, time.time(), json.dumps(res, default=str)[:4000], block_id))
    conn.commit()
    audit(conn, user, "block_applied" if ok else "block_failed", {"id": block_id, "address": b["address"], "site": site["id"]})
    if not ok:
        raise BlockError(f"{fw.vendor} did not confirm: {str(res)[:300]}")


def remove_block(conn, cfg, user, block_id):
    b = conn.execute("SELECT * FROM blocks WHERE id=?", (block_id,)).fetchone()
    if not b:
        raise BlockError("no such block")
    if b["status"] == "pending":
        conn.execute("UPDATE blocks SET status='rejected', removed_by=?, removed_at=? WHERE id=?",
                     (user, time.time(), block_id))
        conn.commit()
        audit(conn, user, "block_rejected", {"id": block_id, "address": b["address"]})
        return
    if b["status"] != "applied":
        raise BlockError("block is not active")
    site = site_of_block(cfg, b)
    res = enforcer(site).delete(b["address"], b["alias"])
    conn.execute("UPDATE blocks SET status='removed', removed_by=?, removed_at=?, result=? WHERE id=?",
                 (user, time.time(), json.dumps(res, default=str)[:4000], block_id))
    conn.commit()
    audit(conn, user, "block_removed", {"id": block_id, "address": b["address"], "site": site["id"]})
