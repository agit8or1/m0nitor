"""Settings -> Devices: onboarding validation, ownership rules, capability display and RBAC (synthetic data)."""
import json

from netmon import devices, web
from netmon.core import get_setting
from urllib.parse import unquote

from test_web import ADMINPW, VIEWPW, client, sid

BASE = {"vendor": "fortigate", "did": "fgt-a", "name": "Branch FortiGate", "site": "site-a", "exporter_ip": "192.0.2.10",
        "syslog_source": "192.0.2.10", "syslog_transport": "tcp", "flow_netflow_v9": "1", "wan_if": "wan1"}


def post(c, url, data):
    return c.post(url, data={**data, "csrf": web.csrf_token(sid(c))}, follow_redirects=False)


def test_add_view_edit_delete_device_and_host_export():
    a = client("admin", ADMINPW)
    r = post(a, "/netmon/settings/devices/add", BASE)
    assert r.status_code == 303 and "/netmon/settings/devices/fgt-a" in r.headers["location"], r.text
    d = devices.device(web.cfg, "fgt-a")
    assert d and d["site"] == "site-a" and d["flows"] == ["netflow_v9"] and not d["primary"]
    assert devices.sender_map(web.cfg)["192.0.2.10"]["id"] == "fgt-a"
    from netmon.admin import HOST_JSON
    host = json.load(open(HOST_JSON))
    assert {"id": "fgt-a", "site": "site-a", "exporter_ip": "192.0.2.10", "syslog_source": "192.0.2.10", "sflow": False} in host["devices"]
    page = a.get("/netmon/settings/devices/fgt-a").text
    assert "Fortinet FortiGate" in page and "PARTIAL" in page and "config log syslogd setting" in page
    assert "Enforcement (blocking)" in page and "not implemented for this vendor" in page
    lst = a.get("/netmon/settings/devices").text
    assert "Branch FortiGate" in lst and "site firewall" in lst
    api = a.get("/netmon/api/devices").json()
    fg = next(x for x in api if x["id"] == "fgt-a")
    syslog = next(p for p in fg["protocols"] if p["protocol"] == "Syslog")
    assert syslog["configured"] and syslog["active"] is not True        # nothing arrived: never shown as working
    r = post(a, "/netmon/settings/devices/fgt-a", {**BASE, "name": "Renamed"})
    assert r.status_code == 303 and devices.device(web.cfg, "fgt-a")["name"] == "Renamed"
    r = post(a, "/netmon/settings/devices/fgt-a/delete", {})
    assert r.status_code == 303 and devices.device(web.cfg, "fgt-a") is None


def test_validation_rules():
    a = client("admin", ADMINPW)
    post(a, "/netmon/settings/devices/add", BASE)
    cases = [({**BASE, "did": "dup-sender"}, "already belongs to"),                       # one sender, one device
             ({**BASE, "did": "x1", "exporter_ip": "192.0.2.11", "syslog_source": "", "flow_netflow_v9": "", "flow_netflow_v5": "1"}, "does not offer"),
             ({**BASE, "did": "x2", "exporter_ip": "", "syslog_source": "", "flow_netflow_v9": ""}, "flow source IP, a syslog source IP"),
             ({**BASE, "did": "x3", "exporter_ip": "192.0.2.12", "syslog_source": "192.0.2.12", "syslog_transport": "tls"}, "TLS syslog"),
             ({**BASE, "did": "x4", "exporter_ip": "127.0.0.1", "syslog_source": ""}, "not a usable sender"),
             ({**BASE, "did": "site-a"}, "already used"),
             ({**BASE, "did": "x5", "exporter_ip": "192.0.2.13", "syslog_source": "", "snmp_host": "192.0.2.13", "snmp_version": "v3",
               "snmp_ifs": "wan=1", "snmp_user": "mon", "snmp_auth_pass": "short", "snmp_priv_pass": "short"}, "8+ characters")]
    for form, err in cases:
        r = post(a, "/netmon/settings/devices/add", form)
        assert r.status_code == 303 and "Not%20saved" in r.headers["location"], form
        assert unquote(r.headers["location"]).find(err) > 0, (err, r.headers["location"])
    post(a, "/netmon/settings/devices/fgt-a/delete", {})


def test_snmpv3_credentials_stored_as_secret_not_in_settings():
    a = client("admin", ADMINPW)
    form = {**BASE, "did": "sw-v3", "vendor": "aruba", "exporter_ip": "192.0.2.31", "syslog_source": "", "flow_netflow_v9": "",
            "flow_sflow": "1", "snmp_host": "192.0.2.31", "snmp_version": "v3", "snmp_ifs": "uplink=49",
            "snmp_user": "m0nitor", "snmp_auth_pass": "auth-passphrase-1", "snmp_priv_pass": "priv-passphrase-2"}
    r = post(a, "/netmon/settings/devices/add", form)
    assert r.status_code == 303 and "Not" not in r.headers["location"], r.headers["location"]
    stored = json.dumps(get_setting(web.conn, devices.DEV_KEY))
    assert "auth-passphrase-1" not in stored and "priv-passphrase-2" not in stored and "v3_file" in stored
    assert "auth-passphrase-1" not in a.get("/netmon/settings/devices/sw-v3").text
    from netmon.counters import auth_args
    args = auth_args(devices.device(web.cfg, "sw-v3")["snmp"])
    assert args[:4] == ["-v3", "-l", "authPriv", "-u"] and "auth-passphrase-1" in args
    post(a, "/netmon/settings/devices/sw-v3/delete", {})


def test_viewer_can_read_not_write():
    v = client("viewer1", VIEWPW)
    assert v.get("/netmon/settings/devices").status_code == 200
    assert "Add a device" not in v.get("/netmon/settings/devices").text
    assert post(v, "/netmon/settings/devices/add", BASE).status_code == 403
    assert devices.device(web.cfg, "fgt-a") is None


def test_site_firewall_of_other_vendor_cannot_enable_blocking():
    from netmon.admin import build_site
    form = {"vendor": "panos", "sid": "pa", "name": "PA", "exporter_ip": "192.0.2.50", "wan_if": "eth1", "lan_if": "eth2",
            "wan_idx": "1", "lan_idx": "2", "block_url": "https://192.0.2.50"}
    try:
        build_site(form)
        raise AssertionError("blocking accepted for a vendor without an adapter")
    except ValueError as ex:
        assert "not implemented" in str(ex)
    assert build_site({**form, "block_url": ""})["vendor"] == "panos"


# ---- live status: evidence rules -----------------------------------------------------------------------------------
def _dev(flows):
    return {"id": "sw1", "site": "site-a", "vendor": "aruba", "exporter_ip": "192.0.2.40", "flows": flows}


def _row(st, proto):
    return next(r for r in st["rows"] if r["protocol"] == proto)


def test_flow_status_without_collector_counters(cfg, conn):
    import time
    fresh = {"192.0.2.40": {"addr": "192.0.2.40", "last": int(time.time()) - 20, "flows": 300}}
    # only one protocol set up and flows arrive: active, with the caveat in the evidence
    st = devices.status_of(cfg, conn, None, _dev(["sflow"]), flows=fresh, logs={}, metrics={})
    assert _row(st, "sFlow")["active"] is True and "not confirmed" in _row(st, "sFlow")["evidence"]
    # two protocols set up: which one arrives is unknown, never "no data"
    st = devices.status_of(cfg, conn, None, _dev(["sflow", "ipfix"]), flows=fresh, logs={}, metrics={})
    assert _row(st, "sFlow")["active"] is None and _row(st, "IPFIX")["active"] is None
    # nothing arriving: no data
    st = devices.status_of(cfg, conn, None, _dev(["sflow"]), flows={}, logs={}, metrics={})
    assert _row(st, "sFlow")["active"] is False
    # ClickHouse unreachable: unknown
    st = devices.status_of(cfg, conn, None, _dev(["sflow"]), flows=None, logs=None, metrics={})
    assert _row(st, "sFlow")["active"] is None
    # counters available: they decide, flows of another protocol do not count
    m = {"192.0.2.40": {"versions": {"ipfix"}, "packets": {}, "templates": set(), "sflow": 0, "errors": {}}}
    st = devices.status_of(cfg, conn, None, _dev(["sflow"]), flows=fresh, logs={}, metrics=m)
    assert _row(st, "sFlow")["active"] is False and _row(st, "IPFIX")["active"] is True


def test_log_activity_attributes_rows_without_device_to_site_firewall():
    class CH:
        def query(self, sql, params):
            self.sql = sql
            return [{"d": "site-a", "t": 1793448000}]
    ch = CH()
    assert devices.log_activity(ch) == {"site-a": 1793448000}
    assert ch.sql.count("if(device = '', site, device)") == 5      # all five event tables
