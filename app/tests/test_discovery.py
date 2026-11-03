from netmon import discovery


def test_merge_adds_new_fills_empty_and_never_overwrites():
    db = {"10.40.0.240": {"name": "mail-1", "role": "mail+dns", "sensitive": False, "notes": ""},
          "10.40.0.8": {"name": "backup-1", "role": "backup", "sensitive": True, "notes": "", "kind": "physical server"}}
    seen = {"10.40.0.240": 100, "10.40.0.50": 200}
    arp = {"10.40.0.240": {"mac": "bc:24:11:5a:b7:d9", "vendor": "Proxmox Server Solutions", "hostname": "", "site": "site-a"},
           "10.40.0.8": {"mac": "bc:24:11:00:00:08", "vendor": "", "hostname": "", "site": "site-a"},
           "10.40.0.60": {"mac": "e4:43:4b:8a:e0:aa", "vendor": "Dell Inc.", "hostname": "idrac-1.lan", "site": "site-a"},
           "10.40.0.61": {"mac": "00:50:56:01:02:03", "vendor": "VMware", "hostname": "bad name <x>", "site": "site-a"}}
    db, added, filled = discovery.merge(db, seen, arp, 1000)
    assert added == ["10.40.0.50", "10.40.0.60", "10.40.0.61"]
    assert db["10.40.0.50"] == {"name": "10.40.0.50", "role": "", "sensitive": False, "source": "auto", "discovered": 1000,
                                "notes": "auto-discovered from traffic", "last_seen": 200}
    assert db["10.40.0.60"]["name"] == "idrac-1.lan" and "kind" not in db["10.40.0.60"] and db["10.40.0.60"]["vendor"] == "Dell Inc."
    assert db["10.40.0.61"]["name"] == "10.40.0.61" and db["10.40.0.61"]["kind"] == "virtual machine"
    # existing: empty type filled from a virtual MAC, a person's type kept, name/role untouched
    assert db["10.40.0.240"]["kind"] == "virtual machine" and db["10.40.0.240"]["name"] == "mail-1" and "source" not in db["10.40.0.240"]
    assert db["10.40.0.8"]["kind"] == "physical server" and db["10.40.0.8"]["mac"] == "bc:24:11:00:00:08"
    assert len(filled) == 3   # .240 type, .8 MAC, .8 vendor (looked up from the MAC)
    # idempotent
    _, added2, filled2 = discovery.merge(db, seen, arp, 2000)
    assert added2 == [] and filled2 == []


def test_usable_skips_external_and_network_addresses(cfg):
    assert discovery._usable(cfg, "10.40.0.50")
    assert not discovery._usable(cfg, "198.51.100.9") and not discovery._usable(cfg, "10.40.0.0") and not discovery._usable(cfg, "junk")
    assert discovery.norm_mac("BC-24-11-5A-B7-D9") == "bc:24:11:5a:b7:d9" and discovery.norm_mac("x") == ""


def test_manual_edit_makes_entry_yours_and_keeps_mac(monkeypatch):
    from test_web import ADMINPW, client, sid, web
    from netmon.core import put_setting
    db = dict(web.cfg["assets"])
    db["10.40.0.70"] = {"name": "10.40.0.70", "role": "", "sensitive": False, "source": "auto", "notes": "", "mac": "bc:24:11:00:00:70",
                        "kind": "virtual machine", "kind_source": "MAC prefix (Proxmox VE)"}
    put_setting(web.conn, "assets:db", db, "t")
    from netmon.core import apply_assets
    apply_assets(web.cfg, web.conn)
    a = client("admin", ADMINPW)
    tok = web.csrf_token(sid(a))
    page = a.get("/netmon/settings/inventory").text
    assert "auto-discovered" in page and 'id="discovery"' in page and "bc:24:11:00:00:70" in page
    from netmon.profile import server_profile
    p = server_profile(web.cfg, web.conn, None, "10.40.0.70")
    assert p["device_type_source"] == "auto: MAC prefix (Proxmox VE)" and p["entry"].startswith("auto-discovered")
    a.post("/netmon/names", data={"ip": "10.40.0.70", "name": "build-vm", "role": "ci", "kind": "container", "csrf": tok})
    e = web.cfg["assets"]["10.40.0.70"]
    assert e["name"] == "build-vm" and e["kind"] == "container" and e["mac"] == "bc:24:11:00:00:70"
    assert "source" not in e and "kind_source" not in e
    monkeypatch.setattr(discovery, "run", lambda cfg, conn, dash, user: {"added": ["10.40.0.71"], "filled": 0, "error": None})
    r = a.post("/netmon/settings/inventory/discovery", data={"enabled": "1", "act": "run", "csrf": tok}, follow_redirects=False)
    assert "1%20added" in r.headers["location"]
    a.post("/netmon/settings/inventory/discovery", data={"act": "save", "csrf": tok})
    assert not discovery.enabled(web.conn)
    a.post("/netmon/settings/inventory/discovery", data={"enabled": "1", "act": "save", "csrf": tok})
    assert discovery.enabled(web.conn)
    a.post("/netmon/names", data={"ip": "10.40.0.70", "clear": "1", "csrf": tok})


def test_vendor_lookup_categories_and_vendor_types(tmp_path, monkeypatch):
    from netmon import devtypes
    (tmp_path / "oui.csv").write_text("Registry,Assignment,Organization Name,Organization Address\n"
                                      "MA-L,E4434B,Dell Inc.,Round Rock\nMA-L,BCAD28,Hangzhou Hikvision Digital Technology Co.,Ltd.,x\n"
                                      "MA-L,001122,Private,\n")
    (tmp_path / "mam.csv").write_text("Registry,Assignment,Organization Name,Organization Address\nMA-M,E4434B1,Longer Prefix Co,x\n")
    monkeypatch.setattr(devtypes, "OUI_DIR", str(tmp_path))
    monkeypatch.setattr(devtypes, "_db", None)
    assert devtypes.vendor_of("e4:43:4b:8a:e0:aa") == "Dell Inc."
    assert devtypes.vendor_of("e4:43:4b:1a:e0:aa") == "Longer Prefix Co"       # 28-bit assignment beats 24-bit
    assert devtypes.vendor_of("bc:24:11:00:00:01") == "Proxmox VE (virtual NIC)"
    assert devtypes.vendor_of("da:a1:19:00:00:01") == "randomized (private) MAC"
    assert devtypes.vendor_of("00:11:22:33:44:55") == "" and devtypes.vendor_of("zz") == ""
    assert devtypes.type_from_mac("e4:43:4b:8a:e0:aa") == (None, None)          # Dell makes many kinds of devices
    assert devtypes.type_from_mac("bc:ad:28:00:00:01")[0] == "IoT / camera"
    assert devtypes.type_from_mac("52:54:00:00:00:01") == ("virtual machine", "MAC prefix (QEMU/KVM)")
    assert devtypes.category_of("virtual machine") == "Virtual" and devtypes.category_of("") == "Unclassified"
    assert set(devtypes.DEVICE_TYPES) == {t for _, ts in devtypes.CATEGORIES for t in ts}   # every type has a category
    monkeypatch.setattr(devtypes, "_db", None)


def test_inventory_and_devices_page_show_categories():
    from test_web import ADMINPW, client
    a = client("admin", ADMINPW)
    page = a.get("/netmon/settings/inventory").text
    assert "<h2>Internal devices</h2>" in page and 'class="catgroup"' in page and "Unclassified" in page
    assert ">Internal devices<" in a.get("/netmon/servers").text
