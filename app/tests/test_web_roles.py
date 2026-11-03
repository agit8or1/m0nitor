from test_web import ADMINPW, VIEWPW, client, sid, web


def test_bulk_role_assignment_keeps_names_and_adds_unnamed():
    from netmon import inventory
    a = client("admin", ADMINPW)
    tok = web.csrf_token(sid(a))
    page = a.get("/netmon/settings/inventory").text
    assert 'action="/netmon/settings/inventory/roles"' in page and "<datalist id=nm-roles>" in page
    r = a.post("/netmon/settings/inventory/roles", data={"ips": "10.40.0.240, 10.40.0.120/31", "role": "marketing crawler", "csrf": tok},
               follow_redirects=False)
    assert r.status_code == 303 and "1%20address%28es%29%20updated%2C%202%20added" in r.headers["location"]
    assets = web.cfg["assets"]
    assert assets["10.40.0.240"]["name"] == "mail-1" and assets["10.40.0.240"]["role"] == "marketing crawler"
    assert assets["10.40.0.121"] == {"name": "10.40.0.121", "role": "marketing crawler", "sensitive": False, "notes": ""}
    assert "marketing crawler" in inventory.role_options()
    # public addresses and oversized ranges are refused, nothing changes
    r = a.post("/netmon/settings/inventory/roles", data={"ips": "198.51.100.9", "role": "web", "csrf": tok}, follow_redirects=False)
    assert "Not%20saved" in r.headers["location"]
    r = a.post("/netmon/settings/inventory/roles", data={"ips": "10.40.0.0/16", "role": "web", "csrf": tok}, follow_redirects=False)
    assert "Not%20saved" in r.headers["location"]
    # only_named skips unnamed addresses
    a.post("/netmon/settings/inventory/roles", data={"ips": "10.40.0.240 10.40.0.99", "role": "mail", "only_named": "1", "csrf": tok})
    assert web.cfg["assets"]["10.40.0.240"]["role"] == "mail" and "10.40.0.99" not in web.cfg["assets"]
    # viewers cannot
    v = client("viewer1", VIEWPW)
    assert v.post("/netmon/settings/inventory/roles", data={"ips": "10.40.0.240", "role": "x", "csrf": web.csrf_token(sid(v))}).status_code == 403
    for ip in ("10.40.0.120", "10.40.0.121"):
        a.post("/netmon/names", data={"ip": ip, "clear": "1", "csrf": tok})
    a.post("/netmon/names", data={"ip": "10.40.0.240", "name": "mail-1", "role": "mail+dns", "csrf": tok})


def test_role_alone_names_server_under_its_ip_and_suggestion_api(monkeypatch):
    from netmon import inventory
    a = client("admin", ADMINPW)
    tok = web.csrf_token(sid(a))
    r = a.post("/netmon/names", data={"ip": "10.40.0.77", "role": "web", "csrf": tok}, headers={"x-nm-fetch": "1"})
    assert r.json()["name"] == "10.40.0.77" and r.json()["role"] == "web" and "web" in r.json()["role_options"]
    a.post("/netmon/names", data={"ip": "10.40.0.77", "clear": "1", "csrf": tok})
    monkeypatch.setattr(inventory, "suggest_role", lambda ip: {"observed_role": "mail", "serves": ["mail (SMTP)"]})
    assert a.get("/netmon/api/role-suggest?ip=10.40.0.240").json() == {"ok": True, "observed_role": "mail", "serves": ["mail (SMTP)"]}
    assert a.get("/netmon/api/role-suggest?ip=198.51.100.9").status_code == 400


def test_device_type_select_single_and_bulk():
    from netmon import inventory
    a = client("admin", ADMINPW)
    tok = web.csrf_token(sid(a))
    page = a.get("/netmon/settings/inventory").text
    assert "<th>Type</th>" in page and "<option>virtual machine</option>" in page and "keep unchanged" in page
    r = a.post("/netmon/names", data={"ip": "10.40.0.8", "name": "backup-1", "role": "backup", "kind": "virtual machine", "csrf": tok},
               headers={"x-nm-fetch": "1"})
    assert r.json()["kind"] == "virtual machine" and "printer" in r.json()["kind_options"]
    assert a.post("/netmon/names", data={"ip": "10.40.0.8", "name": "backup-1", "kind": "toaster", "csrf": tok},
                  headers={"x-nm-fetch": "1"}).status_code == 400
    # a form without the field keeps the type
    inventory.save("10.40.0.8", "backup-1", "backup", True, "", "admin", "admin")
    assert web.cfg["assets"]["10.40.0.8"]["kind"] == "virtual machine"
    # bulk: type only, role kept; unnamed address added with the type
    a.post("/netmon/settings/inventory/roles", data={"ips": "10.40.0.8 10.40.0.66", "kind": "physical server", "keep_role": "1", "csrf": tok})
    assert web.cfg["assets"]["10.40.0.8"]["kind"] == "physical server" and web.cfg["assets"]["10.40.0.8"]["role"] == "backup"
    assert web.cfg["assets"]["10.40.0.66"]["kind"] == "physical server"
    from netmon.profile import server_profile
    assert server_profile(web.cfg, web.conn, None, "10.40.0.8")["device_type"] == "physical server"
    # clearing the type
    a.post("/netmon/settings/inventory/roles", data={"ips": "10.40.0.8", "kind": "__none", "keep_role": "1", "csrf": tok})
    assert "kind" not in web.cfg["assets"]["10.40.0.8"]
    a.post("/netmon/names", data={"ip": "10.40.0.8", "name": "backup-1", "role": "backup", "kind": "printer", "csrf": tok})
    a.post("/netmon/names", data={"ip": "10.40.0.8", "name": "backup-1", "role": "backup", "kind": "__none", "csrf": tok})
    assert "kind" not in web.cfg["assets"]["10.40.0.8"]
    a.post("/netmon/names", data={"ip": "10.40.0.66", "clear": "1", "csrf": tok})
    from netmon.ai import SYSTEM
    assert "device_type" in SYSTEM
