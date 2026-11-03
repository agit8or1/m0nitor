from test_web import ADMINPW, VIEWPW, client


def test_permissions_page_lists_privileges_and_live_check(monkeypatch):
    from netmon import block as blk
    from netmon import fwperms, web
    a = client("admin", ADMINPW)
    page = a.get("/netmon/settings/permissions").text
    for p, *_ in fwperms.OPNSENSE:
        assert p in page
    assert "Firewall permissions" in page and "granted" not in page   # no check until asked

    def fake(self, method, path, data=None, json_=None, params=None):
        if "search_arp" in path:
            raise blk.BlockError('OPNsense HTTP 403: {"status":403,"message":"Forbidden"}')
        return {}
    monkeypatch.setattr(blk.OPNsense, "_call", fake)
    monkeypatch.setattr(blk.OPNsense, "enabled", property(lambda self: True))
    site = web.cfg.sites[0]
    monkeypatch.setattr(type(web.cfg), "sites", property(lambda self: [{**site, "vendor": "opnsense"}]))
    page = a.get("/netmon/settings/permissions?check=1").text
    assert page.count("✓ granted") == len(fwperms.OPNSENSE) - 1 and "✗ missing" in page and "Missing: Diagnostics: ARP Table" in page
    # every probe is read-only: GET, or a POST to a search/query endpoint
    for _, _, _, (m, path, _), _ in fwperms.OPNSENSE:
        assert m == "GET" or any(x in path for x in ("search", "query"))
    assert client("viewer1", VIEWPW).get("/netmon/settings/permissions").status_code == 403
