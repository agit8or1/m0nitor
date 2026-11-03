import json

from netmon import profile


def test_classify_names_functions_and_ignores_one_off_clients():
    served = [{"proto": "tcp", "port": 25, "peers": 40, "flows": 900}, {"proto": "tcp", "port": 993, "peers": 12, "flows": 300},
              {"proto": "tcp", "port": 443, "peers": 30, "flows": 500}, {"proto": "tcp", "port": 4444, "peers": 1, "flows": 2},
              {"proto": "icmp", "port": 0, "peers": 80, "flows": 900}]
    used = [{"proto": "udp", "port": 53, "peers": 2, "flows": 50}]
    got = profile.classify(served, used)
    assert got["observed_role"] == "mail+web"
    assert [s["function"] for s in got["observed_serves"]] == ["mail (SMTP)", "web (HTTPS)", "mail (IMAPS)"]
    assert got["observed_uses"][0]["function"] == "dns"
    assert profile.classify([], [])["observed_role"] == "no public service seen"
    assert profile.function_of("tcp", 7777) == "tcp/7777"


def test_server_profile_has_declared_role_and_expected_reason(cfg, conn):
    from netmon.core import EXPECTED_KEY, put_setting
    put_setting(conn, EXPECTED_KEY, {"10.40.0.240": {"reason": "known relay", "by": "t", "ts": 0}}, "t")
    p = profile.server_profile(cfg, conn, None, "10.40.0.240")
    assert p["declared_role"] == "mail+dns" and p["expected_device"] == "known relay"
    assert profile.server_profile(cfg, conn, None, "10.40.0.77")["declared_role"] == "not set"


def test_alert_ai_evidence_carries_server_function(monkeypatch):
    from netmon import views, web
    monkeypatch.setattr(views, "server_profile", lambda c, n, d, ip: {"declared_role": web.cfg.asset(ip).get("role"), "observed_role": "mail"})
    ctx = views.asset_context("10.40.0.240")
    assert ctx["kind"] == "internal server" and ctx["declared_role"] == "mail+dns" and ctx["observed_role"] == "mail"
    assert views.asset_context("198.51.100.9") == {"kind": "public address"}
    # shared NAT: hosts that got replies from the finding's peer are profiled
    monkeypatch.setattr(views, "nat_peers_hosts", lambda peers, t0, t1: ["10.40.0.8"] if peers == ["198.51.100.61"] else [])
    a = {"evidence": json.dumps([{"peer": "198.51.100.61"}]), "window_start": 0, "window_end": 0}
    ctx = views.asset_context("203.0.113.179", a)
    assert ctx["kind"] == "shared outbound NAT address"
    assert ctx["likely_internal_hosts"] == [{"host": "10.40.0.8", "declared_role": "backup", "observed_role": "mail"}]
    from netmon.ai import SYSTEM
    assert "declared_role" in SYSTEM and "observed_role" in SYSTEM
